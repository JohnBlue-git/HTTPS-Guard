#include <cstring>
#include <iostream>
#include <utility>

#include <linux/if_link.h>  /* XDP_FLAGS_SKB_MODE, XDP_FLAGS_UPDATE_IF_NOEXIST */

#include "https_guard_program.hpp"
#include "log/LogAction.hpp"
#include "blocklist/Blocklist.hpp"
#include "blocklist/BlocklistAction.hpp"
#include "tcp/BlockTcpAction.hpp"
#include "proc_peer_resolver.hpp"

namespace https_guard {

HttpGuardProgram::HttpGuardProgram(std::string object_path,
                                   ActionLoop& action_loop,
                                   std::string openssl_lib_path,
                                   unsigned int ifindex,
                                   std::chrono::seconds blocklist_ttl,
                                   std::string output_path) noexcept
    : BpfProgram(std::move(object_path))
    , action_loop_(action_loop)
    , openssl_lib_path_(std::move(openssl_lib_path))
    , ifindex_(ifindex)
    , blocklist_ttl_(blocklist_ttl)
    , output_path_(std::move(output_path))
{
}

bool HttpGuardProgram::attachProgram() noexcept
{
    bool have_uprobe = false;
    bool have_xdp = false;

    // Uprobe is the PRIMARY detection mechanism on BMC platforms where
    // XDP may not be available (ASpeed AST2600 ftgmac100 NICs).
    bpf_program* uprobe_prog = bpf_object__find_program_by_name(object_, "https_guard_ssl_write");
    if (!uprobe_prog) {
        std::cerr << "https_guard: OpenSSL uprobe program 'https_guard_ssl_write'"
                  << " not found in BPF object (required)\n";
    } else {
        bpf_uprobe_opts uprobe_opts = {};
        uprobe_opts.sz = sizeof(uprobe_opts);
        uprobe_opts.retprobe = false;
        uprobe_opts.func_name = "SSL_write";

        bpf_link* uprobe_link = bpf_program__attach_uprobe_opts(
            uprobe_prog, -1, openssl_lib_path_.c_str(), 0, &uprobe_opts);
        if (!uprobe_link || libbpf_get_error(uprobe_link)) {
            int err = libbpf_get_error(uprobe_link);
            std::cerr << "https_guard: failed to attach SSL_write uprobe at '"
                      << openssl_lib_path_ << "' (err=" << err
                      << ", " << strerror(-err) << ")\n";
        } else {
            std::cerr << "https_guard: uprobe attached to " << openssl_lib_path_
                      << " (link fd=" << bpf_link__fd(uprobe_link) << ")\n";
            links_.push_back(uprobe_link);
            have_uprobe = true;
        }
    }

    // XDP is an AUXILIARY program — works in native mode on NICs with
    // ndo_bpf support, or in generic (SKB) mode on any NIC including
    // virtio-net in QEMU TAP+BRIDGE mode.
    //
    // The attach order is:
    //   1. Try native XDP  (XDP_FLAGS_UPDATE_IF_NOEXIST)
    //   2. On failure, try generic XDP (XDP_FLAGS_SKB_MODE)
    //   3. On both failures, log non-fatal and continue with uprobe only
    bpf_program* xdp_prog = bpf_object__find_program_by_name(object_, "https_guard_xdp");
    if (xdp_prog) {
        int xdp_fd = bpf_program__fd(xdp_prog);
        if (xdp_fd < 0) {
            std::cerr << "https_guard: failed to get XDP program fd (non-fatal): "
                      << strerror(errno) << "\n";
        } else {
            struct bpf_xdp_attach_opts opts = {};
            opts.sz = sizeof(opts);
            int native_err;
            int generic_err;

            // Attempt 1: native XDP (driver-level ndo_bpf).
            // This works on real hardware NICs that support XDP natively.
            native_err = bpf_xdp_attach(ifindex_, xdp_fd,
                                        XDP_FLAGS_UPDATE_IF_NOEXIST, &opts);
            if (native_err) {
                // Attempt 2: generic XDP (SKB_MODE / software fallback).
                // This works on virtio-net (QEMU TAP+BRIDGE) and any NIC
                // that lacks native XDP but has generic XDP support in
                // the kernel's netif_receive_skb() path.
                generic_err = bpf_xdp_attach(
                    ifindex_, xdp_fd,
                    XDP_FLAGS_SKB_MODE | XDP_FLAGS_UPDATE_IF_NOEXIST,
                    &opts);
                if (generic_err) {
                    std::cerr << "https_guard: failed to attach XDP program to ifindex "
                              << ifindex_ << " (non-fatal, continuing with uprobe only):\n"
                              << "  native XDP: " << strerror(-native_err) << "\n"
                              << "  generic XDP: " << strerror(-generic_err) << "\n";
                } else {
                    links_.push_back(nullptr);  /* placeholder: bpf_xdp_attach has no link */
                    have_xdp = true;
                    std::cout << "https_guard: XDP attached in generic (SKB) mode\n";
                }
            } else {
                links_.push_back(nullptr);
                have_xdp = true;
                std::cout << "https_guard: XDP attached in native mode\n";
            }
        }
    } else {
        std::cerr << "https_guard: XDP program not found; running uprobe only\n";
    }

    // Require at least one enforcement path.
    if (!have_uprobe && !have_xdp) {
        std::cerr << "https_guard: neither uprobe nor XDP could be attached\n";
        return false;
    }

    // Log which enforcement paths are active.
    std::cout << "https_guard: enforcement active via "
              << (have_uprobe ? "uprobe(SSL_write) " : "")
              << (have_xdp ? "xdp" : "")
              << "\n";

    /* Adopt the blocklist map so ringBufferHandler can populate it after
     * classifying an event.  This is the only "countermeasure" touch
     * point in the attach path -- everything else stays observational. */
    if (!Blocklist::instance().adopt(getMapFd(kBlocklistMapName))) {
        std::cerr << "https_guard: failed to adopt blocklist map '"
                  << kBlocklistMapName << "' (countermeasure disabled)\n";
        /* Non-fatal: the daemon still works in pure observational mode. */
    }
    return true;
}

ring_buffer_sample_fn HttpGuardProgram::getRingBufferHandler() noexcept
{
    return &HttpGuardProgram::ringBufferCallback;
}

int HttpGuardProgram::ringBufferHandler(void* data, size_t size) noexcept
{
    if (size < sizeof(uint32_t)) {
        std::cerr << "https_guard: ringbuffer callback: undersized event (" << size << " bytes)\n";
        return 0;
    }

    /* ------------------------------------------------------------------
     * HYBRID ARCHITECTURE: BPF is OBSERVATIONAL, userspace makes decisions.
     *
     * BPF sends two types of events:
     *   1. uprobe_event (HG_SOURCE_UPROBE) - purely observational
     *   2. xdp_event (HG_SOURCE_XDP) - minimal classification for XDP_DROP
     *
     * Userspace determines:
     *   - event_type (TLS violation, anomaly, normal traffic)
     *   - severity (Critical, Warning, Informational)
     *   - message_id and message text
     *   - enforcement actions (TCP blocking, blocklisting)
     * ------------------------------------------------------------------ */

    const uint32_t event_source = *static_cast<const uint32_t*>(data);

    std::string severity;
    std::string message_id;
    std::string message;
    bool actionable = false;
    uint32_t pid = 0;
    uint32_t src_ip_v4 = 0;
    uint32_t dst_ip_v4 = 0;
    uint16_t src_port = 0;
    uint16_t dst_port = 0;
    uint16_t tls_version = 0;
    char process[HG_COMM_LEN] = {0};
    char payload_snippet[HG_PAYLOAD_SNIPPET_LEN] = {0};

    if (event_source == HG_SOURCE_UPROBE) {
        /* ==============================================================
         * UPROBE EVENT: Purely observational data from SSL_write
         * ============================================================== */
        if (size < sizeof(struct uprobe_event)) {
            std::cerr << "https_guard: uprobe event too small: " << size << " bytes\n";
            return 0;
        }

        const auto* evt = static_cast<const struct uprobe_event*>(data);

        std::cout << "https_guard: uprobe event received: process='" << evt->process
                  << "' (PID " << evt->pid << "), tls_version=" << evt->tls_version << "\n";

        pid = evt->pid;
        tls_version = evt->tls_version;
        memcpy(process, evt->process, sizeof(evt->process));
        memcpy(payload_snippet, evt->payload_snippet, sizeof(evt->payload_snippet));

        /* Uprobe path: no socket info available from BPF.
         * Userspace will resolve via /proc/<pid>/net/tcp if needed. */
        src_ip_v4 = 0;
        dst_ip_v4 = 0;
        src_port = 0;
        dst_port = 0;

        /* Classify based on TLS version */
        if (tls_version > 0 && tls_version < 0x0303) {
            /* TLS version violation (< 1.2) */
            severity   = "Critical";
            message_id = "OemSecurityEvent.1.0.0.HttpsTlsVersionViolation";
            message    = "Security violation: Process '" + std::string(process) +
                         "' (PID " + std::to_string(pid) +
                         ") attempted an HTTPS connection using an insecure TLS version (" +
                         TlsVersion(tls_version).toString() + "). Packet was blocked.";
            actionable = true;
        } else {
            /* Normal traffic or unknown - apply anomaly detection */
            std::string matched_rule;
            const bool suspicious = detector_.isSuspicious(payload_snippet, matched_rule);

            if (suspicious) {
                if (matched_rule.empty()) {
                    matched_rule = "kernel-signature";
                }
                severity   = "Warning";
                message_id = "OemSecurityEvent.1.0.0.HttpsPayloadAnomalyDetected";
                message    = "Attack signature detected from process '" + std::string(process) +
                             "' (PID " + std::to_string(pid) +
                             "), rule '" + matched_rule +
                             "'. Source should be quarantined.";
                actionable = true;
            } else {
                severity   = "Informational";
                message_id = "OemSecurityEvent.1.0.0.HttpsTrafficObserved";
                message    = "HTTPS traffic observed from process '" + std::string(process) +
                             "' (PID " + std::to_string(pid) +
                             "), TLS version: " + TlsVersion(tls_version).toString();
                actionable = false;
            }
        }
    }
    else if (event_source == HG_SOURCE_XDP) {
        /* ==============================================================
         * XDP EVENT: Minimal classification from XDP program
         * ============================================================== */
        if (size < sizeof(struct xdp_event)) {
            std::cerr << "https_guard: xdp event too small: " << size << " bytes\n";
            return 0;
        }

        const auto* evt = static_cast<const struct xdp_event*>(data);

        std::cout << "https_guard: xdp event received: process='" << evt->process
                  << "' (PID " << evt->pid << "), tls_version=" << evt->tls_version
                  << ", is_violation=" << evt->is_violation << "\n";

        pid = evt->pid;
        tls_version = evt->tls_version;
        src_ip_v4 = evt->src_ip_v4;
        dst_ip_v4 = evt->dst_ip_v4;
        src_port = evt->src_port;
        dst_port = evt->dst_port;
        memcpy(process, evt->process, sizeof(evt->process));
        memcpy(payload_snippet, evt->payload_snippet, sizeof(evt->payload_snippet));

        /* XDP path: socket info is available from BPF.
         * Apply full classification in userspace. */
        if (evt->is_violation) {
            /* TLS version violation - already dropped by XDP, but log it */
            severity   = "Critical";
            message_id = "OemSecurityEvent.1.0.0.HttpsTlsVersionViolation";
            message    = "Security violation: Process '" + std::string(process) +
                         "' (PID " + std::to_string(pid) +
                         ") attempted an HTTPS connection using an insecure TLS version (" +
                         TlsVersion(tls_version).toString() + "). Packet was blocked.";
            actionable = true;
        } else if (evt->is_violation == 0 && payload_snippet[0] != '\0') {
            /* Plaintext HTTP on port 443 - apply anomaly detection */
            std::string matched_rule;
            const bool suspicious = detector_.isSuspicious(payload_snippet, matched_rule);

            if (suspicious) {
                if (matched_rule.empty()) {
                    matched_rule = "kernel-signature";
                }
                severity   = "Warning";
                message_id = "OemSecurityEvent.1.0.0.HttpsPayloadAnomalyDetected";
                message    = "Attack signature detected from process '" + std::string(process) +
                             "' (PID " + std::to_string(pid) +
                             "), rule '" + matched_rule +
                             "'. Source should be quarantined.";
                actionable = true;
            } else {
                severity   = "Informational";
                message_id = "OemSecurityEvent.1.0.0.HttpsTrafficObserved";
                message    = "HTTPS traffic observed from process '" + std::string(process) +
                             "' (PID " + std::to_string(pid) +
                             "), TLS version: " + TlsVersion(tls_version).toString();
                actionable = false;
            }
        } else {
            /* Normal TLS handshake - informational */
            severity   = "Informational";
            message_id = "OemSecurityEvent.1.0.0.HttpsTrafficObserved";
            message    = "HTTPS traffic observed from process '" + std::string(process) +
                         "' (PID " + std::to_string(pid) +
                         "), TLS version: " + TlsVersion(tls_version).toString();
            actionable = false;
        }
    }
    else
    {
        std::cerr << "https_guard: unknown event_source=" << event_source
                  << ", size=" << size << ", skipping\n";
        return 0;
    }

    std::cerr << "https_guard: pushing LogAction for severity=" << severity << "\n";

    // Construct hg_event for RedfishEventMessage
    struct hg_event evt_for_msg;
    memset(&evt_for_msg, 0, sizeof(evt_for_msg));
    evt_for_msg.timestamp_ns = 0;  // Will be set by RedfishEventMessage::format()
    evt_for_msg.pid = pid;
    evt_for_msg.tgid = 0;
    evt_for_msg.src_ip_v4 = src_ip_v4;
    evt_for_msg.dst_ip_v4 = dst_ip_v4;
    evt_for_msg.src_port = src_port;
    evt_for_msg.dst_port = dst_port;
    evt_for_msg.tls_version = tls_version;
    memcpy(evt_for_msg.process, process, sizeof(evt_for_msg.process));
    memcpy(evt_for_msg.payload_snippet, payload_snippet, sizeof(evt_for_msg.payload_snippet));

    // LogAction
    RedfishEventMessage event_msg(
        evt_for_msg, message_id, message, severity);
    action_loop_.pushAction(
        std::make_unique<LogAction>(
        event_msg.format(),
        output_path_));

    if (actionable)
    {
        if (src_ip_v4 != 0)
        {
            // XDP path: socket info is available.
            // BlockTcpAction — kill the specific TCP connection immediately
            // using the kernel's tcp_drop (SOCK_DESTROY) facility, which
            // tears down the socket without touching the owning process.
            action_loop_.pushAction(
                std::make_unique<BlockTcpAction>(
                src_ip_v4,
                dst_ip_v4,
                src_port,
                dst_port,
                message));

            // BlocklistAction — prevent future connections from this source IP
            action_loop_.pushAction(
                std::make_unique<BlocklistAddAction>(
                src_ip_v4,
                blocklist_ttl_,
                message));
        }
        else
        {
            // Uprobe path: no socket info from BPF, but we have the PID.
            // Read /proc/<pid>/net/tcp to find the TCP socket 4-tuple,
            // then issue SOCK_DESTROY to kill the connection.
            auto sockets = ProcPeerResolver::getTcpSockets(
                static_cast<pid_t>(pid));

            if (sockets.empty()) {
                std::cerr << "https_guard: uprobe PID " << pid
                          << " (" << process << "), TLS version: "
                          << TlsVersion(tls_version).toString()
                          << " — no TCP sockets found, cannot SOCK_DESTROY\n";
            } else {
                for (const auto& sock : sockets) {
                    // Only act on established connections to port 443
                    if (sock.dst_port != 443 && sock.dst_port != 0) {
                        continue;
                    }

                    action_loop_.pushAction(
                        std::make_unique<BlockTcpAction>(
                        sock.src_ip_v4,
                        sock.dst_ip_v4,
                        sock.src_port,
                        sock.dst_port,
                        message));

                    // Blocklist the source IP to prevent future connections
                    if (sock.src_ip_v4 != 0) {
                        action_loop_.pushAction(
                            std::make_unique<BlocklistAddAction>(
                            sock.src_ip_v4,
                            blocklist_ttl_,
                            message));
                    }

                    std::cerr << "https_guard: uprobe PID " << pid
                              << " (" << process << "), TLS version: "
                              << TlsVersion(tls_version).toString()
                              << " — SOCK_DESTROY sent\n";
                }
            }
        }
    }

    return 0;
}

int HttpGuardProgram::ringBufferCallback(void* ctx, void* data, size_t size) noexcept
{
    return static_cast<HttpGuardProgram*>(ctx)->ringBufferHandler(data, size);
}

}  // namespace https_guard
#include <iostream>
#include <utility>

#include "https_guard_program.hpp"
#include "log/LogAction.hpp"
#include "blocklist/Blocklist.hpp"
#include "blocklist/BlocklistAction.hpp"
#include "tcp/BlockTcpAction.hpp"

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
    bpf_program* xdp_prog = bpf_object__find_program_by_name(object_, "https_guard_xdp");
    if (!xdp_prog) {
        return false;
    }

    bpf_link* xdp_link = bpf_program__attach_xdp(xdp_prog, ifindex_);
    if (!xdp_link) {
        return false;
    }
    links_.push_back(xdp_link);

    bpf_program* uprobe_prog = bpf_object__find_program_by_name(object_, "https_guard_ssl_write");
    if (!uprobe_prog) {
        return false;
    }

    bpf_link* uprobe_link = bpf_program__attach_uprobe(uprobe_prog, false, -1, openssl_lib_path_.c_str(), 0);
    if (!uprobe_link) {
        return false;
    }
    links_.push_back(uprobe_link);

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
    if (size < sizeof(hg_event)) {
        return 0;
    }

    const auto* evt = static_cast<const hg_event*>(data);
    std::string severity;
    std::string message_id;
    std::string message;
    bool         actionable = false;

    if (evt->event_type == HG_EVENT_TLS_VERSION_VIOLATION)
    {
        severity   = "Critical";
        message_id = "OemSecurityEvent.1.0.0.HttpsTlsVersionViolation";
        message    = "Security violation: Process '" + std::string(evt->process) +
                     "' (PID " + std::to_string(evt->pid) +
                     ") attempted an HTTPS connection using an insecure TLS version (" +
                     TlsVersion(evt->tls_version).toString() + "). Packet was blocked.";
        actionable = true;
    }
    else if (evt->event_type == HG_EVENT_HTTP_ANOMALY_DETECTED ||
            evt->event_type == HG_EVENT_HTTP_PAYLOAD_OBSERVED)
    {
        std::string matched_rule;
        const bool suspicious = detector_.isSuspicious(evt->payload_snippet, matched_rule) ||
                                evt->event_type == HG_EVENT_HTTP_ANOMALY_DETECTED;

        if (!suspicious) {
            return 0;
        }

        if (matched_rule.empty()) {
            matched_rule = "kernel-signature";
        }

        severity   = "Warning";
        message_id = "OemSecurityEvent.1.0.0.HttpsPayloadAnomalyDetected";
        message    = "Attack signature detected from process '" + std::string(evt->process) +
                     "' (PID " + std::to_string(evt->pid) +
                     "), rule '" + matched_rule +
                     "'. Source should be quarantined.";
        actionable = true;
    }
    else
    {
        return 0;
    }

    // LogAction
    RedfishEventMessage event_msg(
        *evt, message_id, message, severity);
    action_loop_.pushAction(
        std::make_unique<LogAction>(
        event_msg.format(),
        output_path_));

    if (actionable && evt->src_ip_v4 != 0)
    {
        // BlockTcpAction — kill the specific TCP connection immediately
        // using the kernel's tcp_drop (SOCK_DESTROY) facility, which
        // tears down the socket without touching the owning process.
        action_loop_.pushAction(
            std::make_unique<BlockTcpAction>(
            evt->src_ip_v4,
            evt->dst_ip_v4,
            evt->src_port,
            evt->dst_port,
            message));

        // BlocklistAction — prevent future connections from this source IP
        action_loop_.pushAction(
            std::make_unique<BlocklistAddAction>(
            evt->src_ip_v4,
            blocklist_ttl_,
            message));
    }

    return 0;
}

int HttpGuardProgram::ringBufferCallback(void* ctx, void* data, size_t size) noexcept
{
    return static_cast<HttpGuardProgram*>(ctx)->ringBufferHandler(data, size);
}

}  // namespace https_guard

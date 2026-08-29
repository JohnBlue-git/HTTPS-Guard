#include <cstring>
#include <memory>
#include <iostream>

#include <linux/if_link.h>  /* XDP_FLAGS_SKB_MODE, XDP_FLAGS_UPDATE_IF_NOEXIST */

/* Explicit now that IHookModule.hpp forward-declares bpf_object/bpf_link
 * instead of including libbpf -- the hooks are where libbpf is actually
 * used, so this is where the dependency belongs. */
#include <bpf/bpf.h>       /* bpf_prog_get_fd_by_id, bpf_prog_get_info_by_fd */
#include <bpf/libbpf.h>
#include <unistd.h>        /* close() for the queried program fd */

#include "XdpTlsProgram.hpp"
#include "xdp_tls_event.h"
#include "xdp_hg_event.hpp"
#include "bounded_string.hpp"

static_assert(sizeof(struct xdp_event) <= HG_MAX_RAW_EVENT_SIZE,
              "xdp_event outgrew HG_MAX_RAW_EVENT_SIZE; raise the cap in "
              "hg_event_source.h -- DetectLoop sizes its queue slots from it");

namespace https_guard {

XdpTlsProgram::XdpTlsProgram(unsigned int ifindex) noexcept
    : ifindex_(ifindex)
{
}

XdpTlsProgram::~XdpTlsProgram() noexcept
{
    if (!owns_legacy_attachment_) {
        return;  // link-based: the kernel detaches when the link fd closes
    }

    // Legacy path only. Without this the attachment outlives the process and
    // the next start cannot attach at all.
    const int err = bpf_xdp_detach(ifindex_, 0, nullptr);
    if (err) {
        std::cerr << "https_guard: failed to detach XDP program from ifindex "
                  << ifindex_ << " (" << strerror(-err)
                  << "); a restart may report 'XDP program already attached'\n";
    } else {
        std::cout << "https_guard: XDP program detached from ifindex " << ifindex_ << "\n";
    }
}

void XdpTlsProgram::clearStaleAttachment() noexcept
{
    bpf_xdp_query_opts query = {};
    query.sz = sizeof(query);

    if (bpf_xdp_query(static_cast<int>(ifindex_), 0, &query) != 0) {
        return;  // nothing attached, or the interface can't be queried
    }

    const __u32 prog_id = query.prog_id != 0 ? query.prog_id : query.skb_prog_id;
    if (prog_id == 0) {
        return;  // interface is free
    }

    // Identify it before removing it. Anything that isn't ours belongs to
    // another tool on this interface, and taking it down would swap our
    // outage for theirs.
    const int prog_fd = bpf_prog_get_fd_by_id(prog_id);
    if (prog_fd < 0) {
        std::cerr << "https_guard: an XDP program (id " << prog_id
                  << ") is attached to ifindex " << ifindex_
                  << " but could not be identified; leaving it alone\n";
        return;
    }

    struct bpf_prog_info info = {};
    __u32 info_len = sizeof(info);
    const bool identified = bpf_prog_get_info_by_fd(prog_fd, &info, &info_len) == 0;
    const bool is_ours = identified && std::strncmp(info.name, "https_guard_xdp",
                                                    sizeof(info.name)) == 0;
    close(prog_fd);

    if (!is_ours) {
        std::cerr << "https_guard: ifindex " << ifindex_
                  << " already has an XDP program attached ('"
                  << (identified ? info.name : "unknown")
                  << "') that is not ours; refusing to replace it\n";
        return;
    }

    // A leaked attachment from a previous run of this daemon -- either from
    // before link-based attach was used, or a legacy-path instance that was
    // killed before its destructor ran.
    const int err = bpf_xdp_detach(static_cast<int>(ifindex_), 0, nullptr);
    if (err) {
        std::cerr << "https_guard: found a leaked https_guard XDP program on ifindex "
                  << ifindex_ << " but could not detach it (" << strerror(-err) << ")\n";
    } else {
        std::cout << "https_guard: cleared a leaked https_guard XDP program from ifindex "
                  << ifindex_ << " (left by a previous run)\n";
    }
}

bool XdpTlsProgram::attach(bpf_object* obj, std::vector<bpf_link*>& links) noexcept
{
    bpf_program* xdp_prog = bpf_object__find_program_by_name(obj, "https_guard_xdp");
    if (!xdp_prog) {
        std::cerr << "https_guard: XDP program not found; running uprobe only\n";
        return false;
    }

    clearStaleAttachment();

    // Preferred: a BPF link, so the kernel detaches automatically when this
    // process goes away for any reason. See the class comment.
    bpf_link* link = bpf_program__attach_xdp(xdp_prog, static_cast<int>(ifindex_));
    const long link_err = libbpf_get_error(link);
    if (link && !link_err) {
        links.push_back(link);
        std::cout << "https_guard: XDP attached via BPF link (auto-detaches on exit)\n";
        return true;
    }

    std::cerr << "https_guard: XDP link attach unavailable (" << strerror(static_cast<int>(-link_err))
              << "); falling back to the legacy netlink attach, whose attachment"
                 " this process must clean up itself\n";

    int xdp_fd = bpf_program__fd(xdp_prog);
    if (xdp_fd < 0) {
        std::cerr << "https_guard: failed to get XDP program fd (non-fatal): "
                  << strerror(errno) << "\n";
        return false;
    }

    struct bpf_xdp_attach_opts opts = {};
    opts.sz = sizeof(opts);

    // Native first (driver ndo_bpf), then generic/SKB (software fallback,
    // which is what virtio-net and similar need).
    int native_err = bpf_xdp_attach(ifindex_, xdp_fd, XDP_FLAGS_UPDATE_IF_NOEXIST, &opts);
    if (!native_err) {
        owns_legacy_attachment_ = true;
        std::cout << "https_guard: XDP attached in native mode (legacy path)\n";
        return true;
    }

    int generic_err = bpf_xdp_attach(
        ifindex_, xdp_fd, XDP_FLAGS_SKB_MODE | XDP_FLAGS_UPDATE_IF_NOEXIST, &opts);
    if (generic_err) {
        std::cerr << "https_guard: failed to attach XDP program to ifindex "
                  << ifindex_ << " (non-fatal, continuing with uprobe only):\n"
                  << "  native XDP: " << strerror(-native_err) << "\n"
                  << "  generic XDP: " << strerror(-generic_err) << "\n";
        return false;
    }

    owns_legacy_attachment_ = true;
    std::cout << "https_guard: XDP attached in generic (SKB) mode (legacy path)\n";
    return true;
}

hg_event_source XdpTlsProgram::eventSource() const noexcept
{
    return HG_SOURCE_XDP;
}

std::unique_ptr<hg_event> XdpTlsProgram::parseEvent(const void* data, size_t size) const noexcept
{
    if (size < sizeof(struct xdp_event)) {
        std::cerr << "https_guard: xdp event too small: " << size << " bytes\n";
        return nullptr;
    }

    const auto* raw = static_cast<const struct xdp_event*>(data);

    auto owned = std::make_unique<XdpEvent>();
    XdpEvent& evt = *owned;
    evt.pid         = raw->pid;
    evt.tls_version = raw->tls_version;
    evt.violation_hint = (raw->is_violation != 0);
    // XDP is an INGRESS hook, so the packet's destination is this BMC and
    // its source is the peer. The raw struct keeps the wire's own src/dst
    // vocabulary; the translation into local/remote roles belongs here, at
    // the boundary where a hook stops speaking packet and starts speaking
    // hg_event.
    evt.local_ip_v4  = raw->dst_ip_v4;
    evt.remote_ip_v4 = raw->src_ip_v4;
    evt.local_port   = raw->dst_port;
    evt.remote_port  = raw->src_port;
    evt.process         = boundedString(raw->process);
    evt.payload_snippet = boundedString(raw->payload_snippet);
    // The BPF side formats the peer address into raw->source_ip but this
    // never copied it across, so every XDP verdict message read "an
    // unidentified peer" despite the address being right there. Noticed
    // because ticket 04's new cipher-suite/SNI messages name the source.
    evt.source_ip       = boundedString(raw->source_ip);

    const uint16_t captured =
        raw->cipher_suite_count < HG_MAX_CIPHER_SUITES ? raw->cipher_suite_count
                                                       : HG_MAX_CIPHER_SUITES;
    evt.cipher_suites.assign(raw->cipher_suites, raw->cipher_suites + captured);
    evt.cipher_suites_offered = raw->cipher_suites_offered;

    evt.sni_present   = (raw->sni_present != 0);
    evt.sni_malformed = (raw->sni_malformed != 0);
    evt.sni_hostname  = boundedString(raw->sni_hostname);

    std::cout << "https_guard: xdp event received: process='" << evt.process
              << "' (PID " << evt.pid << "), tls_version=" << evt.tls_version
              << ", is_violation=" << raw->is_violation
              << ", cipher_suites=" << evt.cipher_suites.size() << "/"
              << evt.cipher_suites_offered
              << ", sni='" << evt.sni_hostname << "'\n";

    return owned;
}

}  // namespace https_guard

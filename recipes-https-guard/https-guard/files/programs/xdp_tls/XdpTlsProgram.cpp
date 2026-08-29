#include <cstring>
#include <iostream>

#include <linux/if_link.h>  /* XDP_FLAGS_SKB_MODE, XDP_FLAGS_UPDATE_IF_NOEXIST */

#include "XdpTlsProgram.hpp"
#include "xdp_tls_event.h"
#include "bounded_string.hpp"

namespace https_guard {

XdpTlsProgram::XdpTlsProgram(unsigned int ifindex) noexcept
    : ifindex_(ifindex)
{
}

bool XdpTlsProgram::attach(bpf_object* obj, std::vector<bpf_link*>& links) noexcept
{
    // XDP is an AUXILIARY program — works in native mode on NICs with
    // ndo_bpf support, or in generic (SKB) mode on any NIC including
    // virtio-net in QEMU TAP+BRIDGE mode.
    //
    // The attach order is:
    //   1. Try native XDP  (XDP_FLAGS_UPDATE_IF_NOEXIST)
    //   2. On failure, try generic XDP (XDP_FLAGS_SKB_MODE)
    //   3. On both failures, log non-fatal and give up
    bpf_program* xdp_prog = bpf_object__find_program_by_name(obj, "https_guard_xdp");
    if (!xdp_prog) {
        std::cerr << "https_guard: XDP program not found; running uprobe only\n";
        return false;
    }

    int xdp_fd = bpf_program__fd(xdp_prog);
    if (xdp_fd < 0) {
        std::cerr << "https_guard: failed to get XDP program fd (non-fatal): "
                  << strerror(errno) << "\n";
        return false;
    }

    struct bpf_xdp_attach_opts opts = {};
    opts.sz = sizeof(opts);

    // Attempt 1: native XDP (driver-level ndo_bpf).
    // This works on real hardware NICs that support XDP natively.
    int native_err = bpf_xdp_attach(ifindex_, xdp_fd, XDP_FLAGS_UPDATE_IF_NOEXIST, &opts);
    if (!native_err) {
        links.push_back(nullptr);  /* placeholder: bpf_xdp_attach has no link */
        std::cout << "https_guard: XDP attached in native mode\n";
        return true;
    }

    // Attempt 2: generic XDP (SKB_MODE / software fallback).
    // This works on virtio-net (QEMU TAP+BRIDGE) and any NIC that lacks
    // native XDP but has generic XDP support in the kernel's
    // netif_receive_skb() path.
    int generic_err = bpf_xdp_attach(
        ifindex_, xdp_fd, XDP_FLAGS_SKB_MODE | XDP_FLAGS_UPDATE_IF_NOEXIST, &opts);
    if (generic_err) {
        std::cerr << "https_guard: failed to attach XDP program to ifindex "
                  << ifindex_ << " (non-fatal, continuing with uprobe only):\n"
                  << "  native XDP: " << strerror(-native_err) << "\n"
                  << "  generic XDP: " << strerror(-generic_err) << "\n";
        return false;
    }

    links.push_back(nullptr);
    std::cout << "https_guard: XDP attached in generic (SKB) mode\n";
    return true;
}

hg_event_source XdpTlsProgram::eventSource() const noexcept
{
    return HG_SOURCE_XDP;
}

std::optional<hg_event> XdpTlsProgram::parseEvent(const void* data, size_t size) const noexcept
{
    if (size < sizeof(struct xdp_event)) {
        std::cerr << "https_guard: xdp event too small: " << size << " bytes\n";
        return std::nullopt;
    }

    const auto* raw = static_cast<const struct xdp_event*>(data);

    hg_event evt{};
    evt.pid         = raw->pid;
    evt.tls_version = raw->tls_version;
    evt.tls_violation_hint = (raw->is_violation != 0);
    evt.src_ip_v4   = raw->src_ip_v4;
    evt.dst_ip_v4   = raw->dst_ip_v4;
    evt.src_port    = raw->src_port;
    evt.dst_port    = raw->dst_port;
    evt.process         = boundedString(raw->process);
    evt.payload_snippet = boundedString(raw->payload_snippet);

    std::cout << "https_guard: xdp event received: process='" << evt.process
              << "' (PID " << evt.pid << "), tls_version=" << evt.tls_version
              << ", is_violation=" << raw->is_violation << "\n";

    return evt;
}

}  // namespace https_guard

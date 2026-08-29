#pragma once

#include "IHookModule.hpp"

namespace https_guard {

/**
 * Attaches the XDP TLS inspector (AUXILIARY — see xdp_tls.bpf.h), trying
 * native mode first, then generic (SKB) mode, and non-fatally giving up
 * if neither is available (e.g. QEMU SLIRP). Parses its raw xdp_event
 * into the common event representation; unlike the uprobe, socket info
 * is already available directly from the packet headers.
 */
class XdpTlsProgram final : public IHookModule {
public:
    explicit XdpTlsProgram(unsigned int ifindex) noexcept;

    bool attach(bpf_object* obj, std::vector<bpf_link*>& links) noexcept override;
    hg_event_source eventSource() const noexcept override;
    std::optional<hg_event> parseEvent(const void* data, size_t size) const noexcept override;

private:
    unsigned int ifindex_;
};

}  // namespace https_guard

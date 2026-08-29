#pragma once

#include <string>

#include "IHookModule.hpp"
#include "IPeerResolver.hpp"

namespace https_guard {

/**
 * Attaches the OpenSSL SSL_write uprobe (the PRIMARY detection mechanism
 * on BMC platforms where XDP may not be available — see ssl_uprobe.bpf.h)
 * plus its SSL_read mirror (request-side data; a non-fatal bonus if it
 * fails to attach), and parses either direction's raw uprobe_event into
 * the common event representation, resolving the PID to a socket 4-tuple
 * via /proc along the way.
 */
class SslUprobeProgram final : public IHookModule, public IPeerResolver {
public:
    explicit SslUprobeProgram(std::string openssl_lib_path) noexcept;

    bool attach(bpf_object* obj, std::vector<bpf_link*>& links) noexcept override;
    hg_event_source eventSource() const noexcept override;
    std::unique_ptr<hg_event> parseEvent(const void* data, size_t size) const noexcept override;

    /**
     * IPeerResolver: reads /proc to identify the connection this event's
     * process is using. Called on demand via hg_event::ensurePeerResolved(),
     * not during parseEvent -- see IPeerResolver.hpp for why.
     */
    bool resolvePeer(hg_event& evt) const noexcept override;

private:
    std::string openssl_lib_path_;
};

}  // namespace https_guard

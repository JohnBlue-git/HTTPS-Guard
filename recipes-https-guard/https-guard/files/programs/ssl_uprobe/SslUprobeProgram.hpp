#pragma once

#include <string>

#include "IHookModule.hpp"

namespace https_guard {

/**
 * Attaches the OpenSSL SSL_write uprobe (the PRIMARY detection mechanism
 * on BMC platforms where XDP may not be available — see ssl_uprobe.bpf.h)
 * plus its SSL_read mirror (request-side data; a non-fatal bonus if it
 * fails to attach), and parses either direction's raw uprobe_event into
 * the common event representation, resolving the PID to a socket 4-tuple
 * via /proc along the way.
 */
class SslUprobeProgram final : public IHookModule {
public:
    explicit SslUprobeProgram(std::string openssl_lib_path) noexcept;

    bool attach(bpf_object* obj, std::vector<bpf_link*>& links) noexcept override;
    hg_event_source eventSource() const noexcept override;
    std::optional<hg_event> parseEvent(const void* data, size_t size) const noexcept override;

private:
    std::string openssl_lib_path_;
};

}  // namespace https_guard

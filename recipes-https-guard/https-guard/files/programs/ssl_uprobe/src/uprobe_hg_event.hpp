#pragma once

#include <cstdint>
#include <string>

#include "hg_event.hpp"
#include "ITlsTrafficInfo.hpp"

namespace https_guard {

/**
 * What an OpenSSL uprobe event carries beyond the universal fields.
 *
 * Supplies ITlsTrafficInfo: the version read from `ssl->version` and the
 * plaintext either side of the call. Notably it does NOT supply
 * IClientHelloInfo — a uprobe fires after the handshake, so there is no
 * ClientHello to parse — which is exactly the sort of thing the old
 * all-fields-in-one event could not express.
 */
class UprobeEvent final : public hg_event, public ITlsTrafficInfo {
public:
    std::uint16_t tls_version     = 0;
    std::uint16_t tls_record_type = 0;
    std::string   payload_snippet;

    /** True for SSL_read (the request side, where attacker input lives). */
    bool is_inbound = false;

    std::uint16_t tlsVersion() const noexcept override { return tls_version; }

    /**
     * Always false here. The uprobe's BPF side makes no determination of
     * its own, so `tls_version == 0` genuinely means "not observed" —
     * unlike the XDP path, where a parsed 0x0000 is a real violation.
     */
    bool tlsViolationHint() const noexcept override { return false; }

    const std::string& payloadSnippet() const noexcept override { return payload_snippet; }
};

}  // namespace https_guard

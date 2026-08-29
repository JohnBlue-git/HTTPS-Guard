#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace https_guard {

/**
 * An event carrying fields parsed out of a TLS ClientHello.
 *
 * Only a hook that inspects the wire before the handshake completes can
 * supply this — today that is `xdp_tls` alone. It is still a capability
 * rather than an XDP-specific event type, because "which hook happens to
 * provide it" is not a property worth encoding in the type system: a
 * future hook that also parses handshakes would implement this and the
 * existing detectors would work unchanged.
 */
class IClientHelloInfo {
public:
    virtual ~IClientHelloInfo() = default;

    /** Suites actually captured — capped, so possibly fewer than offered. */
    virtual const std::vector<std::uint16_t>& cipherSuites() const noexcept = 0;

    /**
     * How many the client really offered. Differs from cipherSuites().size()
     * when the list was truncated at capture; detectors need both to tell a
     * short list apart from a clipped one.
     */
    virtual std::uint16_t cipherSuitesOffered() const noexcept = 0;

    virtual bool sniPresent() const noexcept = 0;

    /**
     * Set when the SNI/ClientHello structure was malformed *or* the
     * hostname was only partially captured. A detector must not compare a
     * partial hostname as if it were whole — a truncated "bmc.evil.com"
     * reading as "bmc" was a real bypass, caught by test before shipping.
     */
    virtual bool sniMalformed() const noexcept = 0;

    virtual const std::string& sniHostname() const noexcept = 0;
};

}  // namespace https_guard

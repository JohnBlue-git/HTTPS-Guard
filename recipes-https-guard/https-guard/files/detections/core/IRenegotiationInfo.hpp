#pragma once

#include <cstdint>

namespace https_guard {

/**
 * An event reporting how many TLS handshake records a source sent inside the
 * counting window.
 *
 * Counts handshake records rather than specifically ClientHellos: a
 * renegotiation storm is characterised by repeated handshakes, and telling
 * the message types apart on the wire would mean parsing before the packet's
 * bounds have been established.
 */
class IRenegotiationInfo {
public:
    virtual ~IRenegotiationInfo() = default;

    virtual std::uint32_t handshakeCount() const noexcept = 0;
    virtual std::uint32_t windowSeconds() const noexcept = 0;
    virtual std::uint32_t threshold() const noexcept = 0;
};

}  // namespace https_guard

#pragma once

#include <cstdint>
#include <string>

namespace https_guard {

/**
 * An event describing observed TLS traffic: a negotiated (or proposed)
 * protocol version, and a snippet of the plaintext that crossed the
 * boundary.
 *
 * Implemented by any hook that can see those things — currently both
 * `ssl_uprobe` (plaintext either side of OpenSSL, version from
 * `ssl->version`) and `xdp_tls` (ClientHello `legacy_version`, plus
 * plaintext-HTTP-on-443 bytes for connections where TLS never starts).
 *
 * That "both" is the whole reason capabilities exist here rather than one
 * event type per hook: `TlsVersionDetector` and `PayloadAnomalyDetector`
 * are registered for both sources, so they need something to bind to that
 * isn't a specific hook.
 */
class ITlsTrafficInfo {
public:
    virtual ~ITlsTrafficInfo() = default;

    /** Raw wire value (e.g. 0x0303), or 0 if never resolved. */
    virtual std::uint16_t tlsVersion() const noexcept = 0;

    /**
     * Whether the producing hook already determined this is a version
     * violation. Necessary because the two hooks differ in what they can
     * conclude alone: a genuinely-parsed `legacy_version` of 0x0000 is a
     * real violation on the wire, while `tls_version == 0` from the uprobe
     * only means "not observed". Collapsing those was a real bug once.
     */
    virtual bool tlsViolationHint() const noexcept = 0;

    /** Plaintext prefix, capped by the producing hook. May be empty. */
    virtual const std::string& payloadSnippet() const noexcept = 0;
};

}  // namespace https_guard

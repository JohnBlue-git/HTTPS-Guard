#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "hg_event.hpp"
#include "IClientHelloInfo.hpp"
#include "ITlsTrafficInfo.hpp"

namespace https_guard {

/**
 * What an XDP wire event carries beyond the universal fields.
 *
 * Supplies both capabilities: ITlsTrafficInfo (the ClientHello's
 * `legacy_version`, or plaintext bytes when something speaks HTTP at port
 * 443 and no TLS session ever forms) and IClientHelloInfo (cipher suites
 * and SNI, which only a pre-handshake wire hook can see).
 */
class XdpEvent final : public hg_event,
                       public ITlsTrafficInfo,
                       public IClientHelloInfo {
public:
    std::uint16_t tls_version = 0;
    std::string   payload_snippet;

    /**
     * Set from the BPF side's own line-rate decision. This is the reason
     * ITlsTrafficInfo has a hint at all: here a parsed `legacy_version` of
     * 0x0000 is a genuine violation, whereas the same zero from the uprobe
     * only means the version was never read.
     */
    bool violation_hint = false;

    std::vector<std::uint16_t> cipher_suites;
    std::uint16_t              cipher_suites_offered = 0;
    bool                       sni_present   = false;
    bool                       sni_malformed = false;
    std::string                sni_hostname;

    std::uint16_t tlsVersion() const noexcept override { return tls_version; }
    bool tlsViolationHint() const noexcept override { return violation_hint; }
    const std::string& payloadSnippet() const noexcept override { return payload_snippet; }

    const std::vector<std::uint16_t>& cipherSuites() const noexcept override { return cipher_suites; }
    std::uint16_t cipherSuitesOffered() const noexcept override { return cipher_suites_offered; }
    bool sniPresent() const noexcept override { return sni_present; }
    bool sniMalformed() const noexcept override { return sni_malformed; }
    const std::string& sniHostname() const noexcept override { return sni_hostname; }
};

}  // namespace https_guard

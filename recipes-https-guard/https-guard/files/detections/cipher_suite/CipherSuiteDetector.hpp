#pragma once

#include <optional>
#include <string>

#include "CipherSuiteEvent.hpp"
#include "Verdict.hpp"
#include "weak_cipher_suites.hpp"

namespace https_guard {

/**
 * Flags a ClientHello that offers a known-weak cipher suite (see
 * weak_cipher_suites.hpp for the curated table and what "weak" covers).
 *
 * Offering a weak suite is not the same as negotiating one — bmcweb will
 * refuse anything it doesn't like, so this fires on intent rather than
 * outcome. That's deliberate: a client asking for RC4 or EXPORT-grade
 * crypto against a BMC is a meaningful signal (an ancient management tool,
 * a misconfiguration, or a downgrade probe) even when the handshake then
 * fails. Hence Warning, not Critical — unlike `TlsVersionDetector`, which
 * fires on a version that actually *was* negotiated.
 *
 * **Not actionable, and that's a deliberate correction.** This detector
 * originally set `actionable = true`, which routes through
 * `BlocklistAddAction` — and the blocklist is enforced in XDP against the
 * source IP for *every* port, not just 443. Live testing on QEMU proved
 * out the consequence immediately: a single crafted ClientHello offering
 * RC4 blocklisted the peer address and instantly cut off the SSH session
 * being used to run the test. On a real BMC that is a self-inflicted
 * denial of service — one scanner packet, or one legacy tool behind a
 * shared NAT address, would lock every administrator sharing that source
 * address out of all BMC services for the blocklist TTL. Merely *offering*
 * a weak suite in a handshake bmcweb then refuses does not justify that.
 * Alerting (Redfish event) is the proportionate response; if a site wants
 * enforcement, that belongs behind an explicit opt-in, not the default.
 *
 * XDP-only: no other hook sees ClientHello bytes at all.
 */
class CipherSuiteDetector {
public:
    std::optional<Verdict> evaluate(const CipherSuiteEvent& evt) const
    {
        for (const std::uint16_t code : evt.cipher_suites) {
            const WeakCipherSuite* weak = findWeakCipherSuite(code);
            if (weak == nullptr) {
                continue;
            }

            Verdict verdict;
            verdict.severity   = "Warning";
            verdict.message_id = "OemSecurityEvent.1.0.HttpsWeakCipherSuiteDetected";
            verdict.message    = "Weak cipher suite offered from " + describeSource(evt.meta) +
                                 ": " + std::string(weak->name) + " (0x" + toHex(code) +
                                 ") — " + std::string(weak->reason) +
                                 ". Client offered " + std::to_string(evt.cipher_suites_offered) +
                                 " suite(s) total.";
            verdict.actionable = false;  // see the class comment — blocklisting on this is a DoS risk
            return verdict;
        }

        return std::nullopt;
    }

private:
    static std::string describeSource(const EventMeta& meta)
    {
        return meta.source_ip.empty() ? std::string("an unidentified peer")
                                      : meta.source_ip;
    }

    static std::string toHex(std::uint16_t value)
    {
        static constexpr char kDigits[] = "0123456789abcdef";
        std::string out(4, '0');
        for (int i = 3; i >= 0; --i) {
            out[static_cast<std::size_t>(i)] = kDigits[value & 0xF];
            value = static_cast<std::uint16_t>(value >> 4);
        }
        return out;
    }
};

}  // namespace https_guard

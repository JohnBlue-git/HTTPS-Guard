#pragma once

#include <optional>
#include <string>

#include "IDetector.hpp"
#include "hg_event.hpp"
#include "ITlsTrafficInfo.hpp"
#include "Verdict.hpp"
#include "tls_version.hpp"

namespace https_guard {

/**
 * Flags a negotiated TLS version below TLS 1.2 (0x0303) as a Critical
 * violation. A version of 0 normally means "no TLS version observed"
 * (e.g. the uprobe never resolved ssl->version) and is not on its own
 * treated as a violation — except when the producing hook already
 * determined it is one (tls_violation_hint), since a hook that classifies
 * on the wire (e.g. XDP) can see a genuinely-parsed 0x0000 legacy_version,
 * which is a real violation, not a missing-data sentinel.
 */
class TlsVersionDetector final : public IDetector {
public:
    std::optional<Verdict> evaluate(const hg_event& evt) const override
    {
        // Binds to the capability, not to a hook: both ssl_uprobe and
        // xdp_tls supply this, and neither is named here.
        const auto* tls = dynamic_cast<const ITlsTrafficInfo*>(&evt);
        if (tls == nullptr) {
            return std::nullopt;  // event source can't describe TLS traffic
        }

        const bool violation = tls->tlsViolationHint() ||
                                (tls->tlsVersion() > 0 && tls->tlsVersion() < 0x0303);
        if (!violation) {
            return std::nullopt;
        }

        Verdict verdict;
        verdict.severity   = "Critical";
        verdict.message_id = "OemSecurityEvent.1.0.HttpsTlsVersionViolation";
        verdict.message    = "Security violation: Process '" + evt.process +
                             "' (PID " + std::to_string(evt.pid) +
                             ") attempted an HTTPS connection using an insecure TLS version (" +
                             TlsVersion(tls->tlsVersion()).toString() + "). Packet was blocked.";
        verdict.actionable = true;
        return verdict;
    }
};

}  // namespace https_guard

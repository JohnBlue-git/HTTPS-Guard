#pragma once

#include <optional>
#include <string>

#include "IDetector.hpp"
#include "IRenegotiationInfo.hpp"
#include "Verdict.hpp"
#include "hg_event.hpp"

namespace https_guard {

/**
 * Flags a source sending TLS handshakes faster than the configured limit.
 *
 * Renegotiation is expensive for the server and cheap for the client, which
 * is the whole basis of the attack — so a source repeatedly handshaking is
 * asymmetric load, not merely unusual traffic. Actionable for that reason.
 *
 * Stateless: the counting is done in BPF and aggregated by ConnRateSweeper.
 */
class RenegotiationDetector final : public IDetector {
public:
    std::optional<Verdict> evaluate(const hg_event& evt) const override
    {
        const auto* reneg = dynamic_cast<const IRenegotiationInfo*>(&evt);
        if (reneg == nullptr) {
            return std::nullopt;
        }
        if (reneg->threshold() == 0 || reneg->handshakeCount() < reneg->threshold()) {
            return std::nullopt;
        }

        const std::string peer = evt.source_ip.empty() ? std::string("an unidentified peer")
                                                       : evt.source_ip;

        Verdict verdict;
        verdict.severity   = "Warning";
        verdict.message_id = "OemSecurityEvent.1.0.HttpsTlsRenegotiationStorm";
        verdict.message    = "TLS renegotiation storm from " + peer + ": " +
                             std::to_string(reneg->handshakeCount()) +
                             " handshake records in " +
                             std::to_string(reneg->windowSeconds()) +
                             "s exceeds the configured limit of " +
                             std::to_string(reneg->threshold()) +
                             ". Source should be quarantined.";
        verdict.actionable = true;
        return verdict;
    }
};

}  // namespace https_guard

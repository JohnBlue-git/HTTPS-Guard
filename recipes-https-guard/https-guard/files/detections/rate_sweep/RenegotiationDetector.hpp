#pragma once

#include <optional>
#include <string>

#include "RenegotiationEvent.hpp"
#include "Verdict.hpp"

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
class RenegotiationDetector {
public:
    std::optional<Verdict> evaluate(const RenegotiationEvent& evt) const
    {
        if (evt.threshold == 0 || evt.handshakes_in_window < evt.threshold)
        {
            return std::nullopt;
        }

        const std::string peer = evt.meta.source_ip.empty()
                                     ? std::string("an unidentified peer")
                                     : evt.meta.source_ip;

        Verdict verdict;
        verdict.severity   = "Warning";
        verdict.message_id = "OemSecurityEvent.1.0.HttpsTlsRenegotiationStorm";
        verdict.message    = "TLS renegotiation storm from " + peer + ": " +
                             std::to_string(evt.handshakes_in_window) +
                             " handshake records in " +
                             std::to_string(evt.window_seconds) +
                             "s exceeds the configured limit of " +
                             std::to_string(evt.threshold) +
                             ". Source should be quarantined.";
        verdict.actionable = true;
        return verdict;
    }
};

}  // namespace https_guard

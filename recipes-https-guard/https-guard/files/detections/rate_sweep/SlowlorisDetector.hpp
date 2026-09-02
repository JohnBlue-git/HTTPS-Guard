#pragma once

#include <optional>
#include <string>

#include "SlowlorisEvent.hpp"
#include "Verdict.hpp"

namespace https_guard {

/**
 * Flags a source holding more connections open than the configured limit.
 *
 * Stateless, like every other detector here: the counting happens in a BPF
 * map and is aggregated by ConnRateSweeper before this ever sees it. That is
 * deliberate — see this ticket's architecture note — and it is why this class
 * can be tested with a hand-built event and no kernel.
 *
 * Actionable, on the same reasoning as connection-rate detection: occupying
 * connection slots is ongoing harm, and an alert that does not free them
 * leaves bmcweb exhausted. Note the flip side, which makes the threshold
 * safety-critical: a legitimate client that keeps many long-lived
 * connections (a websocket-heavy dashboard, say) looks exactly like this.
 */
class SlowlorisDetector {
public:
    std::optional<Verdict> evaluate(const SlowlorisEvent& evt) const
    {
        if (evt.threshold == 0 || evt.open_connections < evt.threshold) {
            return std::nullopt;
        }

        const std::string peer = evt.meta.source_ip.empty()
                                     ? std::string("an unidentified peer")
                                     : evt.meta.source_ip;

        Verdict verdict;
        verdict.severity   = "Warning";
        verdict.message_id = "OemSecurityEvent.1.0.HttpsSlowlorisDetected";
        verdict.message    = "Possible Slowloris from " + peer + ": " +
                             std::to_string(evt.open_connections) +
                             " connections held open exceeds the configured limit of " +
                             std::to_string(evt.threshold) +
                             ". Source should be quarantined.";
        verdict.actionable = true;
        return verdict;
    }
};

}  // namespace https_guard

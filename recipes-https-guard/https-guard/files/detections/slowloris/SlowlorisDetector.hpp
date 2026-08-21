#pragma once

#include <optional>
#include <string>

#include "IDetector.hpp"
#include "ISlowlorisInfo.hpp"
#include "Verdict.hpp"
#include "hg_event.hpp"

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
class SlowlorisDetector final : public IDetector {
public:
    std::optional<Verdict> evaluate(const hg_event& evt) const override
    {
        const auto* slow = dynamic_cast<const ISlowlorisInfo*>(&evt);
        if (slow == nullptr) {
            return std::nullopt;
        }
        if (slow->threshold() == 0 || slow->openConnections() < slow->threshold()) {
            return std::nullopt;
        }

        const std::string peer = evt.source_ip.empty() ? std::string("an unidentified peer")
                                                       : evt.source_ip;

        Verdict verdict;
        verdict.severity   = "Warning";
        verdict.message_id = "OemSecurityEvent.1.0.HttpsSlowlorisDetected";
        verdict.message    = "Possible Slowloris from " + peer + ": " +
                             std::to_string(slow->openConnections()) +
                             " connections held open exceeds the configured limit of " +
                             std::to_string(slow->threshold()) +
                             ". Source should be quarantined.";
        verdict.actionable = true;
        return verdict;
    }
};

}  // namespace https_guard

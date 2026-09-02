#pragma once

#include <optional>
#include <string>

#include "ConnRateEvent.hpp"
#include "Verdict.hpp"

namespace https_guard {

/**
 * Flags a source that made more connection attempts inside the counting
 * window than the configured threshold allows.
 *
 * **Actionable, unlike CipherSuiteDetector and SniDetector**, and the
 * difference is deliberate. Those two fire on a handshake bmcweb refuses
 * anyway: the offer itself does no damage, so alerting is the proportionate
 * response and blocklisting an address across every port is not. A flood or
 * a scan is ongoing active harm, and an alert that does not stop it is of
 * little use — so here enforcement is the point.
 *
 * That makes the threshold the safety-critical knob rather than a tuning
 * detail: too low, and a monitoring system or several administrators behind
 * one NAT address get locked out of every service on the BMC. It is
 * configurable for exactly that reason, and the default was chosen by
 * measuring ordinary traffic rather than picked as a round number.
 */
class ConnRateDetector {
public:
    std::optional<Verdict> evaluate(const ConnRateEvent& evt) const
    {
        // The sweeper only synthesises an event once a window is already over
        // the threshold, but re-check rather than trust the caller: this class
        // is what the tests exercise, and it should be correct alone.
        if (evt.threshold == 0 || evt.attempts_in_window < evt.threshold) {
            return std::nullopt;
        }

        const std::string peer = evt.meta.source_ip.empty()
                                     ? std::string("an unidentified peer")
                                     : evt.meta.source_ip;

        Verdict verdict;
        verdict.severity   = "Warning";
        verdict.message_id = "OemSecurityEvent.1.0.HttpsConnectionRateViolation";
        verdict.message    = "Connection-rate violation from " + peer + ": " +
                             std::to_string(evt.attempts_in_window) +
                             " connection attempts in " +
                             std::to_string(evt.window_seconds) +
                             "s exceeds the configured threshold of " +
                             std::to_string(evt.threshold) +
                             ". Source should be quarantined.";
        verdict.actionable = true;
        return verdict;
    }
};

}  // namespace https_guard

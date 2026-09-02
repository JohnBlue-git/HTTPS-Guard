#pragma once

#include <algorithm>
#include <array>
#include <optional>
#include <string>

#include "Verdict.hpp"
#include "PayloadEvent.hpp"

namespace https_guard {

/**
 * Case-insensitive substring match for attack signatures in observed plaintext.
 *
 * Bound to the PayloadEvent concept, so it serves the uprobe and XDP paths from
 * one definition without naming either. Capped input is expected: the producing
 * hook copies at most 127 bytes per call, so a signature falling entirely past
 * that offset is not seen -- recorded in LIMITATIONS.md rather than papered over.
 */
class PayloadAnomalyDetector {
public:
    std::optional<Verdict> evaluate(const PayloadEvent& evt) const
    {
        if (evt.payload_snippet.empty())
        {
            return std::nullopt;
        }

        std::string lowered = evt.payload_snippet;
        std::transform(lowered.begin(), lowered.end(), lowered.begin(),
                       [](unsigned char c) { return static_cast<char>(std::tolower(c)); });

        for (const auto* rule : kRules)
        {
            if (lowered.find(rule) != std::string::npos)
            {
                Verdict verdict;
                verdict.severity   = "Warning";
                verdict.message_id = "OemSecurityEvent.1.0.HttpsPayloadAnomalyDetected";
                verdict.message    = "Attack signature detected from process '" + evt.meta.process +
                                     "' (PID " + std::to_string(evt.meta.pid) +
                                     "), rule '" + rule +
                                     "'. Source should be quarantined.";
                verdict.actionable = true;
                return verdict;
            }
        }

        return std::nullopt;
    }

private:
    inline static const std::array<const char*, 8> kRules = {
        "../..",
        "union select",
        "or 1=1",
        "drop table",
        "/etc/passwd",
        "%2e%2e%2f",
        "cmd.exe",
        "wget http"
    };
};

}  // namespace https_guard

#pragma once

#include <algorithm>
#include <array>
#include <optional>
#include <string>

#include "IDetector.hpp"
#include "hg_event.hpp"
#include "ITlsTrafficInfo.hpp"
#include "Verdict.hpp"

namespace https_guard {

/**
 * Flags a plaintext HTTP payload containing a known attack-signature
 * substring (SQLi, path traversal, etc.) as a Warning. Applies to
 * whatever payload_snippet an event carries, regardless of which hook
 * produced it — it has no opinion on TLS version or source.
 */
class PayloadAnomalyDetector final : public IDetector {
public:
    std::optional<Verdict> evaluate(const hg_event& evt) const override
    {
        const auto* tls = dynamic_cast<const ITlsTrafficInfo*>(&evt);
        if (tls == nullptr) {
            return std::nullopt;  // nothing to inspect for this event source
        }

        std::string lowered(tls->payloadSnippet());
        std::transform(lowered.begin(), lowered.end(), lowered.begin(), ::tolower);

        for (const auto* rule : kRules) {
            if (lowered.find(rule) != std::string::npos) {
                Verdict verdict;
                verdict.severity   = "Warning";
                verdict.message_id = "OemSecurityEvent.1.0.HttpsPayloadAnomalyDetected";
                verdict.message    = "Attack signature detected from process '" + evt.process +
                                     "' (PID " + std::to_string(evt.pid) +
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

#pragma once

#include <algorithm>
#include <array>
#include <string>

namespace https_guard {

class PatternDetector {
public:
    bool isSuspicious(const std::string& payload, std::string& matched_rule) const
    {
        std::string lowered(payload);
        std::transform(lowered.begin(), lowered.end(), lowered.begin(), ::tolower);

        for (const auto* rule : kRules) {
            if (lowered.find(rule) != std::string::npos) {
                matched_rule = rule;
                return true;
            }
        }

        return false;
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

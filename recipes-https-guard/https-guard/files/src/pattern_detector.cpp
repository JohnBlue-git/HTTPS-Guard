#include "pattern_detector.hpp"

#include <algorithm>
#include <array>

namespace https_guard {

bool is_http_payload_suspicious(const std::string& payload, std::string& matched_rule)
{
	static const std::array<const char*, 8> kRules = {
		"../..",
		"union select",
		"or 1=1",
		"drop table",
		"/etc/passwd",
		"%2e%2e%2f",
		"cmd.exe",
		"wget http"
	};

	std::string lowered(payload);
	std::transform(lowered.begin(), lowered.end(), lowered.begin(), ::tolower);

	for (const auto* r : kRules) {
		if (lowered.find(r) != std::string::npos) {
			matched_rule = r;
			return true;
		}
	}

	return false;
}

}  // namespace https_guard

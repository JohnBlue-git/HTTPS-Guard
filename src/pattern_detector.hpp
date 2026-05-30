#ifndef HTTPS_GUARD_PATTERN_DETECTOR_HPP
#define HTTPS_GUARD_PATTERN_DETECTOR_HPP

#include <string>

namespace https_guard {

bool is_http_payload_suspicious(const std::string& payload, std::string& matched_rule);

}  // namespace https_guard

#endif

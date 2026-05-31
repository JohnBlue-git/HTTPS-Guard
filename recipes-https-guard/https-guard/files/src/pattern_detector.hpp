#pragma once
#include <string>

namespace https_guard {
bool is_http_payload_suspicious(const std::string& payload, std::string& matched_rule);
}

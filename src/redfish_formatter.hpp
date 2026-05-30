#ifndef HTTPS_GUARD_REDFISH_FORMATTER_HPP
#define HTTPS_GUARD_REDFISH_FORMATTER_HPP

#include <string>

#include "https_guard/events.h"

namespace https_guard {

std::string tls_version_to_string(uint16_t tls_version);
std::string now_utc_iso8601();
std::string format_redfish_event(const hg_event& event,
                                 const std::string& message_id,
                                 const std::string& message,
                                 const std::string& severity);

}  // namespace https_guard

#endif

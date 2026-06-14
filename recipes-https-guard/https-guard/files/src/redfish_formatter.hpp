#pragma once
#include <string>
#include "https_guard/events.h"

namespace https_guard {
std::string format_redfish_event(const hg_event& event,
                                 const std::string& message_id,
                                 const std::string& message,
                                 const std::string& severity);
}

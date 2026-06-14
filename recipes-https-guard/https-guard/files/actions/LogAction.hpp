#pragma once

#include <string>

#include "ActionLoop.hpp"
#include "events.h"
#include "redfish_formatter.hpp"

namespace https_guard {

class LogAction : public Action {
public:
    explicit LogAction(std::string output_path);
    void execute(const hg_event& event,
                 const std::string& message_id,
                 const std::string& message,
                 const std::string& severity) override;

private:
    void write_event(const std::string& line);

    std::string output_path_;
    RedfishFormatter formatter_;
};

}  // namespace https_guard

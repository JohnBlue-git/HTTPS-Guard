#pragma once

#include <string>

#include "ActionLoop.hpp"
#include "events.h"
#include "pattern_detector.hpp"
#include "redfish_formatter.hpp"
#include "string_utils.hpp"

namespace https_guard {

class LogAction : public Action {
public:
    explicit LogAction(std::string output_path);
    void execute(const hg_event& event) override;

private:
    std::tuple<std::string, std::string, std::string> create_event_details(const hg_event& event) const;
    void write_event(const std::string& line);

    std::string output_path_;
    PatternDetector pattern_detector_;
    RedfishFormatter formatter_;
};

}  // namespace https_guard

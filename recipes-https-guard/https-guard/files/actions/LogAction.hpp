#pragma once

#include <boost/asio/awaitable.hpp>
#include <string>

#include "ActionLoop.hpp"
#include "events.h"
#include "redfish_formatter.hpp"

namespace https_guard {

class LogAction : public Action {
public:
    LogAction(ActionLoop& action_loop, std::string output_path);
    void execute(const hg_event& event,
                 const std::string& message_id,
                 const std::string& message,
                 const std::string& severity) override;

private:
    static bool ensure_log_directory(const std::string& path) noexcept;
    boost::asio::awaitable<void> execute_async(std::string payload);

    std::string output_path_;
    RedfishFormatter formatter_;
    ActionLoop& action_loop_;
};

}  // namespace https_guard

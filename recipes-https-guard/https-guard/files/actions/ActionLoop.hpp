#pragma once

#include <boost/asio.hpp>
#include <memory>
#include <string>
#include <thread>
#include <vector>

#include "events.h"

namespace https_guard {

class Action {
public:
    virtual ~Action() = default;
    virtual void execute(const hg_event& event,
                         const std::string& message_id,
                         const std::string& message,
                         const std::string& severity) = 0;
};

class ActionLoop {
public:
    static ActionLoop& getInstance();

    ActionLoop();
    ~ActionLoop();

    void add_action(std::unique_ptr<Action> action);
    void post(const hg_event& event,
              const std::string& message_id,
              const std::string& message,
              const std::string& severity);
    void run();
    void stop();

private:
    void handle(const hg_event& event,
                const std::string& message_id,
                const std::string& message,
                const std::string& severity);

    boost::asio::io_context io_context_;
    boost::asio::executor_work_guard<boost::asio::io_context::executor_type> work_guard_;
    std::thread thread_;
    std::vector<std::unique_ptr<Action>> actions_;
};

}  // namespace https_guard

#include "ActionLoop.hpp"

namespace https_guard {

ActionLoop& ActionLoop::getInstance()
{
    static ActionLoop instance;
    return instance;
}

ActionLoop::ActionLoop()
    : work_guard_(boost::asio::make_work_guard(io_context_))
{
}

ActionLoop::~ActionLoop()
{
    stop();
}

void ActionLoop::add_action(std::unique_ptr<Action> action)
{
    actions_.push_back(std::move(action));
}

void ActionLoop::post(const hg_event& event,
                      const std::string& message_id,
                      const std::string& message,
                      const std::string& severity)
{
    io_context_.post([this, event, message_id, message, severity]() {
        handle(event, message_id, message, severity);
    });
}

void ActionLoop::run()
{
    thread_ = std::thread([this]() {
        io_context_.run();
    });
}

void ActionLoop::spawn(boost::asio::awaitable<void> awaitable)
{
    boost::asio::co_spawn(io_context_, std::move(awaitable), boost::asio::detached);
}

void ActionLoop::stop()
{
    work_guard_.reset();
    io_context_.stop();
    if (thread_.joinable()) {
        thread_.join();
    }
}

void ActionLoop::handle(const hg_event& event,
                        const std::string& message_id,
                        const std::string& message,
                        const std::string& severity)
{
    for (const auto& action : actions_) {
        action->execute(event, message_id, message, severity);
    }
}

}  // namespace https_guard

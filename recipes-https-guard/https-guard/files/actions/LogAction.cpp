#include "LogAction.hpp"
#include "../coroutine/async_mutex.hpp"

#include <filesystem>
#include <iostream>
#include <utility>

#include <boost/asio/buffer.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/write.hpp>

namespace asio = boost::asio;

namespace {

AsyncFileStreamManager g_file_mgr;

}  // namespace

namespace https_guard {

LogAction::LogAction(ActionLoop& action_loop, std::string output_path)
    : output_path_(std::move(output_path))
    , formatter_()
    , action_loop_(action_loop)
{
    ensure_log_directory(output_path_);
}

bool LogAction::ensure_log_directory(const std::string& path) noexcept
{
    if (path.empty()) {
        return false;
    }

    std::filesystem::path dir = std::filesystem::path(path).parent_path();
    if (dir.empty()) {
        return true;
    }

    std::error_code ec;
    std::filesystem::create_directories(dir, ec);
    return !ec;
}

void LogAction::execute(const hg_event& event,
                        const std::string& message_id,
                        const std::string& message,
                        const std::string& severity)
{
    const std::string payload = formatter_.format(event, message_id, message, severity);
    action_loop_.spawn(execute_async(payload));
    std::cout << "[HTTPS-Guard] " << message << "\n";
}

asio::awaitable<void> LogAction::execute_async(std::string payload)
{
    auto locked_stream = co_await g_file_mgr.acquire_stream(output_path_);
    if (!locked_stream) {
        co_return;
    }

    payload.push_back('\n');
    boost::system::error_code ec;
    co_await asio::async_write(
        locked_stream.stream(),
        asio::buffer(payload),
        asio::redirect_error(asio::use_awaitable, ec)
    );

    if (ec) {
        std::cerr << "async_write failed for " << output_path_ << ": " << ec.message() << " (" << ec.value() << ")\n";
    }
}

}  // namespace https_guard

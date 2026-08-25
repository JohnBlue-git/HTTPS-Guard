#include <exception>
#include <iostream>
#include <utility>

#include <cstddef>
#include <vector>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/deferred.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/experimental/parallel_group.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/asio/use_awaitable.hpp>

#include "ActionLoop.hpp"

namespace asio = boost::asio;


namespace https_guard {

ActionLoop::ActionLoop() noexcept
    : io_context_()
    , work_guard_(asio::make_work_guard(io_context_))
{
    try {
        thread_ = std::thread([this] { io_context_.run(); });
    } catch (...) {
        stop_.store(true, std::memory_order_relaxed);
        work_guard_.reset();
        io_context_.stop();
    }
}

ActionLoop::~ActionLoop() noexcept {
    stop_.store(true, std::memory_order_relaxed);
    work_guard_.reset();
    io_context_.stop();
    if (thread_.joinable()) thread_.join();
}

ActionLoop& ActionLoop::getInstance() noexcept
{
    static ActionLoop instance;
    return instance;
}

// Tough push would be blocked by the mutex, it is still sufficient for our use case since the ActionLoop is designed to be a single producer (main thread) and single consumer (background thread) model.
// If we want to support multiple producers, we would need to implement a more sophisticated event loop for ActionLoop
void ActionLoop::pushAction(std::unique_ptr<IAction> action) noexcept
{
    // If the action is null or the loop is stopping, we simply ignore the push request.
    if (!action || stop_.load(std::memory_order_relaxed)) {
        return;
    }

    try {
        asio::co_spawn(io_context_,
            [this, action = std::move(action)]() mutable -> asio::awaitable<void> {
            // If the action is null or the loop is stopping, we simply ignore the execution request.
            if (!action || stop_.load(std::memory_order_relaxed)) {
                co_return;
            }

            // We execute the action asynchronously and catch any exceptions to prevent them from propagating and potentially crashing the ActionLoop.
            try {
                co_await action->execute_async();
            } catch (std::exception& e) {
                std::cerr << "Error: failed to execute action: " << e.what() << '\n';
            } catch (...) {
                std::cerr << "Error: failed to execute action due to unknown error\n";
            }

            co_return;
            },
            asio::detached);

    } catch (std::exception& e) {
        std::cerr << "Error: failed to push action to ActionLoop: " << e.what() << '\n';
    } catch (...) {
        std::cerr << "Error: failed to push action to ActionLoop due to unknown error\n";
    }
}

void ActionLoop::pushActions(std::vector<std::unique_ptr<IAction>> actions) noexcept
{
    if (actions.empty() || stop_.load(std::memory_order_relaxed)) {
        return;
    }

    try {
        asio::co_spawn(io_context_,
            [this, actions = std::move(actions)]() mutable -> asio::awaitable<void> {
                if (stop_.load(std::memory_order_relaxed)) {
                    co_return;
                }

                const auto executor = co_await asio::this_coro::executor;

                /* Collect the launched operations first, then wait on all of
                 * them -- the shape `when_all` takes in other coroutine
                 * libraries. co_spawn(..., deferred) yields an operation that
                 * has not started yet, and parallel_group starts them together.
                 * Ranged, because the count is a runtime property of the verdict
                 * (one, two or three). */
                using Op = decltype(asio::co_spawn(
                    executor, std::declval<asio::awaitable<void>>(), asio::deferred));

                std::vector<Op> ops;
                ops.reserve(actions.size());
                for (auto& action : actions) {
                    if (action) {
                        ops.push_back(asio::co_spawn(
                            executor, action->execute_async(), asio::deferred));
                    }
                }
                if (ops.empty()) {
                    co_return;
                }

                auto [completion_order, exceptions] =
                    co_await asio::experimental::make_parallel_group(std::move(ops))
                        .async_wait(asio::experimental::wait_for_all(),
                                    asio::use_awaitable);
                (void)completion_order;

                /* One report per verdict, naming which parts failed. Previously
                 * each action logged into the void independently, so "two of
                 * three countermeasures worked" was not something anyone could
                 * see. */
                std::size_t failed = 0;
                for (std::size_t i = 0; i < exceptions.size(); ++i) {
                    if (!exceptions[i]) {
                        continue;
                    }
                    ++failed;
                    try {
                        std::rethrow_exception(exceptions[i]);
                    } catch (const std::exception& e) {
                        std::cerr << "Error: action " << i << " of " << exceptions.size()
                                  << " failed: " << e.what() << '\n';
                    } catch (...) {
                        std::cerr << "Error: action " << i << " of " << exceptions.size()
                                  << " failed with an unknown exception\n";
                    }
                }
                if (failed != 0) {
                    std::cerr << "Error: " << failed << " of " << exceptions.size()
                              << " action(s) for this verdict did not complete\n";
                }

                co_return;
            },
            asio::detached);

    } catch (const std::exception& e) {
        std::cerr << "Error: failed to push action group to ActionLoop: " << e.what() << '\n';
    } catch (...) {
        std::cerr << "Error: failed to push action group to ActionLoop (unknown error)\n";
    }
}

}  // namespace https_guard

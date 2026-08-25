#pragma once

#include <atomic>
#include <memory>
#include <vector>
#include <thread>

#include <boost/asio/awaitable.hpp>
#include <boost/asio/executor_work_guard.hpp>
#include <boost/asio/io_context.hpp>


namespace https_guard {

class IAction {
public:
    virtual ~IAction() = default;
    virtual boost::asio::awaitable<void> execute_async() = 0;
};

class ActionLoop {
public:
    ActionLoop(const ActionLoop&) = delete;
    ActionLoop& operator=(const ActionLoop&) = delete;

    static ActionLoop& getInstance() noexcept;
    ~ActionLoop() noexcept;

    void pushAction(std::unique_ptr<IAction> action) noexcept;

    /**
     * Runs every action for one verdict concurrently, and waits for all of them.
     *
     * WHY A GROUP RATHER THAN N SEPARATE PUSHES
     * -----------------------------------------
     * A verdict produces up to three actions, and they are genuinely
     * independent I/O: a file write, a netlink SOCK_DESTROY syscall, and a BPF
     * map update. Pushed one at a time they were three detached coroutines with
     * no relationship -- so they ran strictly one after another on the single
     * ActionLoop thread, and nothing anywhere knew when a verdict's *response*
     * had finished or which part of it had failed.
     *
     * Collected into one group they overlap at their suspension points, which is
     * where the waiting actually is, and there is a single completion point:
     * every action's outcome is known together, so a failure is reported
     * alongside its siblings rather than in isolation. That matters here
     * specifically because a silently failing countermeasure is this project's
     * most-repeated bug -- SOCK_DESTROY failed on every event for a long time
     * while the Redfish log looked perfectly healthy.
     *
     * Concurrency, not parallelism: one thread, interleaved at `co_await`. That
     * is the right model for I/O-bound work and the wrong one for CPU-bound
     * work, which is exactly why the detection path does NOT do this. Two of the
     * three actions here genuinely suspend -- BlockTcpAction on an epoll-driven
     * netlink round-trip, LogAction on a coroutine-aware file lock and an
     * async_write -- whereas nothing on the detection path waits on anything
     * external at all. See `detections/core/contract/IDetection.hpp` for that
     * argument at the seam, and `detections/DESIGN.md` for it with the numbers.
     */
    void pushActions(std::vector<std::unique_ptr<IAction>> actions) noexcept;

private:
    ActionLoop() noexcept;

    boost::asio::io_context io_context_;
    boost::asio::executor_work_guard<boost::asio::io_context::executor_type> work_guard_;
    std::thread thread_;
    std::atomic_bool stop_{false};
};

}  // namespace https_guard

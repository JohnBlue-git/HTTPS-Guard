#pragma once

#include <array>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

#include <boost/asio/executor_work_guard.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/strand.hpp>

#include "IDetector.hpp"
#include "IHookModule.hpp"
#include "hg_event_source.h"
#include "core/ActionLoop.hpp"
#include "ConnRateSweeper.hpp"

namespace https_guard {

/**
 * Runs parse -> classify -> dispatch off the libbpf poll thread, on a
 * Boost.Asio event loop -- the same scaffolding `ActionLoop` uses.
 *
 * WHY THIS EXISTS
 * ---------------
 * A ring-buffer callback that runs long lets the buffer fill, and a full
 * ring buffer *drops events* -- a dropped event is a missed detection that
 * nothing reports. Keeping the poll thread short is therefore a detection
 * property, not just a latency one, and it matters most under load, which is
 * exactly when an attack is most likely.
 *
 * The boundary is drawn at the **raw record**, not after parsing. The
 * motivating complaint was that the callback ran `detector->evaluate()`, but
 * measured, evaluate() is the cheapest thing in it (a few hundred integer
 * compares worst case); the real cost is the /proc walk inside parsing. A
 * queue placed after parsing would have added a thread hop and left the
 * bottleneck untouched.
 *
 * WHY post() AND NOT co_spawn()
 * -----------------------------
 * `ActionLoop` uses `co_spawn` because `IAction`'s entry point is a
 * coroutine. Nothing on the classify path awaits anything -- process() and
 * classifyAndDispatch() are straight-line synchronous code -- so `post()` is
 * the honest primitive here, and a coroutine frame per event would be pure
 * overhead. Same loop, different handler shape.
 *
 * TWO THREADS, AND WHY THE SWEEP IS NOT ON THE STRAND
 * --------------------------------------------------
 * Records are posted through `record_strand_`, which serializes them and
 * keeps them in arrival order. The periodic sweep is *not* on that strand,
 * and the loop runs two threads specifically so it need not be.
 *
 * This is the fix for a bug that already shipped once. The sweep originally
 * ran only when the record queue was empty, so a flood -- which generates
 * events -- starved it, and rate detection switched off precisely when it
 * was needed. A single-threaded io_context would reintroduce a weaker form
 * of the same thing by FIFO fairness alone: an expiring timer queues
 * *behind* every record already posted, so a deep backlog delays the sweep
 * by (backlog x per-event cost). Against a fixed 10s counting window
 * (HTTPS_GUARD_CONN_RATE_WINDOW_SEC) that can let a window roll unobserved
 * and lose a flood entirely.
 *
 * The safety of that arrangement rests on classification being free of
 * shared mutable state: detectors are stateless by design (see
 * detections/CLAUDE.md, "Stateful rules without stateful detectors"),
 * ActionLoop::pushAction is thread-safe, and each event object is visible to
 * exactly one classification -- which matters because hg_event's lazy peer
 * resolution mutates `mutable` members. A detector that quietly grew a
 * member would be a data race here, not merely a style breach.
 *
 * BOUNDED ADMISSION IS EXPLICIT
 * -----------------------------
 * `post()` is an unbounded queue, and on a BMC with ~1GB of RAM trading a
 * dropped event for an OOM is a bad trade: the daemon dying takes *all*
 * detection with it, where a drop costs one event. So depth is capped here
 * by an explicit in-flight count, and the full-queue policy is to drop the
 * *newest* record and count it -- the loop then holds a coherent prefix of
 * history rather than a hole in the middle, and dropping the oldest would
 * discard the earliest evidence of an attack in progress. Drops are counted
 * and logged (rate-limited); a drop nobody hears about would recreate the
 * very failure this class exists to prevent.
 */
class DetectLoop {
public:
    /** Keyed by hg_event_source; first matching detector wins. */
    using DetectorRegistry =
        std::unordered_map<hg_event_source, std::vector<std::unique_ptr<IDetector>>>;

    DetectLoop(ActionLoop& action_loop,
               const std::vector<std::unique_ptr<IHookModule>>& hooks,
               DetectorRegistry detectors,
               std::chrono::seconds blocklist_ttl,
               std::string output_path) noexcept;

    /**
     * Starts periodic sweeping of the connection-rate counters. Optional:
     * without it the loop behaves exactly as before, which is what happens
     * when no threshold is configured.
     */
    void enableRateSweeps(int conn_rate_map_fd,
                          ConnRateSweeper::Thresholds thresholds) noexcept;

    ~DetectLoop() noexcept;

    DetectLoop(const DetectLoop&) = delete;
    DetectLoop& operator=(const DetectLoop&) = delete;

    /**
     * Copies one raw ring-buffer record onto the executor. Safe to call from
     * the libbpf callback: the sample pointer is only valid for the duration
     * of that callback, so the bytes are copied here and never referenced
     * afterwards. Never blocks and never throws.
     */
    void submit(const void* data, std::size_t size) noexcept;

    /** Abandons queued work and joins the workers. Idempotent. */
    void stop() noexcept;

    std::uint64_t droppedCount() const noexcept { return dropped_.load(std::memory_order_relaxed); }

private:
    struct RawRecord {
        std::size_t   size = 0;
        alignas(8) unsigned char bytes[HG_MAX_RAW_EVENT_SIZE];
    };

    /** Executor handler for one record: releases its slot, then classifies. */
    void handleRecord(const RawRecord& rec) noexcept;
    void process(const RawRecord& rec);

    /** Classify + dispatch, shared by parsed and synthesised events. */
    void classifyAndDispatch(const hg_event& evt, hg_event_source source);

    /** Reads the rate counters and classifies anything over the threshold. */
    void sweepRates() noexcept;

    /** (Re)arms the sweep timer. Only ever called from the loop's threads. */
    void armSweepTimer() noexcept;

    /** Counts a dropped record and says so, rate-limited. */
    void countDrop(const char* why) noexcept;

    static constexpr std::size_t kMaxQueueDepth = 4096;

    /* Two: one to drain records, one so an expiring sweep timer never has to
     * wait behind a backlog of them. See the class comment. */
    static constexpr std::size_t kThreadCount = 2;

    /* How often the rate counters are read. Short enough that a sustained
     * flood is blocklisted promptly, long enough that the sweep itself is
     * negligible next to the traffic it is watching. */
    static constexpr auto kSweepInterval = std::chrono::seconds(2);

    ActionLoop&                                    action_loop_;
    const std::vector<std::unique_ptr<IHookModule>>& hooks_;
    DetectorRegistry                               detectors_;
    std::chrono::seconds                           blocklist_ttl_;
    std::string                                    output_path_;

    boost::asio::io_context                                                io_context_;
    boost::asio::executor_work_guard<boost::asio::io_context::executor_type> work_guard_;
    boost::asio::strand<boost::asio::io_context::executor_type>             record_strand_;
    boost::asio::steady_timer                                              sweep_timer_;
    std::array<std::thread, kThreadCount>                                  threads_;

    std::atomic<bool>          stop_{false};
    std::atomic<std::size_t>   in_flight_{0};
    std::atomic<std::uint64_t> dropped_{0};
    std::unique_ptr<ConnRateSweeper> rate_sweeper_;
};

}  // namespace https_guard

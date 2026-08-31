#pragma once

#include <array>
#include <atomic>
#include <functional>
#include <span>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

#include <boost/asio/awaitable.hpp>
#include <boost/asio/executor_work_guard.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/strand.hpp>

#include "IDetection.hpp"
#include "dispatch.hpp"
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
 * co_spawn(), READY FOR A DETECTION THAT AWAITS
 * -----------------------------------------------
 * Nothing on the classify path awaits anything today -- `IDetection::inspect()`
 * is still straight-line synchronous code, exactly as `IDetection.hpp` argues it
 * should stay unless a detection genuinely needs to consult something remote or
 * slow. `handleRecord()`/`process()` are coroutines anyway, and `process()`
 * evaluates a record's detections concurrently via
 * `asio::experimental::make_parallel_group` rather than stopping at the first
 * verdict, so that the day a detection's `inspect()` does become awaitable, it
 * suspends alongside its siblings instead of requiring the loop's dispatch
 * shape to change again. Until then this costs one coroutine frame per record
 * for no behavioural difference -- every submitted detection is evaluated
 * either way, and list order still decides the winner. See detections/DESIGN.md.
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
 * exactly one classification -- which matters because EventMeta's lazy peer
 * resolution mutates `mutable` members. A detector that quietly grew a
 * member would be a data race here, not merely a style breach.
 *
 * A SINGLETON, LIKE ActionLoop
 * -----------------------------
 * There is one detection pipeline per process, and every hook's ring-buffer
 * handler needs to reach it. Passing a reference down through the BPF
 * lifecycle to each hook just to call one method was the alternative, and it
 * made `BpfProgram` know about classification.
 *
 * Unlike `ActionLoop`, this loop needs configuration -- the hooks, the
 * blocklist TTL, the output path -- so construction and configuration are
 * separate: `getInstance()` returns a loop whose threads are already running
 * but which has nothing to dispatch to yet, and `configure()` supplies the
 * rest exactly once. A record arriving before that is counted and reported,
 * never silently discarded; in practice it cannot happen, because polling
 * only starts after the composition root has configured the loop.
 *
 * WHY IT KNOWS NOTHING ABOUT EVENTS
 * --------------------------------
 * This class owns a queue, some threads and a timer. It does not know what an
 * event is, which detections exist, or what any of them mean. A record arrives
 * with the list of detections to try against it, the loop walks that list in
 * order, and the first one that returns a verdict wins.
 *
 * Three things fall out of that. The tree never names a hook type, so it keeps
 * no libbpf dependency and stays buildable and unit-testable without a kernel.
 * There is no common event base and no `dynamic_cast` anywhere on the path --
 * each detection knows its own concrete types from the raw bytes through to the
 * verdict. And there is no "no rule matched" branch here either: a hook puts an
 * always-matching `TrafficObservedDetection` last in its list, so first-match-
 * wins covers it with no special case.
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
    /**
     * The detections to try against one record, in priority order.
     *
     * A non-owning view: the hook owns its detections as members, and they
     * outlive the loop. `submit()` copies the pointers into the queued record,
     * because the view itself is typically a temporary at the call site and the
     * record is inspected long after `submit()` has returned.
     */
    using DetectionList = std::span<const IDetection* const>;

    /** How many detections one record may carry. Four is the current maximum. */
    static constexpr std::size_t kMaxDetectionsPerRecord = 8;

    /** The one pipeline for this process. Threads are running on return. */
    static DetectLoop& getInstance() noexcept;

    /**
     * An independent, unconfigured loop, for tests only.
     *
     * A singleton has one honest cost: the thing it makes global stops being
     * constructible per-scenario, and `tests/detectloop/` builds five separate
     * loops precisely so each scheduling property (bounded admission, arrival
     * order, sweep-under-backlog, the throwing-handler boundary, stop()
     * idempotence) is exercised against a clean instance. Losing four of those
     * five checks to protect the singleton would be the wrong trade.
     *
     * Production code must use `getInstance()`. Nothing outside the test
     * harness should call this.
     */
    static std::unique_ptr<DetectLoop> createForTesting() noexcept;

    /**
     * Supplies what the loop cannot invent for itself, and takes ownership of
     * the hooks. Call exactly once, from the composition root, before the
     * ring buffer starts being polled.
     *
     * Configuring twice is a programming error rather than a reconfiguration,
     * and is reported rather than half-applied: the second call would race
     * the workers already reading these fields.
     */
    void configure(ActionLoop& action_loop,
                   std::chrono::seconds blocklist_ttl,
                   std::string output_path) noexcept;

    bool configured() const noexcept { return configured_.load(std::memory_order_acquire); }

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
     * Copies one raw ring-buffer record and the detections to try against it
     * onto the executor.
     *
     * Safe to call from the libbpf callback: the sample pointer is only valid
     * for the duration of that callback, so the bytes are copied here and never
     * referenced afterwards, and so is the pointer list. Never blocks and never
     * throws.
     *
     * The hook decides the list, because the hook is what knows which detections
     * its records can feed — see `BpfProgram::ringBufferHandler`.
     */
    void submit(const void* data, std::size_t size, DetectionList detections) noexcept;

    /** Abandons queued work and joins the workers. Idempotent. */
    void stop() noexcept;

    std::uint64_t droppedCount() const noexcept { return dropped_.load(std::memory_order_relaxed); }

private:
    DetectLoop() noexcept;

    struct RawRecord {
        std::size_t          size = 0;
        std::size_t          detection_count = 0;
        const IDetection*    detections[kMaxDetectionsPerRecord] = {};
        alignas(8) unsigned char bytes[HG_MAX_RAW_EVENT_SIZE];
    };

    /** Executor handler for one record: releases its slot, then classifies. */
    boost::asio::awaitable<void> handleRecord(RawRecord rec) noexcept;
    boost::asio::awaitable<void> process(const RawRecord& rec);


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

    /* All five are written once by configure() and read by the worker
     * threads. The release/acquire pair on configured_ is what publishes
     * them: submit() refuses anything before it is set, and Asio's post()
     * carries the happens-before from there into the handler. */
    ActionLoop*          action_loop_ = nullptr;
    std::chrono::seconds blocklist_ttl_{0};
    std::string          output_path_;

    boost::asio::io_context                                                io_context_;
    boost::asio::executor_work_guard<boost::asio::io_context::executor_type> work_guard_;
    boost::asio::strand<boost::asio::io_context::executor_type>             record_strand_;
    boost::asio::steady_timer                                              sweep_timer_;
    std::array<std::thread, kThreadCount>                                  threads_;

    std::atomic<bool>          configured_{false};
    std::atomic<std::uint64_t> unconfigured_{0};
    std::atomic<std::uint64_t> undetected_{0};
    std::atomic<bool>          stop_{false};
    std::atomic<std::size_t>   in_flight_{0};
    std::atomic<std::uint64_t> dropped_{0};
    std::unique_ptr<ConnRateSweeper> rate_sweeper_;
};

}  // namespace https_guard

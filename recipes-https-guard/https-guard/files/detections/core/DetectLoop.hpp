#pragma once

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

#include "IDetector.hpp"
#include "IHookModule.hpp"
#include "hg_event_source.h"
#include "core/ActionLoop.hpp"

namespace https_guard {

/**
 * Runs parse -> classify -> dispatch on its own thread, so libbpf's
 * ring-buffer callback can return immediately.
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
 * WHY NOT AN ActionLoop ACTION
 * ----------------------------
 * Classification *produces* actions, so running it on ActionLoop's executor
 * means co_spawning onto the queue it is currently executing from -- a
 * self-feeding queue, which makes bounding and shutdown hard to reason
 * about. It would also put two very different latency profiles (netlink
 * syscalls and file writes vs. classification) behind one executor.
 *
 * WHY A BOUNDED QUEUE RATHER THAN ActionLoop's SHAPE
 * -------------------------------------------------
 * ActionLoop uses Boost.Asio `co_spawn(..., detached)`, which is unbounded.
 * On a BMC with ~1GB of RAM, trading a dropped event for an OOM is a bad
 * trade, so this uses an explicit bounded queue instead. Full-queue policy
 * is to drop the *newest* record and count it: the queue then holds a
 * coherent prefix of history rather than a hole in the middle, and dropping
 * the oldest would discard the earliest evidence of an attack in progress.
 * Drops are counted and logged (rate-limited) -- a drop nobody hears about
 * would recreate the very failure this class exists to prevent.
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

    ~DetectLoop() noexcept;

    DetectLoop(const DetectLoop&) = delete;
    DetectLoop& operator=(const DetectLoop&) = delete;

    /**
     * Copies one raw ring-buffer record onto the queue. Safe to call from
     * the libbpf callback: the sample pointer is only valid for the duration
     * of that callback, so the bytes are copied here and never referenced
     * afterwards. Never blocks and never throws.
     */
    void submit(const void* data, std::size_t size) noexcept;

    /** Drops queued work and joins the worker. Idempotent. */
    void stop() noexcept;

    std::uint64_t droppedCount() const noexcept { return dropped_.load(std::memory_order_relaxed); }

private:
    struct RawRecord {
        std::size_t   size = 0;
        alignas(8) unsigned char bytes[HG_MAX_RAW_EVENT_SIZE];
    };

    void run() noexcept;
    void process(const RawRecord& rec);

    static constexpr std::size_t kMaxQueueDepth = 4096;

    ActionLoop&                                    action_loop_;
    const std::vector<std::unique_ptr<IHookModule>>& hooks_;
    DetectorRegistry                               detectors_;
    std::chrono::seconds                           blocklist_ttl_;
    std::string                                    output_path_;

    std::mutex                 mutex_;
    std::condition_variable    cv_;
    std::deque<RawRecord>      queue_;
    std::atomic<bool>          stop_{false};
    std::atomic<std::uint64_t> dropped_{0};
    std::thread                worker_;
};

}  // namespace https_guard

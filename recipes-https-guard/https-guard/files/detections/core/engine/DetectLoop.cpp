#include <cstring>
#include <exception>
#include <iostream>
#include <optional>
#include <utility>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/deferred.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/experimental/parallel_group.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/asio/use_awaitable.hpp>

#include "DetectLoop.hpp"

namespace asio = boost::asio;

namespace https_guard {

DetectLoop& DetectLoop::getInstance() noexcept
{
    static DetectLoop instance;
    return instance;
}

std::unique_ptr<DetectLoop> DetectLoop::createForTesting() noexcept
{
    /* Not make_unique: the constructor is private, and this factory is the
     * only sanctioned way past that outside getInstance(). */
    return std::unique_ptr<DetectLoop>(new (std::nothrow) DetectLoop());
}

void DetectLoop::configure(ActionLoop& action_loop,
                           std::chrono::seconds blocklist_ttl,
                           std::string output_path) noexcept
{
    if (configured_.load(std::memory_order_acquire)) {
        /* Not a reconfiguration: the worker threads are already reading these
         * fields, so a second write would be a data race. Refuse loudly
         * rather than half-applying it. */
        std::cerr << "https_guard: BUG: DetectLoop::configure() called twice; "
                     "ignoring the second call\n";
        return;
    }
    if (stop_.load(std::memory_order_relaxed)) {
        std::cerr << "https_guard: DetectLoop::configure() after stop(); ignored\n";
        return;
    }

    action_loop_   = &action_loop;
    blocklist_ttl_ = blocklist_ttl;
    output_path_   = std::move(output_path);

    /* Release, paired with the acquire in submit(): everything above must be
     * visible to a worker before any record can reach one. */
    configured_.store(true, std::memory_order_release);
}

DetectLoop::DetectLoop() noexcept
    : io_context_()
    , work_guard_(asio::make_work_guard(io_context_))
    , record_strand_(asio::make_strand(io_context_))
    , sweep_timer_(io_context_)
{
    try {
        for (auto& t : threads_) {
            t = std::thread([this] { io_context_.run(); });
        }
    } catch (...) {
        // Without a worker nothing would ever be classified, so make the
        // failure loud rather than silently accepting events onto an
        // executor that is never run.
        stop_.store(true, std::memory_order_relaxed);
        work_guard_.reset();
        io_context_.stop();
        for (auto& t : threads_) {
            if (t.joinable()) t.join();
        }
        std::cerr << "https_guard: FATAL: could not start DetectLoop workers; "
                     "no events will be classified\n";
    }
}

DetectLoop::~DetectLoop() noexcept
{
    stop();
}

void DetectLoop::stop() noexcept
{
    if (stop_.exchange(true, std::memory_order_relaxed)) {
        for (auto& t : threads_) {
            if (t.joinable()) t.join();
        }
        return;
    }

    /* Abandon rather than drain: io_context::stop() returns run() without
     * executing what is still queued. Draining could delay shutdown for as
     * long as the backlog is deep, and a security daemon being slow to stop
     * is worse than losing the tail of its backlog. Say how much was lost
     * rather than dropping it quietly.
     *
     * The sweep timer is deliberately not cancelled here: an asio timer is
     * not safe to touch concurrently with the handler that rearms it, and
     * stopping the context abandons the pending wait anyway. The stop_ flag
     * is what stops it rearming. */
    work_guard_.reset();
    io_context_.stop();

    for (auto& t : threads_) {
        if (t.joinable()) t.join();
    }

    /* Read after the joins, so nothing is still decrementing it. */
    const auto abandoned    = in_flight_.load(std::memory_order_relaxed);
    const auto dropped      = dropped_.load(std::memory_order_relaxed);
    const auto unconfigured = unconfigured_.load(std::memory_order_relaxed);
    if (abandoned != 0 || dropped != 0 || unconfigured != 0) {
        std::cerr << "https_guard: DetectLoop stopped; " << abandoned
                  << " event(s) abandoned at shutdown, " << dropped
                  << " dropped earlier (full queue, oversized, or no detections), "
                  << unconfigured
                  << " arrived before configure()\n";
    }
}

void DetectLoop::countDrop(const char* why) noexcept
{
    const auto n = dropped_.fetch_add(1, std::memory_order_relaxed) + 1;
    if (n == 1 || n % 1000 == 0) {
        std::cerr << "https_guard: DetectLoop dropped an event (" << why
                  << "); " << n << " dropped so far\n";
    }
}

void DetectLoop::submit(const void* data, std::size_t size,
                        DetectionList detections) noexcept
{
    if (data == nullptr || size == 0 || stop_.load(std::memory_order_relaxed)) {
        return;
    }

    if (!configured_.load(std::memory_order_acquire)) {
        /* Nothing to dispatch to yet. Cannot happen in the daemon -- polling
         * only starts after the composition root configures the loop -- but
         * count and say so rather than discarding a security event in
         * silence, which is the failure mode this project keeps rediscovering.
         */
        const auto n = unconfigured_.fetch_add(1, std::memory_order_relaxed) + 1;
        if (n == 1) {
            std::cerr << "https_guard: DetectLoop received an event before "
                         "configure(); dropping until configured\n";
        }
        return;
    }

    if (detections.empty()) {
        /* A hook that submits with no detections would be silently discarding
         * its own events. Report it rather than dropping them quietly. */
        countDrop("no detections submitted with the record");
        return;
    }

    if (detections.size() > kMaxDetectionsPerRecord) {
        std::cerr << "https_guard: BUG: " << detections.size()
                  << " detections submitted, cap is " << kMaxDetectionsPerRecord
                  << "; raise kMaxDetectionsPerRecord\n";
        countDrop("too many detections");
        return;
    }

    if (size > HG_MAX_RAW_EVENT_SIZE) {
        // A record larger than any known event struct: either a new hook
        // outgrew the cap without updating it, or the data is malformed.
        // Either way, don't truncate it into something that parses as
        // valid-looking nonsense.
        std::cerr << "https_guard: oversized ring-buffer record (" << size
                  << " > " << HG_MAX_RAW_EVENT_SIZE << "), dropped\n";
        dropped_.fetch_add(1, std::memory_order_relaxed);
        return;
    }

    /* Claim a slot before posting. post() itself is unbounded, so this
     * counter *is* the queue bound -- see the class comment. Never block
     * here: blocking would stall the poll thread and let the ring buffer
     * overflow, which is the problem this class exists to avoid. */
    std::size_t depth = in_flight_.load(std::memory_order_relaxed);
    do {
        if (depth >= kMaxQueueDepth) {
            countDrop("queue full");
            return;
        }
    } while (!in_flight_.compare_exchange_weak(depth, depth + 1,
                                               std::memory_order_relaxed));

    try {
        RawRecord rec;
        rec.size = size;
        std::memcpy(rec.bytes, data, size);

        /* Copy the pointers, not the view: the view is typically a temporary at
         * the call site, and this record is inspected long after submit() has
         * returned. The pointees are owned by the hook, which outlives the loop. */
        rec.detection_count = detections.size();
        for (std::size_t i = 0; i < detections.size(); ++i) {
            rec.detections[i] = detections[i];
        }

        /* Through the strand, so records are classified one at a time and in
         * arrival order -- which is what makes "drop the newest" leave a
         * coherent prefix of history. */
        asio::co_spawn(record_strand_, handleRecord(std::move(rec)), asio::detached);
    } catch (...) {
        /* post() allocates the handler, so it can throw on a memory-starved
         * BMC. This function is noexcept and is called from libbpf's
         * callback, so the only options are drop-and-count or terminate. */
        in_flight_.fetch_sub(1, std::memory_order_relaxed);
        countDrop("could not queue");
    }
}

asio::awaitable<void> DetectLoop::handleRecord(RawRecord rec) noexcept
{
    in_flight_.fetch_sub(1, std::memory_order_relaxed);

    // Per-item boundary, mirroring ActionLoop's handling of a failing
    // action: one bad event costs that event, not the daemon. Everything
    // below allocates (strings, vectors, json, make_unique), so on a
    // memory-constrained BMC a bad_alloc here is plausible -- and without
    // this it would be std::terminate, since this handler is noexcept.
    try {
        co_await process(rec);
    } catch (const std::exception& e) {
        std::cerr << "https_guard: dropped one event; classification threw: "
                  << e.what() << "\n";
    } catch (...) {
        std::cerr << "https_guard: dropped one event; classification threw"
                     " an unknown exception\n";
    }
}

asio::awaitable<void> DetectLoop::process(const RawRecord& rec)
{
    if (rec.size < sizeof(std::uint32_t)) {
        std::cerr << "https_guard: undersized event (" << rec.size << " bytes)\n";
        co_return;
    }

    std::uint32_t event_source = 0;
    std::memcpy(&event_source, rec.bytes, sizeof(event_source));

    const DispatchContext ctx{action_loop_, blocklist_ttl_, output_path_};

    /* Every submitted detection is evaluated concurrently now, rather than
     * stopping at the first verdict, so that a future I/O-bound detection can
     * suspend inside inspect() without holding up its siblings. List order
     * still decides the winner: results come back indexed by the hook's
     * original order, and the lowest-index non-nullopt verdict is the one
     * dispatched below -- the same outcome as walking the list one entry at a
     * time. See detections/DESIGN.md. */
    const auto executor = co_await asio::this_coro::executor;

    using Op = decltype(asio::co_spawn(
        executor, std::declval<asio::awaitable<void>>(), asio::deferred));

    std::vector<Op> ops;
    ops.reserve(rec.detection_count);

    std::vector<std::optional<Verdict>> verdicts(rec.detection_count);
    std::vector<EventMeta> metas(rec.detection_count);

    /* A plain function, called once per detection to produce the awaitable<void>
     * value co_spawn needs -- as opposed to handing co_spawn the lambda itself,
     * whose closure type would differ per capture and break the homogeneous
     * `Op` vector above. Mirrors ActionLoop::pushActions, which spawns
     * `action->execute_async()` (already a value) rather than a lambda. */
    auto inspectOne = [](const IDetection* detection, const RawRecord& r,
                        std::optional<Verdict>& verdict,
                        EventMeta& meta) -> asio::awaitable<void> {
        if (detection != nullptr) {
            verdict = detection->inspect(r.bytes, r.size, meta);
        }
        co_return;
    };

    for (std::size_t i = 0; i < rec.detection_count; ++i) {
        ops.push_back(asio::co_spawn(
            executor,
            inspectOne(rec.detections[i], rec, verdicts[i], metas[i]),
            asio::deferred));
    }

    auto [completion_order, exceptions] =
        co_await asio::experimental::make_parallel_group(std::move(ops))
            .async_wait(asio::experimental::wait_for_all(), asio::use_awaitable);
    (void)completion_order;

    /* Report every detection that threw, not just the first -- mirroring
     * ActionLoop::pushActions, which exists specifically so a failure is seen
     * "alongside its siblings rather than in isolation" (see its class
     * comment). Concurrent evaluation makes more than one throwing detection
     * for the same record possible, where the old sequential loop stopped at
     * the first. Same outcome as before either way: the record is dropped,
     * not the daemon. */
    std::size_t failed = 0;
    for (std::size_t i = 0; i < exceptions.size(); ++i) {
        if (!exceptions[i]) {
            continue;
        }
        ++failed;
        const IDetection* detection = rec.detections[i];
        try {
            std::rethrow_exception(exceptions[i]);
        } catch (const std::exception& e) {
            std::cerr << "https_guard: detection " << (i + 1) << " of "
                      << exceptions.size() << " ('"
                      << (detection ? detection->name() : "?") << "') threw: "
                      << e.what() << "\n";
        } catch (...) {
            std::cerr << "https_guard: detection " << (i + 1) << " of "
                      << exceptions.size() << " ('"
                      << (detection ? detection->name() : "?")
                      << "') threw an unknown exception\n";
        }
    }
    if (failed != 0) {
        if (failed > 1) {
            std::cerr << "https_guard: " << failed << " of " << exceptions.size()
                      << " detection(s) threw for this record; dropping it\n";
        }
        co_return;
    }

    for (std::size_t i = 0; i < rec.detection_count; ++i) {
        if (verdicts[i]) {
            const IDetection* detection = rec.detections[i];
            /* One trace line per record, from the envelope every source shares.
             * The per-source handlers this replaced each logged their own
             * detail line ("xdp event received: cipher_suites=3/3, sni=..."),
             * which no longer has a home now that no single class sees a whole
             * record. Source-specific detail still reaches the journal through
             * the verdict message; what is kept here is which detection claimed
             * the record, because that is what makes list order observable. */
            std::cout << "https_guard: event source=" << event_source
                      << " pid=" << metas[i].pid << " (" << metas[i].process
                      << ") claimed by '" << detection->name() << "' ("
                      << (i + 1) << " of " << rec.detection_count << "): "
                      << verdicts[i]->message_id << "\n";
            dispatchVerdict(metas[i], *verdicts[i], ctx);
            co_return;
        }
    }

    /* Nothing matched and nothing reported. A hook is expected to put an
     * always-matching TrafficObservedDetection last, so reaching here means
     * either a record too short for any of this hook's layouts, or a list built
     * without that terminal entry. */
    const auto n = undetected_.fetch_add(1, std::memory_order_relaxed) + 1;
    if (n == 1 || n % 1000 == 0) {
        std::cerr << "https_guard: no detection claimed a " << rec.size
                  << "-byte record; tried";
        for (std::size_t i = 0; i < rec.detection_count; ++i) {
            if (rec.detections[i] != nullptr) {
                std::cerr << " " << rec.detections[i]->name();
            }
        }
        std::cerr << " (" << n << " such record(s) so far). A hook's list should"
                     " end with an always-matching traffic-observed entry.\n";
    }
}


asio::awaitable<void> DetectLoop::sweepRates() noexcept
{
    // Same per-item boundary as event processing: a throw here must cost the
    // sweep, not the daemon. Mirrors handleRecord() catching around
    // co_await process(rec) -- ConnRateSweeper::sweep() is not itself
    // noexcept, for the same reason process() is not: this is the layer that
    // catches.
    if (rate_sweeper_) {
        /* Named, not a temporary bound to sweep()'s const& parameter: sweep()
         * is a coroutine, so an argument temporary here would be destroyed
         * once this call expression finishes evaluating -- which happens
         * before sweep()'s body actually runs, not after. process() below
         * binds its own DispatchContext the same way for the same reason. */
        const DispatchContext ctx{action_loop_, blocklist_ttl_, output_path_};
        try {
            co_await rate_sweeper_->sweep(ctx);
        } catch (const std::exception& e) {
            std::cerr << "https_guard: connection-rate sweep threw: " << e.what() << "\n";
        } catch (...) {
            std::cerr << "https_guard: connection-rate sweep threw an unknown exception\n";
        }
    }

    /* Re-arm only now that this sweep has actually finished -- the same
     * "serial: the next wait starts only now" guarantee the old synchronous
     * sweepRates(); armSweepTimer(); pair gave, expressed here as continuing
     * the coroutine rather than returning from a plain function call. */
    armSweepTimer();
}

void DetectLoop::armSweepTimer() noexcept
{
    if (stop_.load(std::memory_order_relaxed)) {
        return;
    }

    try {
        sweep_timer_.expires_after(kSweepInterval);
        sweep_timer_.async_wait([this](const boost::system::error_code& ec) noexcept {
            if (ec || stop_.load(std::memory_order_relaxed)) {
                return;
            }
            try {
                /* Detached: sweepRates() re-arms the timer itself once it
                 * completes, which is what keeps sweeps serial. */
                asio::co_spawn(io_context_, sweepRates(), asio::detached);
            } catch (...) {
                /* co_spawn() allocates the coroutine frame and can throw on a
                 * memory-starved BMC. This handler is noexcept, and nothing
                 * ran to re-arm the timer on this path, so do it here --
                 * skipping one interval beats losing rate detection for good. */
                std::cerr << "https_guard: could not schedule the connection-rate "
                             "sweep; skipping this interval\n";
                armSweepTimer();
            }
        });
    } catch (...) {
        /* Losing the timer loses rate detection silently, which is the exact
         * failure mode this feature is supposed to report on. */
        std::cerr << "https_guard: could not arm the connection-rate sweep "
                     "timer; rate detection is now inactive\n";
    }
}

void DetectLoop::enableRateSweeps(int conn_rate_map_fd,
                                  ConnRateSweeper::Thresholds thresholds) noexcept
{
    rate_sweeper_ = std::make_unique<ConnRateSweeper>(conn_rate_map_fd, thresholds);
    if (!rate_sweeper_->enabled()) {
        rate_sweeper_.reset();   // keep the hot path free of a disabled sweeper
        return;
    }

    /* Arm from inside the loop rather than here: the worker threads are
     * already running, and posting is also what publishes rate_sweeper_ to
     * them. Not on the record strand -- the whole point is that the sweep
     * does not queue behind records. */
    try {
        asio::post(io_context_, [this] { armSweepTimer(); });
    } catch (...) {
        std::cerr << "https_guard: could not start the connection-rate sweep; "
                     "rate detection is inactive\n";
        rate_sweeper_.reset();
    }
}

}  // namespace https_guard

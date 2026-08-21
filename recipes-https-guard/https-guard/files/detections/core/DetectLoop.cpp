#include <cstring>
#include <exception>
#include <iostream>
#include <optional>
#include <utility>

#include <boost/asio/post.hpp>

#include "DetectLoop.hpp"
#include "hg_event.hpp"
#include "Verdict.hpp"
#include "ITlsTrafficInfo.hpp"
#include "tls_version.hpp"
#include "redfish_event_message.hpp"
#include "log/LogAction.hpp"
#include "blocklist/BlocklistAction.hpp"
#include "tcp/BlockTcpAction.hpp"

namespace asio = boost::asio;

namespace https_guard {

DetectLoop::DetectLoop(ActionLoop& action_loop,
                       const std::vector<std::unique_ptr<IHookModule>>& hooks,
                       DetectorRegistry detectors,
                       std::chrono::seconds blocklist_ttl,
                       std::string output_path) noexcept
    : action_loop_(action_loop)
    , hooks_(hooks)
    , detectors_(std::move(detectors))
    , blocklist_ttl_(blocklist_ttl)
    , output_path_(std::move(output_path))
    , io_context_()
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
    const auto abandoned = in_flight_.load(std::memory_order_relaxed);
    const auto dropped   = dropped_.load(std::memory_order_relaxed);
    if (abandoned != 0 || dropped != 0) {
        std::cerr << "https_guard: DetectLoop stopped; " << abandoned
                  << " event(s) abandoned at shutdown, " << dropped
                  << " dropped earlier due to a full queue\n";
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

void DetectLoop::submit(const void* data, std::size_t size) noexcept
{
    if (data == nullptr || size == 0 || stop_.load(std::memory_order_relaxed)) {
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

        /* Through the strand, so records are classified one at a time and in
         * arrival order -- which is what makes "drop the newest" leave a
         * coherent prefix of history. */
        asio::post(record_strand_,
                   [this, rec = std::move(rec)]() noexcept { handleRecord(rec); });
    } catch (...) {
        /* post() allocates the handler, so it can throw on a memory-starved
         * BMC. This function is noexcept and is called from libbpf's
         * callback, so the only options are drop-and-count or terminate. */
        in_flight_.fetch_sub(1, std::memory_order_relaxed);
        countDrop("could not queue");
    }
}

void DetectLoop::handleRecord(const RawRecord& rec) noexcept
{
    in_flight_.fetch_sub(1, std::memory_order_relaxed);

    // Per-item boundary, mirroring ActionLoop's handling of a failing
    // action: one bad event costs that event, not the daemon. Everything
    // below allocates (strings, vectors, json, make_unique), so on a
    // memory-constrained BMC a bad_alloc here is plausible -- and without
    // this it would be std::terminate, since this handler is noexcept.
    try {
        process(rec);
    } catch (const std::exception& e) {
        std::cerr << "https_guard: dropped one event; classification threw: "
                  << e.what() << "\n";
    } catch (...) {
        std::cerr << "https_guard: dropped one event; classification threw"
                     " an unknown exception\n";
    }
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
            sweepRates();
            armSweepTimer();   /* serial: the next wait starts only now */
        });
    } catch (...) {
        /* Losing the timer loses rate detection silently, which is the exact
         * failure mode this feature is supposed to report on. */
        std::cerr << "https_guard: could not arm the connection-rate sweep "
                     "timer; rate detection is now inactive\n";
    }
}

void DetectLoop::process(const RawRecord& rec)
{
    if (rec.size < sizeof(uint32_t)) {
        std::cerr << "https_guard: undersized event (" << rec.size << " bytes)\n";
        return;
    }

    const auto event_source =
        static_cast<hg_event_source>(*reinterpret_cast<const uint32_t*>(rec.bytes));

    const IHookModule* owning_hook = nullptr;
    for (const auto& hook : hooks_) {
        if (hook->eventSource() == event_source) {
            owning_hook = hook.get();
            break;
        }
    }

    if (!owning_hook) {
        std::cerr << "https_guard: unknown event_source=" << event_source
                  << ", size=" << rec.size << ", skipping\n";
        return;
    }

    /* Owning pointer, not a value: the concrete type carries this hook's
     * own data behind capability interfaces, and copying it as an hg_event
     * would slice that away. */
    const std::unique_ptr<hg_event> parsed = owning_hook->parseEvent(rec.bytes, rec.size);
    if (!parsed) {
        return;
    }

    classifyAndDispatch(*parsed, event_source);
}

void DetectLoop::sweepRates() noexcept
{
    if (!rate_sweeper_) {
        return;
    }

    /* Same per-item boundary as event processing: a throw here must cost the
     * sweep, not the daemon. */
    try {
        for (const auto& evt : rate_sweeper_->sweep()) {
            classifyAndDispatch(*evt, HG_SOURCE_CONN_RATE);
        }
    } catch (const std::exception& e) {
        std::cerr << "https_guard: connection-rate sweep threw: " << e.what() << "\n";
    } catch (...) {
        std::cerr << "https_guard: connection-rate sweep threw an unknown exception\n";
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

void DetectLoop::classifyAndDispatch(const hg_event& evt, hg_event_source source)
{
    /* Only for the human-readable fallback and diagnostics below. Absent for
     * event sources that don't describe TLS traffic at all, such as
     * certificate access -- which is the point of asking rather than
     * assuming every event has a TLS version. */
    const auto* tls_info = dynamic_cast<const ITlsTrafficInfo*>(&evt);
    const std::string tls_desc =
        tls_info != nullptr ? TlsVersion(tls_info->tlsVersion()).toString() : "n/a";

    /* Run this source's detectors in order, first match wins. No match means
     * normal traffic. */
    Verdict verdict;
    bool matched = false;
    if (auto it = detectors_.find(source); it != detectors_.end()) {
        for (const auto& detector : it->second) {
            if (auto v = detector->evaluate(evt)) {
                verdict = std::move(*v);
                matched = true;
                break;
            }
        }
    }

    if (!matched) {
        verdict.severity   = "OK";
        verdict.message_id = "OemSecurityEvent.1.0.HttpsTrafficObserved";
        verdict.message    = "HTTPS traffic observed from process '" + evt.process +
                             "' (PID " + std::to_string(evt.pid) +
                             "), TLS version: " + tls_desc;
    }

    if (verdict.actionable)
    {
        /* Only now is the connection tuple worth the cost of resolving --
         * this is the first point that actually needs it, and most events
         * never get here. For XDP the addresses came from the packet and
         * this is already satisfied. */
        /* Ask the hook to resolve the tuple if it supplied a resolver, then
         * gate on whether we actually have an address -- not on whether
         * resolution ran.
         *
         * Conflating those two silently disabled enforcement for every event
         * that already knows its own address: XDP reads it from the packet
         * headers and the rate sweeper sets it directly, so neither carries a
         * resolver, so ensurePeerResolved() returned false and the whole
         * actionable branch was skipped. It stayed hidden because the only
         * enforcement path exercised live was a uprobe payload anomaly, which
         * does have a resolver, and the one actionable XDP rule needs a
         * legacy-TLS client that was never tested end to end. */
        evt.ensurePeerResolved();
        if (evt.remote_ip_v4 != 0)
        {
            /* Tearing down a connection only makes sense when we know which
             * connection. A rate violation is attributed to an address, not
             * a socket -- it has no local endpoint and no ports -- so asking
             * netlink to destroy a zero tuple just produced a guaranteed
             * -ENOENT and a misleading "SOCK_DESTROY failed" line. The
             * blocklist below is the meaningful response for that case. */
            const bool have_full_tuple = evt.local_ip_v4 != 0 &&
                                          evt.local_port != 0 &&
                                          evt.remote_port != 0;
            if (have_full_tuple) {
                action_loop_.pushAction(
                    std::make_unique<BlockTcpAction>(
                    evt.local_ip_v4,
                    evt.remote_ip_v4,
                    evt.local_port,
                    evt.remote_port,
                    verdict.message));
            }

            action_loop_.pushAction(
                std::make_unique<BlocklistAddAction>(
                evt.remote_ip_v4,   /* block the peer, never our own address */
                blocklist_ttl_,
                verdict.message));
        }
        else
        {
            std::cerr << "https_guard: PID " << evt.pid
                      << " (" << evt.process << "), TLS version: "
                      << tls_desc
                      << " — no connection could be attributed, declining to enforce\n";
        }
    }

    RedfishEventMessage event_msg(
        evt, verdict.message_id, verdict.message, verdict.severity);
    action_loop_.pushAction(
        std::make_unique<LogAction>(event_msg.format(), output_path_));
    std::cerr << "https_guard: pushing LogAction for severity=" << verdict.severity << "\n";
}

}  // namespace https_guard

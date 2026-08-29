#include <cstring>
#include <iostream>
#include <optional>
#include <utility>

#include "DetectLoop.hpp"
#include "hg_event.hpp"
#include "Verdict.hpp"
#include "ITlsTrafficInfo.hpp"
#include "tls_version.hpp"
#include "redfish_event_message.hpp"
#include "log/LogAction.hpp"
#include "blocklist/BlocklistAction.hpp"
#include "tcp/BlockTcpAction.hpp"

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
{
    try {
        worker_ = std::thread([this] { run(); });
    } catch (...) {
        // Without a worker nothing would ever be classified, so make the
        // failure loud rather than silently accepting events into a queue
        // that is never drained.
        stop_.store(true, std::memory_order_relaxed);
        std::cerr << "https_guard: FATAL: could not start DetectLoop worker; "
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
        if (worker_.joinable()) {
            worker_.join();
        }
        return;
    }

    std::size_t abandoned = 0;
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        // Abandon rather than drain: draining could delay shutdown for as
        // long as the queue is deep, and a security daemon being slow to
        // stop is worse than losing the tail of its backlog. Say how much
        // was lost rather than dropping it quietly.
        abandoned = queue_.size();
        queue_.clear();
    }
    cv_.notify_all();

    if (worker_.joinable()) {
        worker_.join();
    }

    const auto dropped = dropped_.load(std::memory_order_relaxed);
    if (abandoned != 0 || dropped != 0) {
        std::cerr << "https_guard: DetectLoop stopped; " << abandoned
                  << " event(s) abandoned at shutdown, " << dropped
                  << " dropped earlier due to a full queue\n";
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

    {
        const std::lock_guard<std::mutex> lock(mutex_);
        if (queue_.size() >= kMaxQueueDepth) {
            // Drop the newest, keeping a coherent prefix of history. Never
            // block here: blocking would stall the poll thread and let the
            // ring buffer overflow, which is the problem this class exists
            // to avoid.
            const auto n = dropped_.fetch_add(1, std::memory_order_relaxed) + 1;
            if (n == 1 || n % 1000 == 0) {
                std::cerr << "https_guard: DetectLoop queue full (" << kMaxQueueDepth
                          << "); dropped " << n << " event(s) so far\n";
            }
            return;
        }

        queue_.emplace_back();
        RawRecord& rec = queue_.back();
        rec.size = size;
        std::memcpy(rec.bytes, data, size);
    }
    cv_.notify_one();
}

void DetectLoop::run() noexcept
{
    for (;;) {
        RawRecord rec;
        {
            std::unique_lock<std::mutex> lock(mutex_);
            cv_.wait(lock, [this] {
                return !queue_.empty() || stop_.load(std::memory_order_relaxed);
            });
            if (queue_.empty()) {
                if (stop_.load(std::memory_order_relaxed)) {
                    return;
                }
                continue;
            }
            rec = queue_.front();
            queue_.pop_front();
        }

        // Per-item boundary, mirroring ActionLoop's handling of a failing
        // action: one bad event costs that event, not the daemon. Everything
        // below allocates (strings, vectors, json, make_unique), so on a
        // memory-constrained BMC a bad_alloc here is plausible -- and
        // without this it would be std::terminate, since the callers are
        // noexcept.
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
    const hg_event& evt = *parsed;

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
    if (auto it = detectors_.find(event_source); it != detectors_.end()) {
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
        if (evt.ensurePeerResolved() && evt.remote_ip_v4 != 0)
        {
            action_loop_.pushAction(
                std::make_unique<BlockTcpAction>(
                evt.local_ip_v4,
                evt.remote_ip_v4,
                evt.local_port,
                evt.remote_port,
                verdict.message));

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

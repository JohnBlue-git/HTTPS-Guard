#include <arpa/inet.h>
#include <chrono>
#include <cstring>
#include <ctime>
#include <optional>
#include <string>
#include <iostream>

#include <bpf/bpf.h>

#include "ConnRateSweeper.hpp"
#include "conn_rate.bpf.h"
#include "ConnRateDetector.hpp"
#include "SlowlorisDetector.hpp"
#include "RenegotiationDetector.hpp"

namespace https_guard {

namespace {

/* Synthesised events have no BPF header to take a timestamp from, and a zero
 * one is not harmless: RedfishEventMessage builds both "Id" and "EventId" out
 * of it, so every rate, Slowloris and renegotiation event was emitted as
 * Id "0" / EventId "0-0" -- indistinguishable from each other in the event
 * log. The ring-buffer path had exactly this bug once and it was fixed there
 * only.
 *
 * CLOCK_MONOTONIC deliberately, because that is what bpf_ktime_get_ns()
 * reads: the two paths' ids then share one clock domain and sort against
 * each other. Wall-clock here would order these events randomly among the
 * parsed ones. */
std::uint64_t monotonic_now_ns() noexcept
{
    struct timespec ts = {};
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        return 0;
    }
    return static_cast<std::uint64_t>(ts.tv_sec) * 1000000000ULL +
           static_cast<std::uint64_t>(ts.tv_nsec);
}

}  // namespace

ConnRateSweeper::ConnRateSweeper(int map_fd, Thresholds thresholds) noexcept
    : map_fd_(map_fd)
    , thresholds_(thresholds)
{
    if (map_fd_ < 0) {
        std::cerr << "https_guard: per-source counter map unavailable;"
                     " rate, Slowloris and renegotiation detection disabled\n";
        return;
    }
    if (!enabled()) {
        std::cout << "https_guard: rate, Slowloris and renegotiation detection"
                     " disabled (no thresholds configured)\n";
        return;
    }
    std::cout << "https_guard: per-source detection active ("
              << "rate " << thresholds_.connection_rate
              << "/" << HTTPS_GUARD_CONN_RATE_WINDOW_SEC << "s, "
              << "open-conns " << thresholds_.open_conns << ", "
              << "handshakes " << thresholds_.handshakes
              << "/" << HTTPS_GUARD_CONN_RATE_WINDOW_SEC << "s; 0 = rule off)\n";
}

boost::asio::awaitable<void> ConnRateSweeper::sweep(const DispatchContext& ctx)
{
    if (!enabled()) {
        co_return;
    }

    /* One rule instance per family, reused across sweeps and sources -- same
     * as the per-source handlers this replaced (`static const XDetector rule`
     * in each), just inlined: each rule's `evaluate()` is stateless, so there
     * is nothing to gain from a fresh instance per event. */
    static const ConnRateDetector      kConnRateRule;
    static const SlowlorisDetector     kSlowlorisRule;
    static const RenegotiationDetector kRenegotiationRule;

    /* Iterate with get_next_key rather than holding any lock: entries may be
     * inserted or LRU-evicted underneath this walk, which is fine -- a missed
     * entry is picked up on the next sweep, and a vanished one was evicted
     * precisely because it stopped being active. */
    std::uint32_t key = 0;
    std::uint32_t next_key = 0;
    bool have_key = bpf_map_get_next_key(map_fd_, nullptr, &next_key) == 0;

    decltype(reported_rate_)  seen_rate;
    decltype(reported_reneg_) seen_reneg;
    decltype(reported_open_)  seen_open;

    /* Observability, not debug scaffolding: without this the only way to
     * know what ordinary traffic looks like is to guess a threshold and
     * watch for lockouts. Reported at most every 10s. */
    std::size_t   entries_seen = 0;
    std::uint32_t max_syn = 0, max_hello = 0;
    std::int32_t  max_open = 0;

    /* One reading per sweep: events synthesised by the same walk share it,
     * which is accurate -- they were all observed by that walk. */
    const std::uint64_t now_ns = monotonic_now_ns();

    auto describe = [](std::uint32_t ip_net_order) {
        char buf[INET_ADDRSTRLEN] = {};
        return inet_ntop(AF_INET, &ip_net_order, buf, sizeof(buf)) != nullptr
                   ? std::string(buf) : std::string();
    };

    while (have_key) {
        key = next_key;

        struct hg_conn_rate entry = {};
        if (bpf_map_lookup_elem(map_fd_, &key, &entry) == 0) {
            ++entries_seen;
            if (entry.syn_count   > max_syn)   max_syn   = entry.syn_count;
            if (entry.hello_count > max_hello) max_hello = entry.hello_count;
            if (entry.open_conns  > max_open)  max_open  = entry.open_conns;

            /* --- connection rate (windowed) --- */
            if (thresholds_.connection_rate > 0 &&
                entry.syn_count >= thresholds_.connection_rate) {
                seen_rate[key] = entry.window_start_ns;
                const auto prev = reported_rate_.find(key);
                if (prev == reported_rate_.end() || prev->second != entry.window_start_ns) {
                    ConnRateEvent evt;
                    evt.meta.remote_ip_v4 = key;
                    evt.meta.source_ip    = describe(key);
                    evt.meta.timestamp_ns = now_ns;
                    evt.attempts_in_window = entry.syn_count;
                    evt.window_seconds     = HTTPS_GUARD_CONN_RATE_WINDOW_SEC;
                    evt.threshold          = thresholds_.connection_rate;
                    if (auto v = kConnRateRule.evaluate(evt)) {
                        dispatchVerdict(evt.meta, *v, ctx);
                    }
                }
            }

            /* --- renegotiation storm (windowed) --- */
            if (thresholds_.handshakes > 0 &&
                entry.hello_count >= thresholds_.handshakes) {
                seen_reneg[key] = entry.window_start_ns;
                const auto prev = reported_reneg_.find(key);
                if (prev == reported_reneg_.end() || prev->second != entry.window_start_ns) {
                    RenegotiationEvent evt;
                    evt.meta.remote_ip_v4 = key;
                    evt.meta.source_ip    = describe(key);
                    evt.meta.timestamp_ns = now_ns;
                    evt.handshakes_in_window = entry.hello_count;
                    evt.window_seconds       = HTTPS_GUARD_CONN_RATE_WINDOW_SEC;
                    evt.threshold            = thresholds_.handshakes;
                    if (auto v = kRenegotiationRule.evaluate(evt)) {
                        dispatchVerdict(evt.meta, *v, ctx);
                    }
                }
            }

            /* --- Slowloris (a level, not a window) ---
             * Re-report only when the level climbs. A source sitting on its
             * connections is still a problem, but logging it every sweep
             * would bury everything else. */
            if (thresholds_.open_conns > 0 && entry.open_conns > 0 &&
                static_cast<std::uint32_t>(entry.open_conns) >= thresholds_.open_conns) {
                const auto level = static_cast<std::uint32_t>(entry.open_conns);
                seen_open[key] = level;
                const auto prev = reported_open_.find(key);
                if (prev == reported_open_.end() || level > prev->second) {
                    SlowlorisEvent evt;
                    evt.meta.remote_ip_v4 = key;
                    evt.meta.source_ip    = describe(key);
                    evt.meta.timestamp_ns = now_ns;
                    evt.open_connections  = level;
                    evt.threshold         = thresholds_.open_conns;
                    if (auto v = kSlowlorisRule.evaluate(evt)) {
                        dispatchVerdict(evt.meta, *v, ctx);
                    }
                }
            }
        }

        have_key = bpf_map_get_next_key(map_fd_, &key, &next_key) == 0;
    }

    if (entries_seen > 0) {
        const auto now = std::chrono::steady_clock::now();
        if (now - last_report_ >= std::chrono::seconds(10)) {
            last_report_ = now;
            std::cout << "https_guard: per-source counters: " << entries_seen
                      << " source(s); busiest " << max_syn << " attempts, "
                      << max_hello << " handshakes, " << max_open
                      << " connections held open\n";
        }
    }

    /* Drop memory for sources no longer over any limit, so this cannot grow
     * without bound while the BPF map itself is LRU-bounded. */
    reported_rate_  = std::move(seen_rate);
    reported_reneg_ = std::move(seen_reneg);
    reported_open_  = std::move(seen_open);

    co_return;
}

}  // namespace https_guard

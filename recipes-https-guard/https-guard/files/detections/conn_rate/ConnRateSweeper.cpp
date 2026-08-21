#include <arpa/inet.h>
#include <chrono>
#include <cstring>
#include <string>
#include <iostream>

#include <bpf/bpf.h>

#include "ConnRateSweeper.hpp"
#include "conn_rate.bpf.h"

namespace https_guard {

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

std::vector<std::unique_ptr<hg_event>> ConnRateSweeper::sweep() noexcept
{
    std::vector<std::unique_ptr<hg_event>> flagged;
    if (!enabled()) {
        return flagged;
    }

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
                    auto evt = std::make_unique<ConnRateEvent>();
                    evt->remote_ip_v4   = key;
                    evt->source_ip      = describe(key);
                    evt->attempt_count  = entry.syn_count;
                    evt->window_seconds = HTTPS_GUARD_CONN_RATE_WINDOW_SEC;
                    evt->rate_threshold = thresholds_.connection_rate;
                    flagged.push_back(std::move(evt));
                }
            }

            /* --- renegotiation storm (windowed) --- */
            if (thresholds_.handshakes > 0 &&
                entry.hello_count >= thresholds_.handshakes) {
                seen_reneg[key] = entry.window_start_ns;
                const auto prev = reported_reneg_.find(key);
                if (prev == reported_reneg_.end() || prev->second != entry.window_start_ns) {
                    auto evt = std::make_unique<RenegotiationEvent>();
                    evt->remote_ip_v4   = key;
                    evt->source_ip      = describe(key);
                    evt->handshake_count = entry.hello_count;
                    evt->window_seconds  = HTTPS_GUARD_CONN_RATE_WINDOW_SEC;
                    evt->reneg_threshold = thresholds_.handshakes;
                    flagged.push_back(std::move(evt));
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
                    auto evt = std::make_unique<SlowlorisEvent>();
                    evt->remote_ip_v4        = key;
                    evt->source_ip           = describe(key);
                    evt->open_connections    = level;
                    evt->slowloris_threshold = thresholds_.open_conns;
                    flagged.push_back(std::move(evt));
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
    return flagged;
}

}  // namespace https_guard

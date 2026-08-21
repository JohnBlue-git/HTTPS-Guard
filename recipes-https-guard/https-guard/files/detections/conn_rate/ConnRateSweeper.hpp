#pragma once

#include <chrono>
#include <cstdint>
#include <memory>
#include <unordered_map>
#include <vector>

#include "ConnRateEvent.hpp"
#include "RenegotiationEvent.hpp"
#include "SlowlorisEvent.hpp"

namespace https_guard {

/**
 * Reads the BPF connection-rate counters and turns any source over the
 * threshold into an event for the normal classification path.
 *
 * Exists because the BPF side deliberately only counts (see
 * `programs/xdp_tls/ebpf/conn_rate.bpf.h`): there is no ring-buffer record
 * for a rate violation, so the daemon manufactures one. That keeps the
 * decision in userspace where a mistuned threshold cannot drop traffic at
 * line rate, and avoids needing a second event source from a hook that
 * already has one.
 */
class ConnRateSweeper {
public:
    /**
     * threshold == 0 disables sweeping entirely. That is the value used when
     * nothing is configured, so the feature cannot start enforcing against
     * real traffic on the strength of a default nobody chose.
     */
    /** Per-rule limits. Any of them 0 disables just that rule. */
    struct Thresholds {
        std::uint32_t connection_rate = 0;
        std::uint32_t open_conns      = 0;   /* Slowloris */
        std::uint32_t handshakes      = 0;   /* renegotiation storm */
    };

    ConnRateSweeper(int map_fd, Thresholds thresholds) noexcept;

    /**
     * Returns one event per source currently over the threshold.
     *
     * Reports each window at most once per source: a flood produces a
     * sustained overage, and re-emitting every sweep would bury the log and
     * re-run enforcement against an address already blocklisted.
     */
    /**
     * One event per rule per source currently over its limit. Returned as
     * the common base because the three rules produce different concrete
     * types, each carrying only the capability its own detector reads.
     */
    std::vector<std::unique_ptr<hg_event>> sweep() noexcept;

    bool enabled() const noexcept
    {
        return map_fd_ >= 0 && (thresholds_.connection_rate > 0 ||
                                thresholds_.open_conns > 0 ||
                                thresholds_.handshakes > 0);
    }

private:
    int        map_fd_;
    Thresholds thresholds_;

    /* source IP -> window_start_ns already reported, per rule. Kept here
     * rather than in the BPF map so the sweep needs no write access to it,
     * and so a counter reset in the kernel cannot be mistaken for a fresh
     * violation.
     *
     * Slowloris is tracked separately and by level rather than window: it is
     * not windowed, so "already reported this window" is meaningless for it.
     * Re-reported only when the count climbs, so a source sitting on its
     * connections is not logged every sweep. */
    std::unordered_map<std::uint32_t, std::uint64_t> reported_rate_;
    std::unordered_map<std::uint32_t, std::uint64_t> reported_reneg_;
    std::unordered_map<std::uint32_t, std::uint32_t> reported_open_;

    /* Throttles the periodic "what is being tracked" report. */
    std::chrono::steady_clock::time_point last_report_{};
};

}  // namespace https_guard

#pragma once

#include <chrono>

#include <boost/asio/awaitable.hpp>

namespace https_guard {

/**
 * Safety net for ssl_uprobe's kernel-side session-binding maps
 * (programs/ssl_uprobe/ebpf/ssl_uprobe.bpf.h): deletes any entry older than
 * kMaxAge from both the per-thread and per-session LRU_HASH maps.
 *
 * SSL_free already clears its session's entry immediately, and LRU_HASH
 * bounds both maps under insert pressure regardless of this -- this exists
 * for the gap between those two: a binding whose owning session or thread
 * never revisits port 443 (a non-TLS process, a caller that never reaches
 * SSL_free, a crash) would otherwise sit until unrelated map turnover
 * happens to evict it.
 *
 * Same shape as ConnRateSweeper: a timer-driven walk via
 * bpf_map_get_next_key()/bpf_map_lookup_elem(), reading kernel state
 * directly rather than through a ring-buffer event. Unlike ConnRateSweeper,
 * this produces no verdict and touches no ActionLoop -- a stale kernel-map
 * entry is memory hygiene, not something to alert or enforce on -- so
 * sweep() takes no DispatchContext.
 */
class SessionTupleSweeper {
public:
    SessionTupleSweeper(int thread_map_fd, int session_map_fd) noexcept;

    /** Deletes every entry older than kMaxAge in either map. */
    boost::asio::awaitable<void> sweep();

    bool enabled() const noexcept
    {
        return thread_map_fd_ >= 0 && session_map_fd_ >= 0;
    }

private:
    /* The session map's timestamp is set once, at bind time, and never
     * refreshed by later SSL_write/SSL_read hits (see fill_resolved_conn()
     * in ssl_uprobe.bpf.h) -- so kMaxAge also bounds how long a session may
     * sit idle before its own binding is reclaimed out from under it,
     * degrading that one event to the /proc fallback exactly as if this
     * mechanism did not exist (safe, per LIMITATIONS.md's "under-binds,
     * never mis-binds"). 5 minutes is well past bmcweb's own idle-connection
     * lifetime in practice, so in effect this is a backstop for a binding
     * whose session never reaches SSL_free at all, not a realistic budget
     * being imposed on a legitimately idle live session. */
    static constexpr auto kMaxAge = std::chrono::minutes(5);

    int thread_map_fd_;
    int session_map_fd_;
};

}  // namespace https_guard

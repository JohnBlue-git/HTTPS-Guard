#include <chrono>
#include <cstdint>
#include <ctime>

#include <bpf/bpf.h>

#include "SessionTupleSweeper.hpp"
#include "ssl_uprobe_session_map.h"

namespace https_guard {

namespace {

/* Same clock bpf_ktime_get_ns() reads (CLOCK_MONOTONIC, not wall time) -- see
 * ConnRateSweeper.cpp's identical helper for why. Kept as its own copy rather
 * than shared: six lines private to this translation unit, matching how
 * ConnRateSweeper already keeps its copy unshared. */
std::uint64_t monotonic_now_ns() noexcept
{
    struct timespec ts = {};
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
    {
        return 0;
    }
    return static_cast<std::uint64_t>(ts.tv_sec) * 1000000000ULL +
           static_cast<std::uint64_t>(ts.tv_nsec);
}

/* Walks one map, deleting every entry older than max_age_ns. Shared by both
 * maps: same key type (__u64 -- a pid_tgid or an SSL* cast to an integer),
 * same value type (hg_bound_tuple), same staleness field. They differ only
 * in which kernel-side hook populates them.
 *
 * Iterates the same way ConnRateSweeper does -- get_next_key() rather than
 * holding any lock, so an entry inserted or LRU-evicted underneath this walk
 * is fine: a missed entry is picked up next sweep, and a vanished one was
 * evicted precisely because it stopped being active.
 */
void sweepOneMap(int map_fd, std::uint64_t now_ns, std::uint64_t max_age_ns) noexcept
{
    if (map_fd < 0)
    {
        return;
    }

    std::uint64_t key = 0, next_key = 0;
    bool have_key = bpf_map_get_next_key(map_fd, nullptr, &next_key) == 0;

    while (have_key)
    {
        key = next_key;

        /* Fetch the next key BEFORE possibly deleting this one. Deleting the
         * current key first and then asking the kernel for "the key after
         * it" is undefined for a hash-backed map: a cursor key that no
         * longer exists restarts the walk from the beginning instead of
         * resuming, so this order is not a style choice. */
        have_key = bpf_map_get_next_key(map_fd, &key, &next_key) == 0;

        struct hg_bound_tuple entry = {};
        if (bpf_map_lookup_elem(map_fd, &key, &entry) != 0)
        {
            continue;   /* raced with a delete/eviction elsewhere; nothing to do */
        }

        if (now_ns - entry.timestamp_ns > max_age_ns)
        {
            bpf_map_delete_elem(map_fd, &key);
        }
    }
}

}  // namespace

SessionTupleSweeper::SessionTupleSweeper(int thread_map_fd, int session_map_fd) noexcept
    : thread_map_fd_(thread_map_fd)
    , session_map_fd_(session_map_fd)
{
}

boost::asio::awaitable<void> SessionTupleSweeper::sweep()
{
    if (!enabled())
    {
        co_return;
    }

    const std::uint64_t now_ns = monotonic_now_ns();
    const std::uint64_t max_age_ns = static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::nanoseconds>(kMaxAge).count());

    sweepOneMap(thread_map_fd_, now_ns, max_age_ns);
    sweepOneMap(session_map_fd_, now_ns, max_age_ns);

    co_return;
}

}  // namespace https_guard

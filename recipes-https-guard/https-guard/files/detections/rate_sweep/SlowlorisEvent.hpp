#pragma once

#include <cstdint>

#include "event_meta.hpp"

namespace https_guard {

/**
 * Synthesised by ConnRateSweeper from the per-source held-open level.
 *
 * Satisfies SlowlorisEventLike only. `open_connections` is a *level*, not a
 * windowed rate: the counter behind it survives the window roll, because an
 * attacker who opens connections and then goes quiet would otherwise look idle.
 */
struct SlowlorisEvent {
    EventMeta meta;

    std::uint32_t open_connections = 0;
    std::uint32_t threshold        = 0;

    SlowlorisEvent() = default;

    SlowlorisEvent(const EventMeta& meta_in, std::uint32_t open_connections_in,
                   std::uint32_t threshold_in)
        : meta(meta_in)
        , open_connections(open_connections_in)
        , threshold(threshold_in)
    {
    }
};

}  // namespace https_guard

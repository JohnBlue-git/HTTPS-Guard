#pragma once

#include <cstdint>

#include "event_meta.hpp"

namespace https_guard {

/**
 * Synthesised by ConnRateSweeper from the per-source handshake counter.
 *
 * Satisfies RenegotiationEventLike only. It and ConnRateEvent both carry a
 * windowed count, and keeping them as separate types with separate concepts is
 * what makes "one rule reading another's counter" a compile error rather than
 * something a test has to catch.
 */
struct RenegotiationEvent {
    EventMeta meta;

    std::uint32_t handshakes_in_window = 0;
    std::uint32_t window_seconds       = 0;
    std::uint32_t threshold            = 0;

    RenegotiationEvent() = default;

    RenegotiationEvent(const EventMeta& meta_in, std::uint32_t handshakes_in_window_in,
                        std::uint32_t window_seconds_in, std::uint32_t threshold_in)
        : meta(meta_in)
        , handshakes_in_window(handshakes_in_window_in)
        , window_seconds(window_seconds_in)
        , threshold(threshold_in)
    {
    }
};

}  // namespace https_guard

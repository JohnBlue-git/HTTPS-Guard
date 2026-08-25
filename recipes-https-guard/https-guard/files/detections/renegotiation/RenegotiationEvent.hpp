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
};

}  // namespace https_guard

#pragma once

#include <cstdint>

#include "event_meta.hpp"

namespace https_guard {

/**
 * A connection-rate observation, synthesised by ConnRateSweeper from the BPF
 * counter map.
 *
 * Satisfies ConnectionRateEvent and nothing else: a rate observation has no TLS
 * version, no payload and no ClientHello, because it is a count over a window
 * attributed to an address. Under the old single-base design it inherited a
 * type that claimed all of those and answered 0 to each.
 */
struct ConnRateEvent {
    EventMeta meta;

    std::uint32_t attempts_in_window = 0;
    std::uint32_t window_seconds     = 0;
    std::uint32_t threshold          = 0;

    ConnRateEvent() = default;

    ConnRateEvent(const EventMeta& meta_in, std::uint32_t attempts_in_window_in,
                  std::uint32_t window_seconds_in, std::uint32_t threshold_in)
        : meta(meta_in)
        , attempts_in_window(attempts_in_window_in)
        , window_seconds(window_seconds_in)
        , threshold(threshold_in)
    {
    }
};

}  // namespace https_guard

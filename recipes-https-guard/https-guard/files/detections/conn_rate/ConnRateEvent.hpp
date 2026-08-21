#pragma once

#include <cstdint>

#include "hg_event.hpp"
#include "IConnectionRateInfo.hpp"

namespace https_guard {

/**
 * A connection-rate observation, synthesised by ConnRateSweeper from the BPF
 * counter map.
 *
 * Carries no TLS version, payload or ClientHello, because a rate observation
 * has none of those — it is a count over a window, attributed to an address.
 * The old single-event design would have had to claim all of them.
 */
class ConnRateEvent final : public hg_event, public IConnectionRateInfo {
public:
    std::uint32_t attempt_count  = 0;
    std::uint32_t window_seconds = 0;
    std::uint32_t rate_threshold = 0;

    std::uint32_t attemptCount() const noexcept override { return attempt_count; }
    std::uint32_t windowSeconds() const noexcept override { return window_seconds; }
    std::uint32_t threshold() const noexcept override { return rate_threshold; }
};

}  // namespace https_guard

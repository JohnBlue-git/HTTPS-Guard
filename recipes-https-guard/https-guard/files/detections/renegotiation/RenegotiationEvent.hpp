#pragma once

#include <cstdint>

#include "hg_event.hpp"
#include "IRenegotiationInfo.hpp"

namespace https_guard {

/** Synthesised by ConnRateSweeper from the per-source handshake counter. */
class RenegotiationEvent final : public hg_event, public IRenegotiationInfo {
public:
    std::uint32_t handshake_count = 0;
    std::uint32_t window_seconds  = 0;
    std::uint32_t reneg_threshold = 0;

    std::uint32_t handshakeCount() const noexcept override { return handshake_count; }
    std::uint32_t windowSeconds() const noexcept override { return window_seconds; }
    std::uint32_t threshold() const noexcept override { return reneg_threshold; }
};

}  // namespace https_guard

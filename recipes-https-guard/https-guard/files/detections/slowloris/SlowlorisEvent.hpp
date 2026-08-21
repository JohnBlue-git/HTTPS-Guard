#pragma once

#include <cstdint>

#include "hg_event.hpp"
#include "ISlowlorisInfo.hpp"

namespace https_guard {

/** Synthesised by ConnRateSweeper from the per-source held-open level. */
class SlowlorisEvent final : public hg_event, public ISlowlorisInfo {
public:
    std::uint32_t open_connections = 0;
    std::uint32_t slowloris_threshold = 0;

    std::uint32_t openConnections() const noexcept override { return open_connections; }
    std::uint32_t threshold() const noexcept override { return slowloris_threshold; }
};

}  // namespace https_guard

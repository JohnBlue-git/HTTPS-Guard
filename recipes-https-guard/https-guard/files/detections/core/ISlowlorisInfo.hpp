#pragma once

#include <cstdint>

namespace https_guard {

/**
 * An event reporting how many connections a source is holding open.
 *
 * A *level*, not a rate: Slowloris works by occupying connection slots and
 * then doing as little as possible, so the signal is the standing count
 * rather than how fast connections arrive. A source that opens many
 * connections and then goes quiet is the case of interest, and a windowed
 * counter would show it as idle.
 */
class ISlowlorisInfo {
public:
    virtual ~ISlowlorisInfo() = default;

    /** Connections opened and not yet seen to close. */
    virtual std::uint32_t openConnections() const noexcept = 0;

    virtual std::uint32_t threshold() const noexcept = 0;
};

}  // namespace https_guard

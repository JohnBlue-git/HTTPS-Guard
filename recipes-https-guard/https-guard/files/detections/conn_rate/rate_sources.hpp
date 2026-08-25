#pragma once

#include "ConnRateEvent.hpp"
#include "RenegotiationEvent.hpp"
#include "SlowlorisEvent.hpp"
#include "dispatch.hpp"

namespace https_guard {

/**
 * Classifies the three synthesised per-source counter events.
 *
 * These have no ring-buffer record: `ConnRateSweeper` reads the BPF counter map
 * on a timer and manufactures them. Each is a distinct type bound to a distinct
 * concept, which is what makes "one rule reading another's counter" a build
 * error -- the runtime version needed a test to pin that the three rules did not
 * poach each other's events.
 */
void handleConnRateEvent(const ConnRateEvent& evt, const DispatchContext& ctx);
void handleSlowlorisEvent(const SlowlorisEvent& evt, const DispatchContext& ctx);
void handleRenegotiationEvent(const RenegotiationEvent& evt, const DispatchContext& ctx);

}  // namespace https_guard

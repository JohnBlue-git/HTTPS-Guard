#include <optional>

#include "rate_sources.hpp"
#include "ConnRateDetector.hpp"
#include "RenegotiationDetector.hpp"
#include "SlowlorisDetector.hpp"

namespace https_guard {

void handleConnRateEvent(const ConnRateEvent& evt, const DispatchContext& ctx)
{
    static const ConnRateDetector rule;
    if (auto v = rule.evaluate(evt)) {
        dispatchVerdict(evt.meta, *v, ctx);
    }
    /* No traffic-observed fallback: the sweeper only synthesises these once a
     * counter is already over its threshold, so "nothing matched" means the
     * threshold moved under us, not that normal traffic was seen. */
}

void handleSlowlorisEvent(const SlowlorisEvent& evt, const DispatchContext& ctx)
{
    static const SlowlorisDetector rule;
    if (auto v = rule.evaluate(evt)) {
        dispatchVerdict(evt.meta, *v, ctx);
    }
}

void handleRenegotiationEvent(const RenegotiationEvent& evt, const DispatchContext& ctx)
{
    static const RenegotiationDetector rule;
    if (auto v = rule.evaluate(evt)) {
        dispatchVerdict(evt.meta, *v, ctx);
    }
}

}  // namespace https_guard

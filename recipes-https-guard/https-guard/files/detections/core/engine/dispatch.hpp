#pragma once

#include <chrono>
#include <string>

#include "Verdict.hpp"
#include "event_meta.hpp"

namespace https_guard {

class ActionLoop;

/** What every handler needs to turn a verdict into actions. */
struct DispatchContext {
    ActionLoop*          action_loop   = nullptr;
    std::chrono::seconds blocklist_ttl{0};
    std::string          output_path;
};

/**
 * The tail of every detection path: enforce if the verdict says so, then log.
 *
 * Shared by all handlers rather than duplicated per source, because the
 * enforcement gate below is the single most consequential piece of logic in the
 * project and has already been got wrong once.
 */
void dispatchVerdict(const EventMeta& meta,
                     const Verdict& verdict,
                     const DispatchContext& ctx);

/**
 * The "nothing matched" verdict. Not a rule: there is nothing to detect in the
 * absence of a detection, so it does not belong behind a rule's interface.
 * `tls_desc` is whatever the source can say about the TLS version, or "n/a".
 */
Verdict trafficObservedVerdict(const EventMeta& meta, const std::string& tls_desc);

}  // namespace https_guard

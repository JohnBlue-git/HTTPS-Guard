#pragma once

#include <string>

namespace https_guard {

/**
 * What a detector decided about an event: how severe, what to say about
 * it, and whether it's worth enforcing against. Not a property of the
 * event itself (see event_meta.hpp) — this is the rule's own output.
 */
struct Verdict {
    std::string severity;
    std::string message_id;
    std::string message;
    bool        actionable = false;
};

}  // namespace https_guard

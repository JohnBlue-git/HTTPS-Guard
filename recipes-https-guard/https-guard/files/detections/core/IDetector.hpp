#pragma once

#include <optional>

#include "hg_event.hpp"
#include "Verdict.hpp"

namespace https_guard {

/**
 * A single, pure, synchronous classification rule. Implementations must
 * not perform I/O, touch BPF/sockets, or dispatch enforcement actions —
 * that's the action layer's job (see actions/). A detector only decides
 * whether an already-parsed event matches its rule.
 */
class IDetector {
public:
    virtual ~IDetector() = default;

    /**
     * Inspects evt. Returns a Verdict if this rule matches, or
     * std::nullopt if it doesn't — evt itself is never mutated.
     */
    virtual std::optional<Verdict> evaluate(const hg_event& evt) const = 0;
};

}  // namespace https_guard

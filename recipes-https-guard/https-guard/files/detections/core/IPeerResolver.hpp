#pragma once

namespace https_guard {

class hg_event;

/**
 * Resolves the connection 4-tuple for an event, on demand.
 *
 * This exists so the expensive half of parsing doesn't run for events that
 * never need it. Filling `local_*`/`remote_*` for a uprobe event means
 * reading and line-parsing `/proc/<pid>/net/tcp` (several hundred lines on a
 * busy system) plus `/proc/<pid>/fd` — by far the most costly thing in the
 * pipeline — and every consumer of the result sits behind
 * `Verdict::actionable`, which the large majority of events never reach.
 *
 * Implemented by the hook that knows how to do the resolution (only
 * `ssl_uprobe` needs it; XDP reads the addresses straight from the packet),
 * and invoked through `hg_event::ensurePeerResolved()`, which memoises so
 * repeated asks cost nothing.
 *
 * Implementations must be safe to call from DetectLoop's threads and
 * must not throw — they are reached from a `noexcept` path.
 */
class IPeerResolver {
public:
    virtual ~IPeerResolver() = default;

    /**
     * Fills evt's local_ and remote_ fields. Returns whether a connection
     * was unambiguously identified; on false the fields are left untouched
     * (zeroed), which callers treat as "do not enforce".
     */
    virtual bool resolvePeer(hg_event& evt) const noexcept = 0;
};

}  // namespace https_guard

#pragma once

#include <cstdint>
#include <string>

#include "IPeerResolver.hpp"

namespace https_guard {

/**
 * What every event has, regardless of which hook or sweeper produced it.
 *
 * COMPOSED, NOT INHERITED
 * -----------------------
 * This used to be a polymorphic base class (`hg_event`) that every event type
 * derived from, so that one `IDetector` interface could take them all and each
 * rule could `dynamic_cast` back to the capability it needed. The type of a
 * record was therefore known exactly once -- in the code that parsed it -- then
 * deliberately erased, then guessed again downstream.
 *
 * Now it is a plain member. Events are concrete structs with no vtable, rules
 * take one concrete event struct each, and dispatch picks
 * a handler from the event-source word rather than probing types at runtime.
 * The same move the raw BPF side already made, where `hg_event_hdr` is nested
 * rather than inherited.
 */
struct EventMeta {
    std::uint64_t timestamp_ns = 0;
    std::uint32_t pid  = 0;
    std::uint32_t tgid = 0;

    /** Self-reported comm — a hint, never an identity. */
    std::string process;

    // The connection this event belongs to, named by ROLE rather than by
    // direction — deliberately, because "src"/"dst" caused a real bug.
    //
    //   local_*  = this BMC's end of the connection
    //   remote_* = the peer's end (the thing you would blocklist)
    //
    // The previous names were src_*/dst_*, which sound unambiguous but are
    // not: they depend on whose frame of reference you take. The two hooks
    // took opposite ones — the uprobe read /proc's local_address into src_*,
    // while the XDP ingress hook put the packet's sender there. Since the
    // blocklist blocked src_ip_v4, uprobe-sourced events were blocklisting the
    // BMC's own address, and since netlink wants local-then-remote, the XDP
    // tuple was inverted for SOCK_DESTROY.
    //
    // Byte order:
    //   - addresses are NETWORK byte order (memory bytes as on the wire, so
    //     inet_ntop and netlink's __be32 fields take them verbatim)
    //   - ports are HOST byte order (print directly; convert with htons()
    //     at any boundary wanting network order)
    std::uint32_t local_ip_v4  = 0;
    std::uint32_t remote_ip_v4 = 0;
    std::uint16_t local_port   = 0;
    std::uint16_t remote_port  = 0;

    /** Printable peer address, when the producer knows it. */
    std::string source_ip;

    // Resolving the tuple above is the most expensive operation in the
    // pipeline for uprobe events, and every consumer of it sits behind
    // Verdict::actionable — which most events never reach. So the producer
    // supplies a resolver instead of doing the work up front.
    //
    // Non-owning: the resolver is the hook module, which outlives every
    // event it produces. Null means "already resolved, or not resolvable
    // for this source" (XDP reads addresses straight from the packet).
    const IPeerResolver* peer_resolver = nullptr;

    /**
     * Resolves the connection tuple if a resolver was supplied and it hasn't
     * been done yet. Returns whether a tuple is available.
     *
     * const, with a mutable memo, so a rule holding a const reference can ask.
     *
     * THREADING: the memo is only safe because one event is touched by exactly
     * one classification at a time. That is a real constraint, not an
     * observation -- DetectLoop runs the connection-rate sweep concurrently
     * with a record, so an event shared between the two would race here.
     */
    bool ensurePeerResolved() const noexcept
    {
        if (peer_attempted_) {
            return peer_ok_;
        }
        peer_attempted_ = true;
        if (peer_resolver != nullptr) {
            peer_ok_ = peer_resolver->resolvePeer(const_cast<EventMeta&>(*this));
        }
        return peer_ok_;
    }

private:
    mutable bool peer_attempted_ = false;
    mutable bool peer_ok_        = false;
};

}  // namespace https_guard

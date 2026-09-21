#pragma once

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <string>

#include "IPeerResolver.hpp"

namespace https_guard {

/** Which shape the bytes in an `IpAddress` are. */
enum class IpFamily : std::uint8_t {
    kV4,
    kV6,
};

/**
 * A local or remote endpoint address, IPv4 or IPv6, tagged explicitly rather
 * than assumed.
 *
 * Byte order matches the convention the rest of this struct already uses:
 * NETWORK byte order, so the bytes are exactly what inet_ntop/inet_ntop6 and
 * netlink's __be32/struct in6_addr fields expect verbatim. For `kV4`, only
 * the first 4 bytes are meaningful; the remaining 12 are zero and unused.
 *
 * As of this type's introduction, every producer in this codebase only ever
 * sets `kV4` -- the wire (XDP) hook, the `/proc`-based uprobe fallback, and
 * the rate-sweep synthesised events are all IPv4-only today. The tag exists
 * so a future producer (ssl_uprobe's kernel-side session binding) can supply
 * an IPv6 tuple without every consumer needing to change again.
 */
struct IpAddress {
    IpFamily family = IpFamily::kV4;
    std::array<std::uint8_t, 16> bytes{};

    /** True once something has actually been written here. */
    bool isSet() const noexcept
    {
        return std::any_of(bytes.begin(), bytes.end(),
                            [](std::uint8_t b) noexcept { return b != 0; });
    }

    /**
     * The address as a plain 32-bit IPv4 value (network byte order).
     * Only meaningful when `family == IpFamily::kV4` -- callers must check
     * that first; this simply reads the first 4 bytes regardless of family.
     */
    std::uint32_t v4() const noexcept
    {
        std::uint32_t v = 0;
        std::memcpy(&v, bytes.data(), sizeof(v));
        return v;
    }

    /** Sets this address to an IPv4 value (network byte order) and tags it kV4. */
    void setV4(std::uint32_t v) noexcept
    {
        family = IpFamily::kV4;
        bytes.fill(0);
        std::memcpy(bytes.data(), &v, sizeof(v));
    }
};

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
    //     inet_ntop and netlink's __be32/in6_addr fields take them verbatim)
    //   - ports are HOST byte order (print directly; convert with htons()
    //     at any boundary wanting network order)
    //
    // local_ip_v4/remote_ip_v4 (plain uint32_t) were folded into IpAddress
    // above so a producer that knows an IPv6 peer can say so; every producer
    // as of this change still only ever sets kV4, so isSet()/v4()/setV4()
    // read exactly like the old zero-means-unset uint32_t did.
    IpAddress     local_ip;
    IpAddress     remote_ip;
    std::uint16_t local_port  = 0;
    std::uint16_t remote_port = 0;

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
        if (peer_attempted_)
        {
            return peer_ok_;
        }
        peer_attempted_ = true;
        if (peer_resolver != nullptr)
        {
            peer_ok_ = peer_resolver->resolvePeer(const_cast<EventMeta&>(*this));
        }
        return peer_ok_;
    }

private:
    mutable bool peer_attempted_ = false;
    mutable bool peer_ok_        = false;
};

}  // namespace https_guard

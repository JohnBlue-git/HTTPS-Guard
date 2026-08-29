#pragma once

#include <cstdint>
#include <string>

#include "IPeerResolver.hpp"

namespace https_guard {

/**
 * What every event has, regardless of which hook produced it: when, which
 * process, and which connection.
 *
 * WHAT IS DELIBERATELY *NOT* HERE
 * -------------------------------
 * Anything only some hooks can supply. This class used to carry 25 members
 * covering every hook's fields at once, which meant an LSM
 * certificate-access event arrived holding a cipher-suite list and an SNI
 * flag, a uprobe event held `cert_shadow_mode`, and — the part that
 * actually hurt — every new hook or feature widened a type in the
 * classification layer that every other hook depends on.
 *
 * Hook-specific data now lives on the hook's own event type, exposed
 * through small capability interfaces (`ITlsTrafficInfo`,
 * `IClientHelloInfo`, `ICertAccessInfo`). A detector asks for the
 * capability it needs; this class names none of them, so adding a hook or
 * a field cannot touch it.
 *
 * Capabilities rather than one event type per hook, because two detectors
 * (`TlsVersionDetector`, `PayloadAnomalyDetector`) are registered for both
 * the uprobe and XDP sources and would otherwise have no shared type to
 * bind to — see `ITlsTrafficInfo`.
 *
 * Polymorphic, so `parseEvent()` hands back `std::unique_ptr<hg_event>` and
 * detectors recover their capability with `dynamic_cast`. Copying one of
 * these by value would slice off the hook's half, so don't.
 */
class hg_event {
public:
    virtual ~hg_event() = default;

    hg_event() = default;
    hg_event(const hg_event&) = delete;             // would slice
    hg_event& operator=(const hg_event&) = delete;

    uint64_t timestamp_ns = 0;
    uint32_t event_type   = 0;

    uint32_t pid  = 0;
    uint32_t tgid = 0;

    // The connection this event belongs to, named by ROLE rather than by
    // direction — deliberately, because "src"/"dst" caused a real bug.
    //
    //   local_*  = this BMC's end of the connection
    //   remote_* = the peer's end (the thing you would blocklist)
    //
    // The previous names were src_*/dst_*, which sound unambiguous but are
    // not: they depend on whose frame of reference you take. The two hooks
    // took opposite ones — ssl_uprobe read /proc's local_address into src_*,
    // while xdp_tls (an ingress hook) put the packet's sender there. Since
    // BlocklistAddAction blocked src_ip_v4, uprobe-sourced events were
    // blocklisting the BMC's own address, and since netlink wants
    // local-then-remote, the XDP tuple was inverted for SOCK_DESTROY.
    //
    // Byte order:
    //   - addresses are NETWORK byte order (memory bytes as on the wire, so
    //     inet_ntop and netlink's __be32 fields take them verbatim)
    //   - ports are HOST byte order (print directly; convert with htons()
    //     at any boundary wanting network order)
    uint32_t local_ip_v4  = 0;
    uint32_t remote_ip_v4 = 0;
    uint16_t local_port   = 0;
    uint16_t remote_port  = 0;

    std::string process;    /* self-reported comm — a hint, not an identity */
    std::string source_ip;  /* printable peer address, when the hook knows it */

    // Resolving the tuple above is the most expensive operation in the
    // pipeline for uprobe events, and every consumer of it sits behind
    // Verdict::actionable — which most events never reach. So the hook
    // supplies a resolver instead of doing the work up front.
    //
    // Non-owning: the resolver is the hook module, which outlives every
    // event it produces. Null means "already resolved, or not resolvable
    // for this source" (XDP reads addresses straight from the packet).
    const IPeerResolver* peer_resolver = nullptr;

    /**
     * Resolves the connection tuple if a resolver was supplied and it
     * hasn't been done yet. Returns whether a tuple is available.
     *
     * const, with a mutable memo, so a detector holding `const hg_event&`
     * can ask — no current detector needs the tuple to classify, but a
     * future one keyed on source address would, and it should not have to
     * reintroduce the eager cost for every other event to get it.
     */
    bool ensurePeerResolved() const noexcept
    {
        if (peer_attempted_) {
            return peer_ok_;
        }
        peer_attempted_ = true;
        if (peer_resolver != nullptr) {
            peer_ok_ = peer_resolver->resolvePeer(const_cast<hg_event&>(*this));
        }
        return peer_ok_;
    }

private:
    mutable bool peer_attempted_ = false;
    mutable bool peer_ok_        = false;
};

}  // namespace https_guard

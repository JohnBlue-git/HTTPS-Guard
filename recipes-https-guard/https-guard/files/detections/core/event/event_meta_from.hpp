#pragma once

#include <cstring>

#include "bounded_string.hpp"
#include "event_meta.hpp"
#include "hg_event_source.h"

namespace https_guard {

/**
 * Fills the common envelope from a raw record.
 *
 * Every hook's raw struct starts with `hg_event_hdr` — that is what makes this
 * one function rather than one per source — so this covers the universal fields
 * for any of them. A source with more to say about the connection adds it in an
 * overload below.
 *
 * Kept in `core/` and not repeated per detection: several detections inspect the
 * same record, and duplicating the envelope parse across them would be both
 * wasteful and a place for them to drift.
 */
template <class RawT>
inline void fillEnvelope(const RawT& raw, EventMeta& meta) noexcept
{
    meta.timestamp_ns = raw.hdr.timestamp_ns;
    meta.pid          = raw.hdr.pid;
    meta.tgid         = raw.hdr.tgid;
    meta.process      = boundedString(raw.hdr.comm);
}

/**
 * The connection, for a source that carries one.
 *
 * XDP is an INGRESS hook, so the packet's destination is this BMC and its source
 * is the peer. The raw struct keeps the wire's own src/dst vocabulary; this is
 * the single place that translates direction into role. Getting that backwards
 * once meant blocklisting the BMC's own address — see `event_meta.hpp`.
 */
template <class ConnT>
inline void fillConnection(const ConnT& conn, EventMeta& meta) noexcept
{
    meta.local_ip.setV4(conn.dst_ip_v4);
    meta.remote_ip.setV4(conn.src_ip_v4);
    meta.local_port  = conn.dst_port;
    meta.remote_port = conn.src_port;
    meta.source_ip   = boundedString(conn.src_ip_str);
}

/**
 * The connection, for a source whose tuple is only sometimes resolved
 * (ssl_uprobe's kernel-side session binding — see hg_uprobe_conn).
 *
 * Present (`conn.resolved`): populate directly and leave `peer_resolver`
 * unset, extending the same "already resolved" contract XDP events use —
 * `EventMeta::ensurePeerResolved()` treats a null resolver as nothing left
 * to do, and `dispatchVerdict()` gates on the address being present, not on
 * whether resolution ran.
 *
 * Absent: defer to `resolver` exactly as if this hook had no tuple support
 * at all — today's `/proc`-based fallback, unchanged.
 */
template <class ConnT>
inline void fillResolvedConnection(const ConnT& conn, EventMeta& meta,
                                   const IPeerResolver* resolver) noexcept
{
    if (!conn.resolved)
    {
        meta.peer_resolver = resolver;
        return;
    }

    meta.local_ip.family  = conn.is_ipv6 ? IpFamily::kV6 : IpFamily::kV4;
    meta.remote_ip.family = meta.local_ip.family;
    std::memcpy(meta.local_ip.bytes.data(), conn.local_addr, meta.local_ip.bytes.size());
    std::memcpy(meta.remote_ip.bytes.data(), conn.remote_addr, meta.remote_ip.bytes.size());
    meta.local_port  = conn.local_port;
    meta.remote_port = conn.remote_port;
}

}  // namespace https_guard

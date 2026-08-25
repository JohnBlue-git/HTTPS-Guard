#pragma once

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
    meta.local_ip_v4  = conn.dst_ip_v4;
    meta.remote_ip_v4 = conn.src_ip_v4;
    meta.local_port   = conn.dst_port;
    meta.remote_port  = conn.src_port;
    meta.source_ip    = boundedString(conn.src_ip_str);
}

}  // namespace https_guard

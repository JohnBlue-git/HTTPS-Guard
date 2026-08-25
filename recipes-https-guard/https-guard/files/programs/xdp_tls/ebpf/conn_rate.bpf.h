/* SPDX-License-Identifier: GPL-2.0 */
/* Per-source connection-attempt counters, for volumetric abuse detection.
 *
 * Counts inbound TCP SYNs per source address into an LRU hash, and does
 * nothing else. It draws no conclusion and drops no packet.
 *
 * WHY BPF COUNTS BUT DOES NOT DECIDE
 * ----------------------------------
 * The counting has to be here: it is per-packet, and a flood is exactly the
 * situation where userspace cannot keep up. The *threshold* decision is
 * deliberately not here, for two reasons.
 *
 * First, a rate signal is far more false-positive-prone than the wire-format
 * checks this program already makes. A malformed ClientHello is malformed;
 * "20 connections a second" might be a monitoring system, a busy dashboard
 * opening parallel requests, or several administrators behind one NAT
 * address. Deciding in BPF would mean a second synchronous XDP_DROP path,
 * so a mistuned threshold would drop legitimate traffic at line rate with
 * nothing in the loop to catch it. Making cipher-suite and SNI detection
 * actionable already locked an operator out of SSH once during testing; that
 * is the same failure mode with a wider blast radius.
 *
 * Second, keeping the decision in userspace means the counters need no
 * BPF->userspace event channel at all: the daemon sweeps this map on a timer
 * and synthesises its own event. That avoids either bolting rate fields onto
 * xdp_event (the god-object problem the event types were split to avoid) or
 * changing BpfProgram so one hook can emit several event kinds.
 *
 * The cost is that enforcement waits for the next sweep rather than acting
 * on the offending packet. For *sustained* abuse -- which is what this
 * detects -- that is immaterial: once the source is blocklisted,
 * blocklist_check() above drops the remainder at line rate, which is the
 * same two-tier flow a TLS-version violation already uses.
 *
 * WINDOW vs THRESHOLD
 * -------------------
 * The window is fixed here because it is structural: it decides how much
 * memory a burst can occupy and how the counter resets. The count threshold
 * is the policy knob, and lives in configuration (HTTPS_GUARD_RATE_THRESHOLD)
 * because "abusive" is deployment-dependent. Changing the window needs a
 * rebuild; that is a real limitation, not an oversight.
 */
#pragma once

#include "hg_event_source.h"   /* uint*_t, in both the BPF and C++ worlds */

#define HTTPS_GUARD_CONN_RATE_MAP_NAME    "conn_rate"
#define HTTPS_GUARD_CONN_RATE_MAX_ENTRIES 4096

/* Fixed accumulation window. See "WINDOW vs THRESHOLD" above. */
#define HTTPS_GUARD_CONN_RATE_WINDOW_SEC  10

/* Per-source state, shared with userspace, which reads this map directly.
 *
 * Note the distinction between windowed and non-windowed fields. Rates reset
 * when the window rolls; `open_conns` is a *level* -- how many connections
 * this source currently holds open -- and must survive the roll, or a
 * Slowloris that simply waits would look like it had gone away. */
struct hg_conn_rate {
    uint64_t window_start_ns;  /* bpf_ktime_get_ns() when this window opened */
    uint32_t syn_count;        /* WINDOWED: inbound SYNs since the roll */
    uint32_t hello_count;      /* WINDOWED: TLS ClientHellos since the roll */
    int32_t  open_conns;       /* LEVEL: SYNs minus FIN/RSTs; survives the roll */
    uint32_t padding;
};

#ifndef __cplusplus

#include <bpf/bpf_helpers.h>

/* LRU rather than a plain hash, deliberately: a plain hash keyed on source
 * address is itself a DoS vector, since a spoofed-source flood would fill it
 * and then fail inserts. LRU bounds the memory and evicts the least recently
 * seen source, which under a distributed flood is exactly the entry least
 * worth keeping. */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, HTTPS_GUARD_CONN_RATE_MAX_ENTRIES);
    __type(key, uint32_t);                 /* source IPv4, network order */
    __type(value, struct hg_conn_rate);
} conn_rate SEC(".maps");

/* Which per-source counter an observation bumps. */
enum hg_conn_event {
    HG_CONN_ATTEMPT = 0,   /* inbound SYN: a new connection attempt */
    HG_CONN_CLOSED  = 1,   /* FIN or RST: a connection went away */
    HG_CONN_HELLO   = 2,   /* a TLS ClientHello arrived */
};

/* Records one observation about src_ip. Counts only; never decides. */
static __always_inline void conn_rate_record(uint32_t src_ip, enum hg_conn_event what)
{
    const uint64_t now = bpf_ktime_get_ns();
    const uint64_t window_ns =
        (uint64_t)HTTPS_GUARD_CONN_RATE_WINDOW_SEC * 1000000000ULL;

    struct hg_conn_rate *entry = bpf_map_lookup_elem(&conn_rate, &src_ip);
    if (!entry) {
        /* A close for a source we have never seen is not worth an entry --
         * it is the tail of a connection that predates us. */
        if (what == HG_CONN_CLOSED) {
            return;
        }
        struct hg_conn_rate fresh = {};
        fresh.window_start_ns = now;
        fresh.syn_count   = (what == HG_CONN_ATTEMPT) ? 1 : 0;
        fresh.hello_count = (what == HG_CONN_HELLO)   ? 1 : 0;
        fresh.open_conns  = (what == HG_CONN_ATTEMPT) ? 1 : 0;
        bpf_map_update_elem(&conn_rate, &src_ip, &fresh, BPF_ANY);
        return;
    }

    /* Roll the window rather than decaying: a fixed window is cheap and
     * cannot be gamed by pacing packets to sit just under a moving average,
     * which matters more here than smoothness.
     *
     * Only the windowed counters reset. open_conns deliberately carries over:
     * it describes how many connections are held open right now, and a
     * Slowloris that stops sending would otherwise appear to release them. */
    if (now - entry->window_start_ns > window_ns) {
        entry->window_start_ns = now;
        entry->syn_count   = 0;
        entry->hello_count = 0;
    }

    /* Saturate rather than wrap. Anything at the ceiling is far past any
     * plausible threshold, and a wrapped counter would read as innocent. */
    switch (what) {
    case HG_CONN_ATTEMPT:
        if (entry->syn_count < 0xFFFFFFFFU) {
            entry->syn_count += 1;
        }
        if (entry->open_conns < 0x7FFFFFFF) {
            entry->open_conns += 1;
        }
        break;
    case HG_CONN_HELLO:
        if (entry->hello_count < 0xFFFFFFFFU) {
            entry->hello_count += 1;
        }
        break;
    case HG_CONN_CLOSED:
        /* Floor at zero. Closes can legitimately outnumber the SYNs we saw
         * (connections predating this entry, or a FIN and an RST for the
         * same connection), and a negative level would read as innocent
         * forever afterwards. */
        if (entry->open_conns > 0) {
            entry->open_conns -= 1;
        }
        break;
    }
}

#endif /* !__cplusplus */

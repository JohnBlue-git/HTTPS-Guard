#pragma once

#include "hg_event_source.h"

/* Which direction of SSL_write/SSL_read produced this event. SSL_write's
 * buffer already holds plaintext when its (entry-only) uprobe fires;
 * SSL_read's buffer is only populated once the call returns, so that
 * side is captured via a paired entry+return uprobe instead — see
 * ssl_uprobe.bpf.h for why. */
enum hg_uprobe_direction {
    HG_UPROBE_DIR_WRITE = 0,  /* data the process sent (response) */
    HG_UPROBE_DIR_READ  = 1,  /* data the process received (request) */
};

/* What the uprobe could see of the TLS session, grouped so it is obvious
 * that this is the whole of this hook's TLS knowledge: a version read out
 * of the SSL object, and a prefix of the plaintext. No connection tuple —
 * a uprobe has no socket identity of its own, which is why ProcPeerResolver
 * exists as a userspace fallback and hg_uprobe_conn (below) as the kernel-
 * side alternative. */
struct hg_uprobe_tls {
    uint16_t version;         /* raw ssl->version, read via bpf_probe_read_user */
    uint16_t padding;
    char     payload_snippet[HG_PAYLOAD_SNIPPET_LEN];
};

/* The connection tuple, when the kernel-side session binding resolved one
 * for this SSL session before this event fired -- ssl_uprobe's kprobes on
 * tcp_recvmsg/tcp_sendmsg, correlated with the SSL_accept/SSL_connect
 * uprobes at handshake time. Absent (resolved == 0, every other field
 * zeroed) whenever that binding hasn't happened: a connection predating
 * this daemon's attach, a session whose accept/first-read ran on different
 * threads, or simply a session for which this event is not yet the first
 * one seen. `resolved` is the explicit signal deliberately, rather than
 * inferring absence from an all-zero address -- an unresolved tuple and a
 * resolved one that happened to be all-zero must never be confused, the
 * same reasoning EventMeta::IpAddress::isSet() already documents.
 *
 * Dual-stack: 16 address bytes regardless of family, network byte order,
 * matching EventMeta::IpAddress -- for an IPv4 tuple only the first 4 bytes
 * are meaningful and the rest are zero. */
struct hg_uprobe_conn {
    uint8_t  resolved;    /* 1 if the fields below are valid */
    uint8_t  is_ipv6;
    uint16_t padding;
    uint8_t  local_addr[16];
    uint8_t  remote_addr[16];
    uint16_t local_port;  /* host byte order */
    uint16_t remote_port; /* host byte order */
};

/* =========================================================================
 * Uprobe event: PURELY OBSERVATIONAL
 * ========================================================================= */
struct uprobe_event {
    struct hg_event_hdr   hdr;
    uint32_t              direction;  /* enum hg_uprobe_direction */
    uint32_t              padding;
    struct hg_uprobe_tls  tls;
    struct hg_uprobe_conn resolved_conn;
};

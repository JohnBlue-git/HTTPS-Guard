#pragma once

#include "hg_event_source.h"

/* The connection this packet belongs to, as read from the headers.
 *
 * Named by DIRECTION (src/dst) rather than by role (local/remote), unlike
 * EventMeta -- deliberately, because that is what a packet on an ingress
 * path actually tells you. XdpTlsProgram::parseEvent() is the one place
 * that maps direction to role, and it is an ingress hook, so src is the
 * peer. See event_meta.hpp for the bug that conflating the two once caused. */
struct hg_conn_tuple {
    uint32_t src_ip_v4;                /* network byte order */
    uint32_t dst_ip_v4;                /* network byte order */
    uint16_t src_port;                 /* host byte order */
    uint16_t dst_port;                 /* host byte order */
    char     src_ip_str[HG_IP_STR_LEN];/* printable src, formatted in BPF */
};

/* What the wire showed about TLS, plus the one line-rate classification
 * this project allows in BPF. `is_violation` is a hint and not a verdict:
 * it exists because XDP has to decide whether to drop *this* packet before
 * userspace can see it. See detections/CLAUDE.md for why it cannot simply
 * be re-derived from `version`. */
struct hg_xdp_tls {
    uint16_t version;         /* raw legacy_version from the record header */
    uint16_t is_violation;    /* 1 if version < TLS 1.2 */
    char     payload_snippet[HG_PAYLOAD_SNIPPET_LEN];
};

/* ClientHello detail. Populated only for actual ClientHello handshake
 * messages (HandshakeType 0x01); entirely zero otherwise, which is why it
 * is a separate struct rather than fields hanging off xdp_event -- a reader
 * can see at a glance that these travel together and are absent together.
 *
 * Raw observations only, no classification: see detections/cipher_suite/
 * and detections/sni/. Both arrays are capture caps rather than protocol
 * limits, so `cipher_suites_offered` reports the true count and lets a
 * detector tell a short list from a clipped one. */
struct hg_client_hello {
    uint16_t cipher_suites[HG_MAX_CIPHER_SUITES];  /* host byte order */
    uint16_t cipher_suite_count;     /* how many of the above are valid */
    uint16_t cipher_suites_offered;  /* total offered; > count means truncated */

    uint8_t  sni_present;      /* 1 if an SNI host_name was extracted */
    uint8_t  sni_malformed;    /* 1 if the structure did not parse as expected */
    uint16_t padding;
    char     sni_hostname[HG_SNI_LEN];
};

/* =========================================================================
 * XDP event: MINIMAL CLASSIFICATION FOR LINE-RATE DECISIONS
 * ========================================================================= */
struct xdp_event {
    struct hg_event_hdr    hdr;
    struct hg_conn_tuple   conn;
    struct hg_xdp_tls      tls;
    struct hg_client_hello client_hello;
};

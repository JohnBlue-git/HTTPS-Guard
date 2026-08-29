#pragma once

#include "hg_event_source.h"

/* =========================================================================
 * XDP event: MINIMAL CLASSIFICATION FOR LINE-RATE DECISIONS
 * ========================================================================= */
struct xdp_event {
    uint32_t event_source;    /* HG_SOURCE_XDP */
    uint32_t is_violation;    /* 1 if TLS version < 1.2, 0 otherwise */

    uint64_t timestamp_ns;
    uint32_t pid;
    uint32_t tgid;

    uint32_t src_ip_v4;
    uint32_t dst_ip_v4;
    uint16_t src_port;
    uint16_t dst_port;

    uint16_t tls_version;     /* Raw TLS version from ClientHello */
    uint16_t padding;         /* Alignment */

    char process[HG_COMM_LEN];
    char source_ip[HG_IP_STR_LEN];
    char payload_snippet[HG_PAYLOAD_SNIPPET_LEN];

    /* --- ClientHello detail, only populated for actual ClientHello
     * handshake messages (HandshakeType 0x01); all zero otherwise.
     * Raw observations only — no classification, unlike is_violation
     * above. See detections/cipher_suite/ and detections/sni/. --- */
    uint16_t cipher_suites[HG_MAX_CIPHER_SUITES];  /* host byte order */
    uint16_t cipher_suite_count;     /* how many of the above are valid */
    uint16_t cipher_suites_offered;  /* total the client offered; > count means truncated */

    uint8_t  sni_present;      /* 1 if an SNI host_name was extracted */
    uint8_t  sni_malformed;    /* 1 if ClientHello structure didn't parse as expected */
    uint16_t padding2;         /* Alignment */
    char     sni_hostname[HG_SNI_LEN];
};

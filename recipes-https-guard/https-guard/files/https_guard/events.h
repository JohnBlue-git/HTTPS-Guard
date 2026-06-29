#ifndef HTTPS_GUARD_EVENTS_H
#define HTTPS_GUARD_EVENTS_H

/*
 * Use BPF-native integer types when compiled for the BPF target
 * (clang -target bpf), and standard <stdint.h> types otherwise.
 */
#ifdef __BPF__
typedef unsigned char      uint8_t;
typedef unsigned short     uint16_t;
typedef unsigned int       uint32_t;
typedef unsigned long long uint64_t;
#else
#include <stdint.h>
#endif // __BPF__

#define HG_COMM_LEN            16
#define HG_IP_STR_LEN          32
#define HG_PAYLOAD_SNIPPET_LEN 128

/* Event source discriminator - first field in all event structs */
enum hg_event_source {
    HG_SOURCE_UPROBE = 1,
    HG_SOURCE_XDP    = 2
};

/* =========================================================================
 * Uprobe event: PURELY OBSERVATIONAL
 * ========================================================================= */
struct uprobe_event {
    uint32_t event_source;    /* HG_SOURCE_UPROBE */
    uint32_t reserved;        /* Padding */

    uint64_t timestamp_ns;
    uint32_t pid;
    uint32_t tgid;

    uint16_t tls_version;     /* Raw TLS version from ssl->version */
    uint16_t padding;         /* Alignment */

    char process[HG_COMM_LEN];
    char payload_snippet[HG_PAYLOAD_SNIPPET_LEN];
};

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
};

#endif /* HTTPS_GUARD_EVENTS_H */

#ifndef HTTPS_GUARD_EVENTS_H
#define HTTPS_GUARD_EVENTS_H

#include <stdint.h>

#define HG_COMM_LEN 16
#define HG_IP_STR_LEN 48
#define HG_SNI_LEN 128
#define HG_URI_LEN 256
#define HG_PAYLOAD_SNIPPET_LEN 256

enum hg_event_type {
    HG_EVENT_TLS_VERSION_VIOLATION = 1,
    HG_EVENT_TLS_HANDSHAKE_METADATA = 2,
    HG_EVENT_HTTP_PAYLOAD_OBSERVED = 3,
    HG_EVENT_HTTP_ANOMALY_DETECTED = 4
};

enum hg_severity {
    HG_SEV_INFO = 0,
    HG_SEV_WARNING = 1,
    HG_SEV_CRITICAL = 2
};

struct hg_event {
    uint64_t timestamp_ns;
    uint32_t event_type;
    uint32_t severity;

    uint32_t pid;
    uint32_t tgid;

    uint32_t src_ip_v4;
    uint32_t dst_ip_v4;
    uint16_t src_port;
    uint16_t dst_port;

    uint16_t tls_version;
    uint16_t tls_record_type;

    char process[HG_COMM_LEN];
    char source_ip[HG_IP_STR_LEN];
    char sni[HG_SNI_LEN];
    char uri[HG_URI_LEN];
    char payload_snippet[HG_PAYLOAD_SNIPPET_LEN];
};

#endif

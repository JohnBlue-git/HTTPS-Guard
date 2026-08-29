#pragma once

#include "../core/hg_event_source.h"

/* Which direction of SSL_write/SSL_read produced this event. SSL_write's
 * buffer already holds plaintext when its (entry-only) uprobe fires;
 * SSL_read's buffer is only populated once the call returns, so that
 * side is captured via a paired entry+return uprobe instead — see
 * ssl_uprobe.bpf.h for why. */
enum hg_uprobe_direction {
    HG_UPROBE_DIR_WRITE = 0,  /* data the process sent (response) */
    HG_UPROBE_DIR_READ  = 1,  /* data the process received (request) */
};

/* =========================================================================
 * Uprobe event: PURELY OBSERVATIONAL
 * ========================================================================= */
struct uprobe_event {
    uint32_t event_source;    /* HG_SOURCE_UPROBE */
    uint32_t direction;       /* enum hg_uprobe_direction */

    uint64_t timestamp_ns;
    uint32_t pid;
    uint32_t tgid;

    uint16_t tls_version;     /* Raw TLS version from ssl->version */
    uint16_t padding;         /* Alignment */

    char process[HG_COMM_LEN];
    char payload_snippet[HG_PAYLOAD_SNIPPET_LEN];
};

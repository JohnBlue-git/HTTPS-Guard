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
 * a uprobe has no socket identity, which is why ProcPeerResolver exists. */
struct hg_uprobe_tls {
    uint16_t version;         /* raw ssl->version, read via bpf_probe_read_user */
    uint16_t padding;
    char     payload_snippet[HG_PAYLOAD_SNIPPET_LEN];
};

/* =========================================================================
 * Uprobe event: PURELY OBSERVATIONAL
 * ========================================================================= */
struct uprobe_event {
    struct hg_event_hdr  hdr;
    uint32_t             direction;  /* enum hg_uprobe_direction */
    uint32_t             padding;
    struct hg_uprobe_tls tls;
};

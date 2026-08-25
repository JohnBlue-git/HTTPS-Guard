#pragma once

#include "hg_event_source.h"

/* What the LSM hook observed about the access itself.
 *
 * comm_mismatch is a WEAK, BPF-side-only signal (see lsm_cert_guard.bpf.h
 * for why the real identity check cannot run in-kernel on this platform).
 * The strong check, from the accessing process's real executable, happens
 * in userspace — LsmCertGuardProgram::parseEvent() via /proc/<pid>/exe —
 * and lands in CertAccessEvent::identity_mismatch, a different field from
 * this one. Keeping them separately named is deliberate: they disagree,
 * and which one a reader is looking at matters. */
struct hg_cert_access {
    uint64_t cgroup_id;       /* bpf_get_current_cgroup_id() of the opener */
    uint32_t comm_mismatch;   /* 1 if the self-reported comm != "bmcweb" */
    uint32_t shadow_mode;     /* 1 if this decision was observe-only */
};

/* =========================================================================
 * LSM cert-access-guard event: an open() of the BMC's HTTPS certificate
 * or private key file.
 * ========================================================================= */
struct lsm_cert_guard_event {
    struct hg_event_hdr   hdr;
    struct hg_cert_access cert;
};

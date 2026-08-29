#pragma once

#include "../core/hg_event_source.h"

/* =========================================================================
 * LSM cert-access-guard event: an open() of the BMC's HTTPS certificate
 * or private key file. comm_mismatch is a WEAK, BPF-side-only signal (see
 * lsm_cert_guard.bpf.h for why the real identity check can't run
 * in-kernel on this platform) — the strong check, from the accessing
 * process's real executable, happens in userspace (LsmCertGuardProgram::
 * parseEvent(), via /proc/<pid>/exe) and lands in hg_event.cert_identity_
 * mismatch, a different field from this one.
 * ========================================================================= */
struct lsm_cert_guard_event {
    uint32_t event_source;   /* HG_SOURCE_LSM_CERT_GUARD */
    uint32_t comm_mismatch;  /* 1 if the self-reported comm != "bmcweb" */
    uint32_t shadow_mode;    /* 1 if this decision was observe-only (never denied) */
    uint32_t padding;

    uint64_t timestamp_ns;
    uint32_t pid;
    uint32_t tgid;
    uint64_t cgroup_id;

    char comm[HG_COMM_LEN];
};

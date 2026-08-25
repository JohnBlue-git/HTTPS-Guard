/* SPDX-License-Identifier: GPL-2.0 */
/* HTTPS-Guard eBPF program — BPF-LSM certificate-access guard
 *
 * Attaches to the "file_open" LSM hook (SEC("lsm.s/file_open"),
 * https_guard_cert_open below) and fires for every file opened on the
 * system, not just the certificate. It filters down to one exact path —
 * the BMC's HTTPS certificate/key file — and, for opens of that file
 * only, reports the accessing process's PID, self-reported comm, and
 * cgroup, then hands off to userspace for the real identity check.
 *
 * WHY THE REAL IDENTITY CHECK CAN'T RUN IN-KERNEL ON THIS PLATFORM:
 * ------------------------------------------------------------------------
 * The obvious design — resolve the accessing process's REAL executable
 * (not just comm) here, so a synchronous deny can be trustworthy — was
 * tried and does not work on this target. The kernel's own recommended
 * mechanism for this (bpf_get_task_exe_file() + bpf_path_d_path(), both
 * kfuncs — see fs/bpf_fs_kfuncs.c and the kernel's own
 * tools/testing/selftests/bpf/progs/verifier_vfs_accept.c) passes BPF
 * verification but fails at BPF_PROG_LOAD with "-ENOTSUPP: JIT does not
 * support calling kernel function" — the ARM32 BPF JIT
 * (arch/arm/net/bpf_jit_32.c) cannot emit calls to kfuncs at all, unlike
 * x86_64/arm64. A manual task->mm->exe_file walk avoids the kfunc-call
 * problem but hits a different, unavoidable one: the verifier drops
 * pointer trust after the second pointer hop from
 * bpf_get_current_task_btf() (task->mm, then mm->exe_file), and
 * bpf_d_path() (the one path-to-string helper that IS a plain, JIT-
 * compatible helper rather than a kfunc) refuses an untrusted pointer.
 * There is no third option available on this kernel/architecture
 * combination: real-executable resolution for the CURRENT task requires
 * either a kfunc or a trust level this hook can't obtain another way.
 *
 * So the real identity check happens where a hook CAN read /proc freely:
 * userspace, in LsmCertGuardProgram::parseEvent(), via
 * /proc/<pid>/exe — the same "resolve in userspace" pattern
 * ssl_uprobe/proc_peer_resolver.hpp already uses for socket info the
 * uprobe context can't see either. The cost is that this can only ever
 * be an asynchronous, observational check (see below) — it cannot gate
 * this hook's own synchronous allow/deny decision, because by the time
 * userspace has resolved it, this file_open call has already returned.
 *
 * WHAT THIS HOOK *CAN* STILL DECIDE SYNCHRONOUSLY: comm_mismatch below
 * is a coarse, self-reported, spoofable pre-check (exactly the kind of
 * signal this ticket set out to move beyond) — kept only so the shadow-
 * mode / enforcement mechanics below are real, working code, not a
 * fiction. It is never enabled by default; see the "SHADOW MODE" note.
 *
 * WHY THIS NEEDS A SLEEPABLE LSM PROGRAM:
 * ------------------------------------------------------------------------
 * bpf_d_path() is only reachable from BPF_PROG_TYPE_LSM programs that are
 * sleepable (kernel/trace/bpf_trace.c's bpf_d_path_allowed() checks
 * bpf_lsm_is_sleepable_hook() for LSM-type programs; "file_open" is on
 * that allowlist). SEC("lsm.s/...") is libbpf's naming convention for
 * the sleepable variant (vs. plain "lsm/...").
 *
 * SHADOW MODE (default on, see the ticket for the rollout plan):
 * ------------------------------------------------------------------------
 * shadow_mode below is a genuine runtime branch, not compiled away —
 * it's declared `const volatile` specifically so a future loader could
 * patch it via the program's .rodata map before load. Nothing in this
 * ticket ever does that: shadow_mode is always true here, so the deny
 * branch exists and is verifier-checked, but is not reachable by
 * anything this ticket ships — and, given it can only ever be gated on
 * the weak comm signal on this platform, it is not expected to become
 * reachable by a later ticket either without a stronger in-kernel
 * signal this hardware doesn't currently offer a way to get. Every open
 * of the cert file is still reported to userspace via the ring buffer
 * regardless of shadow_mode — "observe and log" rather than nothing
 * happening at all, with the STRONG (real-exe-path) check happening
 * asynchronously on the userspace side of that same event.
 */
#pragma once

#include "lsm_cert_guard_event.h"

#define HTTPS_GUARD_CERT_PATH "/etc/ssl/certs/https/server.pem"
#define HTTPS_GUARD_BMCWEB_COMM "bmcweb"

/* errno.h isn't available in BPF C (see https_guard.bpf.c's note on BPF
 * having no standard library); EACCES is always 13 on Linux. */
#define HG_EACCES 13

const volatile bool shadow_mode = true;

/* Resolves `path` to a string and compares it against `expected`
 * (a compile-time string literal, `expected_len` excluding the NUL).
 * bpf_d_path() returns strlen()+1 (including the NUL) on success. Only
 * ever called here with file->f_path, an embedded (non-pointer) struct
 * member at a fixed offset from the hook's own trusted `file` argument —
 * still verifier-trusted despite not being kfunc-acquired. */
static __always_inline bool
https_guard_path_matches(struct path *path, const char *expected, int expected_len)
{
    char buf[HG_PATH_LEN];
    long len = bpf_d_path(path, buf, sizeof(buf));

    if (len != expected_len + 1)
        return false;

    for (int i = 0; i < expected_len; i++) {
        if (buf[i] != expected[i])
            return false;
    }
    return true;
}

SEC("lsm.s/file_open")
int BPF_PROG(https_guard_cert_open, struct file *file)
{
    static const char cert_path[]    = HTTPS_GUARD_CERT_PATH;
    static const char bmcweb_comm[]  = HTTPS_GUARD_BMCWEB_COMM;

    if (!https_guard_path_matches(&file->f_path, cert_path, sizeof(cert_path) - 1))
        return 0;  /* not the certificate file: nothing to say or decide */

    char comm[HG_COMM_LEN];
    bpf_get_current_comm(&comm, sizeof(comm));

    bool comm_ok = true;
    for (int i = 0; i < (int)sizeof(bmcweb_comm) - 1; i++) {
        if (comm[i] != bmcweb_comm[i]) {
            comm_ok = false;
            break;
        }
    }

    struct lsm_cert_guard_event *evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
    if (evt) {
        __builtin_memset(evt, 0, sizeof(*evt));
        evt->hdr.event_source = HG_SOURCE_LSM_CERT_GUARD;
        evt->hdr.reserved     = 0;
        evt->cert.comm_mismatch = comm_ok ? 0 : 1;
        evt->cert.shadow_mode   = shadow_mode ? 1 : 0;
        evt->hdr.timestamp_ns   = bpf_ktime_get_ns();

        __u64 pid_tgid = bpf_get_current_pid_tgid();
        evt->hdr.pid  = (__u32)pid_tgid;
        evt->hdr.tgid = (__u32)(pid_tgid >> 32);
        evt->cert.cgroup_id = bpf_get_current_cgroup_id();

        __builtin_memcpy(evt->hdr.comm, comm, sizeof(comm));

        bpf_ringbuf_submit(evt, 0);
    }

    if (shadow_mode)
        return 0;  /* observe-and-log only: never deny, regardless of comm_ok */

    return comm_ok ? 0 : -HG_EACCES;
}

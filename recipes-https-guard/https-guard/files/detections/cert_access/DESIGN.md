# Certificate access violation

**Emits:** `OemSecurityEvent.1.0.HttpsCertificateAccessViolation` (Critical) ·
**Enforces:** no — there is no connection to act on, and on this target the
in-kernel decision cannot happen at all.

## Why detect this

Every other detection here asks *what does this traffic look like*. This one asks
*who did that*, about the one asset where the answer matters most.

`ssl_uprobe` verifies what TLS traffic looks like but never who is behind it: its
process field is a self-reported `comm`, changeable by the process itself. That is
adequate for a hint attached to a traffic event and useless for the question
"should this program be reading the BMC's private key".

And `/etc/ssl/certs/https/server.pem` is the asset where it matters. If a process
outside the small set that legitimately touches it reads that file, the key may
already be compromised and **every connection ever protected by it is
retroactively suspect** — no amount of traffic inspection recovers from that.

```
┌──────────────────────────────────────────────────────────────────┐
│  bmcweb                       → opens the key at startup.        │
│                                  Expected.                        │
│                                                                   │
│  phosphor-certificate-manager → writes a new key/cert here on a  │
│                                  Redfish/D-Bus certificate        │
│                                  install, then restarts bmcweb.   │
│                                  Expected.                        │
│                                                                   │
│  anything else                → the key is now assumed leaked.   │
│    ...even if it called prctl(PR_SET_NAME, "bmcweb") first,      │
│       which is exactly why comm is not the check.                │
└──────────────────────────────────────────────────────────────────┘
```

**Why `phosphor-certificate-manager` is on the allow list, not just bmcweb.**
`bmcweb` is a *consumer* of `server.pem` — it reads the file at startup and,
if it is entirely absent, falls back to generating a self-signed one so the
WebUI stays reachable. It is not the component that manages certificate
lifecycle. That belongs to `phosphor-certificate-manager`, the OpenBMC service
behind the Redfish/D-Bus certificate-install API: when an operator uploads a
new HTTPS certificate through Redfish or the WebUI, this service is what
writes `/etc/ssl/certs/https/server.pem` and then restarts `bmcweb.service` so
the new certificate takes effect. That write is exactly the kind of event this
detector watches for, and it is routine, not an attack — so it has to be
enumerated as an expected accessor rather than left to fall through to
"anything else". Without it, every legitimate certificate rotation would raise
a Critical `HttpsCertificateAccessViolation`, which is worse than a merely
noisy false positive: an operator who has seen that "violation" fire for their
own routine cert upload once is primed to dismiss it the next time it fires
for real.

## How to detect — three attempts, in the order they were tried

This detection's implementation history matters more than most, because each of
the first two obvious designs **compiled**, and each failed for a different
reason, at a later stage than the one before.

**Attempt 1 — resolve the real exe path in-kernel by walking
`task->mm->exe_file`, then `bpf_d_path()`.** The natural design:
`bpf_get_current_task_btf()` gives a verifier-trusted `task_struct*`, so walking
to `exe_file` and handing that to `bpf_d_path()` looks like it should work. It
does not. The verifier drops pointer trust after the *second* hop from a trusted
anchor (`task->mm`, then `mm->exe_file`), and `bpf_d_path()` refuses anything but
a trusted, RCU, or hook-argument-provided pointer. Rejected at `BPF_PROG_LOAD`:

```
R1 type=untrusted_ptr_ expected=ptr_, trusted_ptr_, rcu_ptr_
```

**Attempt 2 — the kernel's own recommended fix: `bpf_get_task_exe_file()` +
`bpf_path_d_path()`.** The kernel's selftests for this exact problem
(`verifier_vfs_accept.c`) show the intended solution:
`bpf_get_task_exe_file(task)` does the trusted walk internally and returns an
acquired, refcounted `file*`, and `bpf_path_d_path()` is documented as the
"safer variant... should be used in place of `bpf_d_path()` whenever possible".
This **passes verification cleanly** — and still fails, one layer deeper, at load:

```
-ENOTSUPP: JIT does not support calling kernel function
```

Both are **kfuncs**, not classic numbered helpers, and the ARM32 BPF JIT
(`arch/arm/net/bpf_jit_32.c`) has never implemented kfunc-call codegen. A real
current architecture gap, not a config option. (`bpf_d_path()` from attempt 1 is
a classic helper and has no such problem — only kfunc calls do.)

**Attempt 3, shipped — do the strong check in userspace.** Since kfuncs are
unusable here, in-kernel real-exe-path resolution is unusable here, full stop.
So the BPF side keeps to what a classic helper can verify and JIT: it filters on
the exact cert path (`bpf_d_path()` against `file->f_path` — a hook-argument
pointer, still trusted) and reports PID, `comm` and cgroup, plus a coarse
comm-based pre-check. The real check happens during parsing, in
`CertAccessDetection::inspect()`, via `readlink("/proc/<pid>/exe")` — a plain
syscall, no BPF at all. That mirrors how the uprobe path already recovers socket
info it cannot see directly.

**Then a fourth problem, independent of all three.** Attaching *any*
`BPF_PROG_TYPE_LSM` program — regardless of what it does internally — needs the
kernel's BPF trampoline mechanism, and ARM32 has no
`arch_prepare_bpf_trampoline()` at all: absent from `arch/arm/net/`, present in
`arch/{arm64,x86,riscv,s390,powerpc,loongarch,parisc}/net/`. So
`bpf_program__attach_lsm()` fails with `-ENOTSUPP` on this hardware no matter how
the program is written.

### The two identity signals are deliberately not merged

| Field | Source | Trustworthy? |
|---|---|---|
| `meta.process` | `bpf_get_current_comm()` | No — the process can set it |
| `identity_mismatch` | `readlink("/proc/<pid>/exe")` in userspace | Yes — kernel-maintained, unforgeable by the process |

They can disagree, and only the second is acted on. An **empty** resolved path
(the process exited before we looked) counts as a mismatch: silently trusting
"unknown" would defeat the point.

## How to protect — and why it cannot, here

```
libbpf: prog 'https_guard_cert_open': failed to attach: -ENOTSUPP
https_guard: failed to attach LSM cert-access-guard (non-fatal): Unknown error 524
https_guard: enforcement active via 2 of 3 hook(s)
```

`2 of 3` is the expected healthy state on AST2600/ARMv7, not a fault.

The verdict is also not `actionable` even where the hook does attach, and for a
different reason: there is no connection to tear down and no address to
blocklist. A file open is not a flow. Any in-kernel decision already happened —
or did not — before the rule ever ran.

**Where that leaves the rollout:**

1. **On this hardware:** alert-only, permanently, until proven otherwise. The Critical Redfish event *is* the security value — an operator or SIEM sees "an unrecognised process opened the HTTPS private key" and can rotate the key and investigate, even though the kernel could not stop the read.
2. **On a platform with trampoline support** (arm64, x86_64) the deny branch becomes reachable — but should still not be enabled as-is, because it is gated on the weak `comm` check, the exact signal this detection exists to move beyond. Making it trustworthy there means re-attempting attempt 2, since kfunc JIT support is a genuine per-architecture capability rather than the universal gap ARM32 has.
3. **If real-time denial on this exact hardware is ever required**, it needs a fundamentally different mechanism — a small non-BPF LSM module, or file permissions / a MAC policy that does not depend on BPF trampolines. A new investigation, not a variation of this.

## What to hook

`lsm_cert_guard`, `SEC("lsm.s/file_open")` — sleepable, because the path
comparison needs it. Attach mechanics and the expected failure are in
[`programs/DESIGN.md`](../../programs/DESIGN.md).

## Limits worth knowing

- **No synchronous enforcement on this project's target**, for the two independent reasons above. This is the central limitation, not a footnote.
- **The BPF-side `comm` check is exactly as spoofable as the uprobe's.** It exists only to keep the shadow-mode mechanics real rather than fictional; it is not the stronger check.
- **The `/proc/<pid>/exe` check can race a short-lived process.** Open-then-exit fast enough and the `readlink()` fails, `real_exe_path` comes back empty, and the event is logged as a violation with an empty path. Worth knowing when reading the message rather than assuming a nonempty path was always resolved.

## How to trigger it

See [README.md § Exercising the Detections](../../../../../README.md#exercising-the-detections)
for the runnable recipe and this detection's live-verification status.

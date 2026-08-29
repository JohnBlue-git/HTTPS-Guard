# `lsm_cert_guard` — BPF-LSM certificate-access guard (AUXILIARY hook)

## Why detect this

`ssl_uprobe` verifies *what TLS traffic looks like*, but never *who's actually behind it* — its `process` field is a self-reported `comm` string, changeable by the process itself. The BMC's HTTPS private key (`/etc/ssl/certs/https/server.pem`) is the one asset on this system where "who opened this file" matters more than any traffic pattern: if a process other than bmcweb ever reads it, the key may already be compromised, and every connection ever protected by it is retroactively suspect. This hook exists to answer that one question with something stronger than `comm`.

```
┌──────────────────────────────────────────────────────────────────┐
│  Who might open the certificate file, and why it matters         │
│                                                                    │
│  Legitimate: bmcweb, at startup or cert rotation                  │
│      → real exe path == /usr/bin/bmcweb → not flagged             │
│                                                                    │
│  Attack: any other process — a compromised service, a shell       │
│          someone got onto the BMC, malware — opening the same     │
│          file, possibly even naming itself "bmcweb" via            │
│          prctl(PR_SET_NAME) to fool comm-based checks              │
│      → real exe path != /usr/bin/bmcweb → CertAccessDetector       │
│        fires: Critical (but see "What actually enforces" below —   │
│        on this hardware, this can only ever be an alert, not a     │
│        block)                                                      │
└──────────────────────────────────────────────────────────────────┘
```

## How to detect — three attempts, in the order they were actually tried

This hook's implementation history matters more than most, because each of the first two "obvious" designs compiled, and each failed for a *different* reason, at a *later* stage than the one before. Understanding all three is the only way to know why the shipped design looks the way it does — and why its own deny branch isn't expected to ever safely turn on for this hardware.

**Attempt 1 — resolve the real exe path in-kernel via a manual `task->mm->exe_file` walk, pass it to the classic `bpf_d_path()` helper.** This is the natural design: `bpf_get_current_task_btf()` gives a verifier-trusted `struct task_struct*`, so walking `->mm->exe_file` and handing the result to `bpf_d_path()` looks like it should just work. It doesn't: the BPF verifier drops pointer trust after the *second* pointer hop from a trusted anchor (`task->mm`, then `mm->exe_file`), and `bpf_d_path()` refuses anything but a trusted, RCU, or hook-argument-provided pointer (`kernel/trace/bpf_trace.c`'s `bpf_d_path_allowed()`). Rejected at `BPF_PROG_LOAD` with `R1 type=untrusted_ptr_ expected=ptr_, trusted_ptr_, rcu_ptr_`.

**Attempt 2 — the kernel's own recommended fix: `bpf_get_task_exe_file()` + `bpf_path_d_path()`.** The kernel's actual selftests for this exact problem (`tools/testing/selftests/bpf/progs/verifier_vfs_accept.c`) show the intended solution: `bpf_get_task_exe_file(task)` is a *kfunc* that does the trusted walk internally and returns an acquired (refcounted, trusted) `struct file*`; `bpf_path_d_path()` is kernel/fs/bpf_fs_kfuncs.c's own explicitly-documented "safer variant... should be used in place of `bpf_d_path()` whenever possible." This passes verification cleanly. It still fails — one layer deeper, at load time, with `-ENOTSUPP: JIT does not support calling kernel function`. Both `bpf_get_task_exe_file()` and `bpf_path_d_path()` are **kfuncs**, not classic numbered helpers, and the ARM32 BPF JIT (`arch/arm/net/bpf_jit_32.c`) has never implemented kfunc-call codegen — a real, current architecture gap, not a config option. (`bpf_d_path()`, the *classic helper* used in attempt 1, has no such problem — the JIT call mechanism for numbered helpers works fine there; only kfunc calls don't.)

**Attempt 3 (shipped) — do the strong check in userspace instead, keep the BPF side to what a classic helper can verify and JIT.** Since kfuncs are unusable here, in-kernel real-exe-path resolution is unusable here — full stop, not just for THIS hook's exact code shape. The BPF side (`lsm_cert_guard.bpf.h`) keeps to classic helpers only: it filters on the exact cert-file path (`bpf_d_path()` against `file->f_path` — a hook-argument-provided pointer, still trusted, still just a classic helper call, so this part of attempt 1 was never the problem) and reports PID/comm/cgroup, plus a coarse comm-based pre-check. `LsmCertGuardProgram::parseEvent()` (userspace) then does the real check via `/proc/<pid>/exe` — a plain `readlink()`, no BPF involved at all — exactly mirroring how `ssl_uprobe/proc_peer_resolver.hpp` already resolves socket info a uprobe can't see directly. `CertAccessDetector` classifies on that userspace-resolved field, not the BPF-side comm check.

Then a **fourth, even more fundamental problem** surfaced, independent of any of the above: attaching *any* `BPF_PROG_TYPE_LSM` program — regardless of what it does internally — requires the kernel's BPF trampoline mechanism (the same one `fentry`/`fexit` use), and ARM32 has no `arch_prepare_bpf_trampoline()` implementation at all (confirmed by its total absence from `arch/arm/net/`, versus present implementations in `arch/{arm64,x86,riscv,s390,powerpc,loongarch,parisc}/net/`). `bpf_program__attach_lsm()` fails with `-ENOTSUPP` on this specific hardware (AST2600, ARMv7/ARM32) no matter how the program is written. See [What actually enforces, on this hardware](#what-actually-enforces-on-this-hardware) below.

## What's hooked, concretely

- **Hook point:** the `file_open` LSM hook (`security_file_open` in kernel terms) — fires for *every* file opened on the system, filtered down in the BPF program itself to one exact path.
- **BPF program:** `SEC("lsm.s/file_open")` (`https_guard_cert_open` in `lsm_cert_guard.bpf.h`) — the `.s` marks it sleepable, required because `bpf_d_path()` is only reachable from sleepable LSM hooks (`kernel/bpf/bpf_lsm.c`'s `sleepable_lsm_hooks` allowlist includes `file_open`).
- **Target path:** `/etc/ssl/certs/https/server.pem` (confirmed against bmcweb's actual source, `include/hostname_monitor.hpp`, not assumed).
- **Expected accessor:** `/usr/bin/bmcweb` (confirmed against bmcweb's actual installed binary path in this Yocto build, not assumed).
- **Attach:** `bpf_program__attach_lsm(prog)`. Non-fatal on failure, same degrade-gracefully pattern `xdp_tls` already uses for XDP unavailability — see the next section for why this always fails on the project's actual target hardware.
- **Raw event struct:** `struct lsm_cert_guard_event` in `lsm_cert_guard_event.h` — PID/tgid/cgroup/comm/timestamp and a weak `comm_mismatch` flag. Deliberately carries no exe-path field; that's resolved entirely in userspace.

## What actually enforces, on this hardware

```
file_open(cert file) ──► https_guard_cert_open (BPF, in-kernel)
                              │
                              │  comm == "bmcweb"?  (weak, spoofable —
                              │  exists only so shadow_mode has a real
                              │  branch to gate, not a fiction)
                              │
                    shadow_mode (const volatile bool, always true —
                    nothing in this hook ever flips it)
                              │
                    ┌─────────┴─────────┐
                    │ true (always)     │ false (dead code today)
                    ▼                   ▼
              return 0 (allow)    comm_ok ? 0 : -EACCES
              regardless of            (never reached — and even if
              comm_ok                  reached, only as strong as
                                        the spoofable comm check)
                              │
                              ▼  (ring buffer, regardless of shadow_mode)
                  LsmCertGuardProgram::parseEvent()
                              │
                              │  readlink("/proc/<pid>/exe")  — the
                              │  REAL check, but async: the open()
                              │  has already returned by now
                              ▼
                  CertAccessDetector: real_exe_path != "/usr/bin/bmcweb"?
                              │
                              ▼
                  Verdict{Critical, actionable=false} → Redfish log only
```

Two separate, independent reasons this can currently only alert, never block, on the project's actual target (AST2600/ARM32):

1. **The strong check is asynchronous by construction.** Even if the BPF hook itself attached, the real identity check happens in userspace after the file is already open — there's no way to retroactively deny an `open()` that already succeeded.
2. **The hook can't attach at all on this architecture.** `bpf_program__attach_lsm()` returns `-ENOTSUPP` — ARM32 has no BPF trampoline support, and LSM program attach fundamentally requires one. This is independent of (1): even a hook that only ever intended to be observational still can't get onto this platform's file_open path via BPF LSM at all.

Reason 2 is the one worth being unambiguous about: it is not a bug in this hook, not something a different BPF program shape fixes, and not something this ticket can close. A synchronous, in-kernel deny for this specific check is not achievable on this hardware with BPF LSM, period.

## Rollout plan (shadow mode → enforcement)

Given the above, "flipping shadow mode off" is not a meaningful next step *for this hardware* — there is no reachable enforcement to flip on; the hook cannot attach at all, so shadow_mode's value is moot there. The plan going forward:

1. **On this hardware:** treat this hook as alert-only, permanently, until proven otherwise. `CertAccessDetector`'s Critical verdict (Redfish-logged) is the actual security value here — an operator or SIEM sees "an unrecognized process opened the HTTPS private key" and can act (rotate the key, investigate the process), even though the kernel itself couldn't stop the read.
2. **On a platform where LSM attach succeeds** (anything with BPF trampoline support — arm64, x86_64, several others; see [How to detect](#how-to-detect--three-attempts-in-the-order-they-were-actually-tried)) shadow_mode's deny branch *would* become reachable, but should still not be flipped on as-is: it's currently gated on the weak comm check, the exact signal this ticket set out to move beyond. Making it trustworthy there would mean re-attempting attempt 2's kfunc-based real-path check, since kfunc-call JIT support is a genuine per-architecture capability (arm64/x86_64 do support it) rather than the universal gap ARM32 has.
3. **If real-time denial on this exact hardware is ever required**, it would need a fundamentally different mechanism than BPF LSM — e.g. a small non-BPF LSM kernel module, or restricting the file via a completely separate access-control layer (permissions, a mandatory-access-control policy) that doesn't depend on BPF trampoline support at all. That's a new investigation, not a variation of this hook.

## Known limitations

- **No synchronous enforcement on this project's actual target**, for the two independent reasons above — this is the hook's central, load-bearing limitation, not a footnote.
- **The BPF-side comm check is exactly as spoofable as `ssl_uprobe`'s.** It exists only to keep the shadow-mode mechanics real rather than fictional; it is not, and should not be treated as, the "stronger" check this hook exists to provide.
- **The userspace `/proc/<pid>/exe` check can race a short-lived process.** If the accessing process has already exited by the time `parseEvent()` runs, the `readlink()` fails and `real_exe_path` comes back empty — treated as a mismatch (see the comment in `LsmCertGuardProgram.cpp`), which means a sufficiently fast open-then-exit could still get logged as a violation with an empty resolved path, worth knowing when reading the Redfish message rather than assuming a nonempty path was always resolved.

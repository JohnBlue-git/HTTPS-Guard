# 09 — XDP attachment leaks across daemon restarts, silently disabling wire-level detection

**What to build:** Make the XDP program detach when the daemon stops, so restarting the daemon restores wire-level detection instead of permanently losing it until the next reboot.

**Blocked by:** None — can start immediately

**Status:** done

## The bug

`XdpTlsProgram::attach()` attaches via `bpf_xdp_attach()`, which — unlike `bpf_program__attach_uprobe_opts()` / `bpf_program__attach_lsm()` — produces no `bpf_link`. The code acknowledges this by pushing a placeholder:

```cpp
links.push_back(nullptr);  /* placeholder: bpf_xdp_attach has no link */
```

The orchestrator's teardown closes `bpf_link`s, so there is nothing for it to close here, and an `bpf_xdp_attach()` attachment is owned by the *netdev*, not the process — it outlives the daemon. On the next start, `bpf_xdp_attach()` is called with `XDP_FLAGS_UPDATE_IF_NOEXIST` against an interface that already has a program attached, and both the native and generic attempts fail:

```
libbpf: Kernel error message: XDP program already attached
https_guard: failed to attach XDP program to ifindex 2 (non-fatal, continuing with uprobe only):
  native XDP: Device or resource busy
  generic XDP: Device or resource busy
https_guard: enforcement active via 1 of 3 hook(s)
```

## Why this matters more than it looks

The failure is non-fatal by design (correct — one dead hook shouldn't take the daemon down), so the daemon comes up `active` and keeps working on the uprobes. But everything that only XDP can see is now gone, silently:

- TLS ClientHello inspection — so `TlsVersionDetector`'s wire-level path, plus the `CipherSuiteDetector` and `SniDetector` added in ticket 04, all stop firing.
- The synchronous `XDP_DROP` blocklist enforcement — the only enforcement path in the project that actually works today (see ticket 08 for why TCP-kill doesn't).

So a single `systemctl restart https-guard-daemon` — routine after a config change — degrades the tool to uprobe-only until someone reboots the BMC, while still reporting itself healthy. On the target image there is no easy manual recovery either: BusyBox `ip` doesn't support XDP detach and `bpftool` isn't installed, so a reboot is the only way back.

## Evidence

Observed live on QEMU during ticket 04 verification. The first successful daemon start attached XDP in native mode; a later stop/start cycle on the same boot then hit "XDP program already attached" and ran at 1 of 3 hooks. Confirmed the stale program is the cause: nothing else had claimed the interface, and a fresh boot attaches cleanly again.

- [x] Stopping the daemon detaches its XDP program, so a restart attaches successfully on the same boot with no manual intervention
- [x] Verified across at least two stop/start cycles on one QEMU boot that the log reports the full hook count each time (not `1 of 3`), and that a wire-level detection actually fires after the restart — a successful attach log line alone isn't sufficient, given this bug's whole character is "reports healthy while broken"
- [x] Decide and document how a *stale* attachment from a previously-crashed daemon is handled — detaching unconditionally at startup would recover automatically but could stomp a different tool's XDP program on a shared interface, so this is a real trade-off worth stating rather than picking silently
- [x] The `links.push_back(nullptr)` placeholder either goes away or is replaced by something the teardown path can genuinely act on; a `nullptr` that silently means "nothing to clean up" is what allowed this to go unnoticed
- [x] Consider whether `bpf_link`-based XDP attach (`bpf_program__attach_xdp()`) is available and preferable on the target kernel — it would make the lifetime process-owned and this class of leak structurally impossible, rather than needing explicit cleanup

## Reconfirmed

Reproduced again while verifying ticket 11 (a `systemctl restart` during that
run): uprobes re-attached, XDP did not, and the daemon reported
`enforcement active via 1 of 3 hook(s)` while `systemctl is-active` said
`active`. The "reports healthy while degraded" character of this bug is
exactly as described above.

## Implementation

**Primary fix: attach via a BPF link.** `bpf_program__attach_xdp()` returns a
real `bpf_link*`, and the kernel then owns the attachment's lifetime — when
the link fd closes the program is detached, including on a crash or SIGKILL,
where no destructor would ever run. Confirmed available on this target:
`net/core/dev.c` has `bpf_xdp_link` and the sysroot's libbpf exports
`bpf_program__attach_xdp`. This makes the leak structurally impossible rather
than something that has to be remembered, which also disposes of the
`links.push_back(nullptr)` placeholder — the link pushed now is genuine and
the existing teardown path closes it like any other.

**The legacy path is kept as a fallback** for kernels without XDP link
support, and only in that case does the destructor detach explicitly.
Recorded honestly in the class comment: that covers clean shutdown but not a
crash, which is precisely why it isn't the first choice.

**Stale attachments: identify before removing.** The ticket flagged
force-detaching as a real trade-off, and it is — clearing whatever happens to
be on the interface would swap our own outage for another tool's. So
`clearStaleAttachment()` queries the interface (`bpf_xdp_query`), resolves the
attached program (`bpf_prog_get_fd_by_id` → `bpf_prog_get_info_by_fd`) and
compares its name:

- name is `https_guard_xdp` → a leaked instance of *us*, from before this
  change or from a legacy-path daemon that was killed. Detach it and continue.
- anything else → log what is there and leave it alone.
- unidentifiable → leave it alone and say so.

That recovers automatically from our own leaks without ever touching someone
else's program, which is the behaviour the trade-off called for rather than
picking one horn of it.

## Verified on QEMU

One boot, then two `systemctl restart` cycles:

```
link attaches:              3
already-attached failures:  0
enforcement active via 2 of 3   (x3 — boot and both restarts)
```

Previously the second start onward reported `1 of 3` and stayed that way
until reboot.

Then the part the ticket insisted on, because a successful attach line is
exactly what this bug used to fake: a crafted weak-cipher ClientHello sent
*after* both restarts produced

```
xdp event received: ... cipher_suites=3/3, sni='bmc.example.com'
"MessageId":"OemSecurityEvent.1.0.HttpsWeakCipherSuiteDetected"
```

`HttpsWeakCipherSuiteDetected` can only come from the XDP path, so wire-level
detection is genuinely working post-restart rather than merely claiming to be.

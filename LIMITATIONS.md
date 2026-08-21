# Known limitations

What this tool does **not** do, and what has **not** been proven. Collected
here because the per-ticket notes under `.scratch/` are working records, not
something an operator or a future maintainer will read.

Every entry below is established, not speculative — each was either measured,
traced to kernel source, or observed failing on real hardware.

---

## Platform: the certificate guard cannot enforce on ARM32

`programs/lsm_cert_guard/` is **alert-only** on this project's actual target
(AST2600, ARMv7). Two independent reasons, both in the architecture rather
than in this code:

- `BPF_PROG_TYPE_LSM` attach requires the BPF trampoline mechanism, and
  `arch/arm/net/` never implemented `arch_prepare_bpf_trampoline()` — it is
  present for arm64, x86, riscv, s390, powerpc, loongarch and parisc, and
  absent for arm. `bpf_program__attach_lsm()` therefore returns `-ENOTSUPP`
  and the hook does not attach at all.
- The ARM32 BPF JIT cannot emit kfunc calls, so the kernel's own recommended
  way to resolve a process's real executable in-kernel
  (`bpf_get_task_exe_file()` + `bpf_path_d_path()`) fails to load even though
  it passes verification.

Consequence: the identity check runs in userspace from `/proc/<pid>/exe`,
after the file has already been opened. The hook can report that an
unrecognised process read the HTTPS private key; it cannot prevent it. On a
platform with trampoline support the hook attaches, but its deny branch is
still gated on a spoofable `comm` check and should not be enabled as-is.

## Detection coverage

- **Payload inspection is capped at 127 bytes per call.** A signature that
  falls entirely past that offset in a single `SSL_write`/`SSL_read` is not
  seen. Observed directly: a signature placed in a late request header did
  not match, while the same signature early in the request path did.
- **ClientHello capture is capped** at 32 cipher suites and 63 SNI bytes. The
  true offered count is reported separately so a detector can tell a short
  list from a clipped one, and a partially captured hostname is flagged
  malformed so it can never be compared as though complete.
- **`legacy_version` is not necessarily the negotiated version.** A
  TLS-1.3-capable client sets it to 0x0303 and signals the real version in an
  extension this hook does not parse. That is fine for the intended case — a
  genuinely old client has no such fallback — but it means this is not a
  report of what was negotiated.
- **The connection-rate window is fixed at build time** (10s). Only the count
  threshold is configurable; changing the window needs a rebuild.
- **Rate detection only sees the monitored interface.** Loopback traffic never
  traverses XDP, so connections from the BMC to itself are not counted.
- **Clients behind one NAT address share the rate budget**, because the
  counter is keyed on source address. Several busy administrators or a
  monitoring system behind one address can look like one abusive source.

## Attribution and enforcement

- **The blocklist applies to a source address on every port**, not just 443.
  A false positive therefore removes access to *all* BMC services for the
  blocklist TTL (300s). This is why cipher-suite and SNI detection are
  alert-only: making them actionable locked an operator out of SSH during
  testing. Connection-rate detection *is* actionable, deliberately, because a
  flood is ongoing harm — which makes its threshold safety-critical rather
  than a tuning detail.
- **Uprobe events often cannot be attributed to a connection.** A uprobe
  carries no socket identity, so the peer is resolved by intersecting the
  process's owned socket inodes with established connections. When a process
  owns more than one, the event is deliberately left unresolved and
  enforcement declines rather than guessing — acting on the wrong connection
  would blocklist an uninvolved host. Resolving this properly needs the socket
  fd read out of the `SSL` object's `BIO` in BPF.
- **Open question:** during a live request, bmcweb's own file descriptors were
  observed to be unix-domain and listening sockets rather than an established
  TCP socket, so uprobe-path enforcement may rarely resolve for bmcweb at all.
  If that holds, `/proc`-based attribution is the wrong mechanism rather than
  a buggy one. Not yet settled.
- **Connection teardown needs a full 4-tuple.** Verdicts attributed to an
  address rather than a connection (connection-rate violations) blocklist the
  source but cannot tear down a specific socket.
- **`SOCK_DESTROY` requires `CONFIG_INET_DIAG`.** It is enabled in
  `recipes-kernel/linux/bpf-kernel-config.cfg`; on a kernel without it, every
  teardown fails with `-ENOENT` from `sock_diag` before the 4-tuple is even
  examined, which reads misleadingly like "no such socket".

## What has not been verified live

Unit tests cover these; live confirmation on hardware does not. That is a
weaker claim and is recorded as such rather than folded into "verified".

- **`TlsVersionDetector`** — needs a client that actually negotiates below
  TLS 1.2. Never exercised end to end.
- **`CertAccessDetector`** — needs the LSM hook, which cannot attach on ARM32
  (above).
- **Connection-rate true positive at the shipped threshold.** QEMU SLIRP will
  not propagate a rapid connect/close burst to the guest (the highest
  reachable from the host was ~456 in 6s, just under the 500 default), so the
  end-to-end test used a lowered threshold. The mechanism was verified; the
  specific default was not exceeded in testing.
- **`RenegotiationDetector`** — every attempt to drive TLS handshakes through
  the QEMU SLIRP port-forward failed to complete, because holding connections
  open to reach the condition saturates the same forward. Unit-tested, and its
  counter increments from the live-verified ClientHello path, but never
  confirmed end to end.
- **`DetectLoop`'s throughput improvement is reasoned, not measured.** Lazy
  `/proc` enrichment is proven by unit test to run only when asked, and the
  work it removed from the poll thread is known, but no before/after latency
  or drop-rate numbers were taken. Its *scheduling* properties — bounded
  admission, arrival order, and the sweep surviving a backlog — are covered by
  `tests/detectloop/`, which is a separate binary with a documented build
  command rather than part of `https_guard_tests`; see its README for why.

## Observability

- **`ConnRateSweeper`'s `per-source counters: …` line goes to `std::cout`,
  which journald pipes make block-buffered.** Those lines therefore arrive in
  ~4KB batches carrying identical timestamps — sometimes minutes late — and
  the remainder is only flushed when the daemon exits. Every other diagnostic
  uses `std::cerr` and appears immediately. Do not read the absence of a
  recent counters line as "the sweep is not running"; force a flush with
  `systemctl restart https-guard-daemon`, or read the Redfish event log. This
  is a one-line fix that has deliberately not been made, to keep it out of an
  unrelated change.

## Testing environment caveats

- QEMU SLIRP terminates and re-originates TCP, so rapid connect/close bursts
  from the host do not reach the guest as SYNs. Use completed connections when
  exercising anything that counts them.
- The target image has neither `bpftool` nor an `ip` that can detach XDP, so a
  leaked XDP attachment historically needed a reboot to clear. Attachments are
  now `bpf_link`-owned and released by the kernel on process exit, including on
  `SIGKILL`.
- Traffic generated *from* the guest to `127.0.0.1` never traverses XDP. Tests
  for wire-level detection must originate outside the guest.
- **Check which QEMU you are talking to.** A stale instance from an earlier
  session holds its port, so `runqemu` silently bumps the new one (2222 → 2223,
  4433 → 4434) and SSH on 2222 answers from an old image. This produced a
  confident but entirely wrong reading of a fresh build's behaviour once.
  Confirm the image timestamp in the `runqemu` command line, not just that SSH
  responds.
- Holding as few as five connections open through SLIRP hostfwd saturates the
  forward and breaks SSH on that same forward. "SSH dropped" is therefore not
  evidence that a source was blocklisted — the two are indistinguishable from
  outside. Read the journal instead; this was initially misdiagnosed the other
  way round.

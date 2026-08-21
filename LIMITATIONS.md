# Known limitations

What this tool does **not** do — the constraints that come from the platform,
the capture mechanism, or the enforcement model, and which no amount of testing
will change. Collected here because the per-ticket notes under `.scratch/` are
working records, not something an operator or a future maintainer will read.

Every entry below is established, not speculative — each was either measured,
traced to kernel source, or observed failing on real hardware.

**Two related things live in [README.md](README.md) instead, deliberately —
they belong next to the commands they qualify, and duplicating them here would
guarantee the two copies drift apart:**

- **How to trigger each detection**, and which Redfish message ID each
  produces → [Exercising the Detections](README.md#exercising-the-detections)
- **Which rules have been driven end-to-end on hardware** and which are only
  unit-tested, plus the QEMU/SLIRP traps that decide which is which →
  [Verification status](README.md#verification-status) and
  [Test-environment caveats](README.md#test-environment-caveats)

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

## Measurement gaps

- **`DetectLoop`'s throughput improvement is reasoned, not measured.** Lazy
  `/proc` enrichment is proven by unit test to run only when asked, and the work
  it removed from the poll thread is known, but no before/after latency or
  drop-rate numbers were taken. Its *scheduling* properties — bounded
  admission, arrival order, and the sweep surviving a backlog — *are* covered,
  by `tests/detectloop/`; that is a separate binary with a documented build
  command rather than part of `https_guard_tests`, and its README says why.

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

---

*Per-detection trigger recipes, live-verification status, and the QEMU/SLIRP
testing traps are in [README.md](README.md#exercising-the-detections).*

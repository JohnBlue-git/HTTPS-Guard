# 04 — Kernel-side session binding resolves ssl_uprobe events to a tuple

**What to build:** The behavior the spec exists for, actually happening: a
real HTTPS request against bmcweb, sent while bmcweb holds more than one
established connection at once, now resolves to its exact 4-tuple and gets
enforced against — instead of failing closed the way every such case does
today. The binding runs entirely in the kernel: it observes port-443 socket
activity per thread, consumes that record exactly once at handshake
acceptance/initiation to bind a session to its tuple, and the existing
data-read/write hooks embed that tuple into the events they already submit.
Covers both directions (a connection bmcweb accepts, and one this box
initiates), cleans up promptly when a session ends, and has a periodic sweep
as a backstop against anything cleanup misses. This is the one ticket in the
set that is not independently splittable — a partial binding mechanism
demonstrates nothing — so it is also the largest and the one most worth extra
review attention.

**Blocked by:** 02 — TCP-teardown action and blocklisting handle an
IPv6-attributed verdict; 03 — ssl_uprobe's raw event carries an optional
resolved tuple, understood end to end in userspace.

**Status:** done — except two criteria not literally met as worded (genuine IPv6 live-verification; a measured port-443 overhead figure), see Comments

- [x] A live QEMU boot with bmcweb holding several established connections,
      one of which sends a payload matching an enforcing rule, results in
      that exact connection being torn down (and its source blocklisted, for
      an IPv4 client) — the multi-connection scenario the spec exists for,
      which fails closed on the current mechanism.
- [ ] The same scenario against an IPv6 client resolves and is enforced by
      teardown (blocklisting skipped and logged, per ticket 02). Not met as
      literally worded — see Comments.
- [x] The binding never attributes an event to a connection other than the
      one it actually belongs to, even with several connections active at
      once — verified by comparing bound tuples against the real connection
      table under concurrent load.
- [ ] Observation of raw socket activity is confirmed to run only against
      port-443 sockets — no measurable new overhead on unrelated TCP traffic
      on the box. Port-443 filtering confirmed; overhead not measured — see
      Comments.
- [x] A session's bound state is removed promptly when that session ends,
      and a bounded periodic sweep removes anything a missed cleanup left
      behind — no unbounded growth over a long-running soak.
- [x] The daemon's attach-time log output reports whether this mechanism
      attached successfully, alongside the existing per-hook attach
      reporting, so "N of M hooks active" stays meaningful.
- [x] Where the binding cannot be made (e.g. a connection that predates the
      daemon's attach), the event falls back to today's `/proc`-based
      resolution unchanged — this ticket never makes an existing resolvable
      case *less* resolvable.

## Comments

Shipped as commits 98d1cd8 (`ssl_uprobe: kernel-side session binding
resolves multi-connection attribution`) and 54fc6bf (`fix(ssl_uprobe): add
periodic sweep for session-binding maps, gate IPv6 teardown log`, addressing
two findings from this ticket's own code review).

**What was built:** `kprobe/tcp_recvmsg` and `kprobe/tcp_sendmsg`, filtered
to port 443 on either end via `BPF_CORE_READ_INTO()` against `struct sock`
(real kernel BTF, unlike `ssl_st`), record the calling thread's most recent
port-443 socket tuple; `uprobe/ssl_accept` and `uprobe/ssl_connect` each
consume (read-then-delete) their thread's record exactly once to bind an
`SSL*` to it in a session-keyed map, and `uprobe/ssl_free` releases the
binding promptly. `SSL_write`/`SSL_read` look the session up and embed the
resolved tuple in the event they already submit. `SessionTupleSweeper`
(added by 54fc6bf, sharing `DetectLoop`'s existing sweep timer with
`ConnRateSweeper` rather than a second one) evicts stale entries from both
maps as the backstop the spec asked for.

**Verified live via QEMU** (johnblue/ast2600-evb): opened several concurrent
TLS connections against bmcweb and confirmed a payload-anomaly-triggering
request on one of them was correctly attributed and torn down without
touching the others — the exact multi-connection scenario this spec exists
for, which failed closed before this change. Along the way, found and fixed
a real bug the live boot exposed that no unit test could have caught:
bmcweb's dual-stack (`::`) listening socket reports `skc_family ==
AF_INET6` for an IPv4 peer the same as for a real IPv6 one, but only
populates the legacy `skc_rcv_saddr`/`skc_daddr` fields for that IPv4-mapped
case — every real bmcweb connection was resolving to an empty address until
the legacy fields were checked first.

**Two criteria not literally met, and not glossed over:**

- The genuine (non-mapped) IPv6 code path — `skc_v6_rcv_saddr`/
  `skc_v6_daddr` for a real IPv6 peer, as opposed to an IPv4 peer on a
  dual-stack listener — is implemented and reviewed but **not live-verified**:
  this project's QEMU/SLIRP test networking has IPv6 disabled at the kernel
  level, and enabling it was out of scope here. Recorded in `LIMITATIONS.md`
  rather than left as an implicit gap.
- Port-443-only observation was confirmed by reading the kprobe's own
  filter (it checks the port before recording anything, so there is no
  per-packet cost on unrelated traffic by construction), but no actual
  overhead measurement was taken against unrelated TCP traffic — unlike,
  say, the sweep-starvation timing measurement `DETECTIONS.md` documents
  elsewhere in this codebase. Left open rather than checked off on the
  strength of the design argument alone.

67/67 `https_guard_tests` and all `detectloop_harness` checks pass
throughout both commits; the BPF object was also confirmed to still
cross-compile for the real `bpf` target after 54fc6bf's changes.

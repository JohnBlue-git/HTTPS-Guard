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

**Status:** ready-for-agent

- [ ] A live QEMU boot with bmcweb holding several established connections,
      one of which sends a payload matching an enforcing rule, results in
      that exact connection being torn down (and its source blocklisted, for
      an IPv4 client) — the multi-connection scenario the spec exists for,
      which fails closed on the current mechanism.
- [ ] The same scenario against an IPv6 client resolves and is enforced by
      teardown (blocklisting skipped and logged, per ticket 02).
- [ ] The binding never attributes an event to a connection other than the
      one it actually belongs to, even with several connections active at
      once — verified by comparing bound tuples against the real connection
      table under concurrent load.
- [ ] Observation of raw socket activity is confirmed to run only against
      port-443 sockets — no measurable new overhead on unrelated TCP traffic
      on the box.
- [ ] A session's bound state is removed promptly when that session ends,
      and a bounded periodic sweep removes anything a missed cleanup left
      behind — no unbounded growth over a long-running soak.
- [ ] The daemon's attach-time log output reports whether this mechanism
      attached successfully, alongside the existing per-hook attach
      reporting, so "N of M hooks active" stays meaningful.
- [ ] Where the binding cannot be made (e.g. a connection that predates the
      daemon's attach), the event falls back to today's `/proc`-based
      resolution unchanged — this ticket never makes an existing resolvable
      case *less* resolvable.

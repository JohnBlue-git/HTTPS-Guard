# 03 — ssl_uprobe's raw event carries an optional resolved tuple, understood end to end in userspace

**What to build:** The wire format between the ssl_uprobe hook's BPF program
and the daemon can carry a resolved connection tuple. When one is present,
the daemon uses it directly with no resolver call — extending today's
"already resolved" contract (currently only exercised by wire-hook events) to
ssl_uprobe events too. When absent, today's `/proc`-based fallback runs
exactly as it does now. Nothing in the kernel populates this tuple yet, so
real-world behavior is unchanged after this ticket — every live event still
arrives with an absent tuple until the kernel-side binding ships. Verified
entirely host-side with hand-built raw events.

**Blocked by:** 01 — Shared event metadata carries a dual-stack connection
tuple.

**Status:** ready-for-agent

- [ ] The raw uprobe event's wire format can carry an address-family tag, a
      dual-stack address, and both ports, defaulting to absent.
- [ ] Given a hand-built raw event with a present tuple, the fill step
      populates the shared event metadata directly and leaves it in the
      "already resolved" state (no resolver call made).
- [ ] Given a hand-built raw event with an absent tuple, the fill step
      preserves today's resolver-based fallback behavior unchanged.
- [ ] Both IPv4-shaped and IPv6-shaped present-tuple cases are covered by
      tests, alongside the existing absent-tuple case.
- [ ] No kernel/BPF change is required for this ticket to be verifiable —
      all new coverage runs host-side, same as the rest of this test suite.

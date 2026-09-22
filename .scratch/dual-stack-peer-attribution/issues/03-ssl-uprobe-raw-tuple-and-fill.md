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

**Status:** done

- [x] The raw uprobe event's wire format can carry an address-family tag, a
      dual-stack address, and both ports, defaulting to absent.
- [x] Given a hand-built raw event with a present tuple, the fill step
      populates the shared event metadata directly and leaves it in the
      "already resolved" state (no resolver call made).
- [x] Given a hand-built raw event with an absent tuple, the fill step
      preserves today's resolver-based fallback behavior unchanged.
- [x] Both IPv4-shaped and IPv6-shaped present-tuple cases are covered by
      tests, alongside the existing absent-tuple case.
- [x] No kernel/BPF change is required for this ticket to be verifiable —
      all new coverage runs host-side, same as the rest of this test suite.

## Comments

Shipped as commit 21377ac (`ssl_uprobe: raw event can carry a resolved
tuple, wired through to EventMeta`). `uprobe_event` gained `hg_uprobe_conn`
— a connection tuple gated by an explicit `resolved` flag rather than
inferred from an all-zero address, 16 address bytes regardless of family,
matching `EventMeta::IpAddress`. A new `HasResolvedConnectionTuple` concept
(distinct from the wire hook's unconditional `HasConnectionTuple`) and
`fillResolvedConnection()` give the three uprobe-serving detection
templates (`traffic_observed`, `tls_version`, `payload_anomaly`) a third
branch: present → populate `EventMeta` directly and leave its resolver
unset (extending today's "already resolved" contract to `ssl_uprobe`);
absent → today's `/proc`-based fallback, byte-for-byte unchanged. Nothing
in the kernel populates the tuple yet at this point (that is ticket 04), so
every real event still arrived unresolved and production behavior was
unchanged by this ticket alone. Tests: extended
`tests/core/event_meta_test.cpp` with hand-built `uprobe_event` cases
(present-and-v4, present-and-v6, absent) — no kernel/BPF required, matching
this suite's existing constraints. Verified via ptest cross-compile +
qemu-arm: 67/67 `https_guard_tests` and all `detectloop_harness` checks
passed.

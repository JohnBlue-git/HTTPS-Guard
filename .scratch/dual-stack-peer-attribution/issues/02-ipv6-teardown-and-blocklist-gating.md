# 02 — TCP-teardown action and blocklisting handle an IPv6-attributed verdict

**What to build:** Given a verdict attributed to an IPv6 connection, the
daemon can tear down that exact TCP connection. Since the blocklist map is
staying IPv4-only (agreed out of scope for this effort), an IPv6-attributed
actionable verdict is enforced by teardown alone — dispatch recognizes it
cannot also add an IPv6 source to the IPv4-only blocklist map and says so in
its log output, rather than silently skipping enforcement entirely or
misusing the map. The teardown request's field-population logic is
unit-tested for both address families without opening a real netlink socket
— this code has zero tests today.

**Blocked by:** 01 — Shared event metadata carries a dual-stack connection
tuple.

**Status:** done

- [x] Given a dual-stack tuple, the teardown action selects the correct
      address family and constructs a request the kernel's socket
      diagnostics API accepts, for both IPv4 and IPv6.
- [x] Given an IPv6-attributed actionable verdict, the daemon tears down the
      connection and logs that blocklisting was skipped for that source
      (map is IPv4-only) — not silent, and not a crash or corrupted map
      entry.
- [x] Given an IPv4-attributed actionable verdict, both teardown and
      blocklisting still happen exactly as today.
- [x] The teardown request's field-population is unit-tested in isolation
      from the real socket, covering both address families and the existing
      IPv4 byte-order/field cases this file's own history warns about
      (address byte order, port byte order, local/remote orientation).

## Comments

Shipped as commit 7a4c4fd (`actions/tcp: dual-stack teardown; dispatch gates
blocklisting on family`). `TcpDestroyer`/`BlockTcpAction` now take a family
flag plus 16-byte dual-stack addresses instead of a bare `uint32_t`; the
netlink request's field population was pulled into a pure static
`TcpDestroyer::populateRequest()` with no socket, specifically so this
logic — wrong twice before, silently — finally has tests. `dispatchVerdict()`
builds the teardown for either family; the blocklist BPF map stays
IPv4-only, and an IPv6-attributed verdict now logs that blocklisting was
skipped rather than leaving it silent (later refined by commit 54fc6bf to
only claim "connection teardown still applies" when a full tuple was
actually available). Tests: new `tests/actions/tcp_destroyer_test.cpp`
exercises `populateRequest()` directly — family selection, local/remote
orientation, port byte order, the all-ones cookie — with no real socket;
this file had zero tests before. Verified via ptest cross-compile +
qemu-arm: 64/64 `https_guard_tests` and all `detectloop_harness` checks
passed.

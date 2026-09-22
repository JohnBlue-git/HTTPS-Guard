# 01 — Shared event metadata carries a dual-stack connection tuple

**What to build:** The connection tuple carried on the shared event-metadata
type (and anything that already carries one) can represent either an IPv4 or
an IPv6 address, tagged explicitly by family. Every existing producer — the
wire hook, the `/proc`-based fallback, the rate-sweep synthesized events —
keeps populating it as IPv4, and every existing consumer (logging, Redfish
message text, enforcement) behaves byte-for-byte identically to today. This
is representation work only: no new attribution capability yet, just room
for the tickets that add it.

**Blocked by:** None — can start immediately.

**Status:** done

- [x] The shared event-metadata type's connection tuple can hold either
      address family, tagged explicitly rather than assumed.
- [x] Every existing call site that reads or writes the IPv4 tuple compiles
      against the new representation with no behavior change.
- [x] Existing tests for the shared event-metadata type and every detection
      pass unmodified.
- [x] New tests confirm the IPv4 shape round-trips identically to before
      (same fields, same values, same byte order) through the new
      representation.

## Comments

Shipped as commit f5d55d0 (`detections: EventMeta's connection tuple is
dual-stack, tagged by family`). `EventMeta::IpAddress` (family tag + 16 bytes,
network byte order, `setV4()`/`v4()`/`isSet()`) replaces the plain
`local_ip_v4`/`remote_ip_v4` fields; every existing producer (XDP fill, the
`/proc`-based uprobe fallback, the three rate-sweep synthesized events) keeps
populating it as IPv4 via the same accessors, so production behavior is
unchanged — this ticket is representation work only, exactly as scoped.
`dispatch.cpp` already gained the family check ahead of ticket 02 needing it.
Verified via the real ptest cross-compile + qemu-arm run: 59/59
`https_guard_tests` and all `detectloop_harness` checks passed, including the
new `IpAddressTest` v4-round-trip and v6-representability cases.

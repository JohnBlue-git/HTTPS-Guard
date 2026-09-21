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

**Status:** ready-for-agent

- [ ] The shared event-metadata type's connection tuple can hold either
      address family, tagged explicitly rather than assumed.
- [ ] Every existing call site that reads or writes the IPv4 tuple compiles
      against the new representation with no behavior change.
- [ ] Existing tests for the shared event-metadata type and every detection
      pass unmodified.
- [ ] New tests confirm the IPv4 shape round-trips identically to before
      (same fields, same values, same byte order) through the new
      representation.

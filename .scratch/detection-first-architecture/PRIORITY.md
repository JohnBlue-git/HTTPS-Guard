# Ticket priority — detection-first architecture

Strict dependency order. The chain is real: each ticket rewrites call sites the
next one touches, and reordering means editing the same includes and CMake
wiring twice — the cost ticket 12 of the previous spec already paid.

| Order | Ticket | Why here |
|---|---|---|
| ✅ | **01** — DetectLoop singleton + runner | Everything depends on it: `BpfProgram`'s default handler needs somewhere to submit without an injected reference. Self-contained, no type changes. |
| ✅ | **02** — Hooks inherit BpfProgram | Needs 01's singleton. Carries the one hard constraint in this spec: one BPF object, one ring buffer, one blocklist map. |
| ✅ | **03** — EventMeta composition | Deletes the `hg_event` base. Sequenced after 02 because both rewrite the same call sites. |
| ✅ | **04** — Concepts replace capability interfaces | Needs 03's structs. Turns a runtime decline into a compile error. |
| ✅ | **05** — Registered typed handlers | The point of the whole spec: type known once, statically, end to end. Needs 03 and 04. |
| ✅ | **06** — Move events + parsing into `detections/` | Structural, no behaviour change. Last of the code tickets deliberately. |
| ✅ | **07** — Per-detection DESIGN.md | Docs should describe the arrangement that already exists. |
| ✅ | **08** — Documentation pass | Blocked by construction; doing it earlier means doing it twice. |

## Where things stand

| | Count | Tickets |
|---|---|---|
| done | 8 | 01–08 |
| remaining | 0 | — all tickets closed |

## Two decisions already taken, recorded in the spec

- **Parsing does not move onto the poll thread.** The request asks for parsing
  "within ringBufferCallback" *and* for that callback to "only submit". The
  second wins: ticket 11 established by measurement that a slow callback drops
  events. Handlers are registered with `DetectLoop` and run on its thread.
- **Hooks inherit `BpfProgram` but stop owning the BPF object.** Three hooks
  each owning an object means three blocklist maps, and enforcement writes the
  map XDP reads. The object moves to `HttpGuardProgram`.

## Risk worth naming up front

This spec removes the mechanism (`dynamic_cast` through a common base) that
currently makes a mis-typed event *decline* at runtime. Statically typed
dispatch is better, but during the transition a handler registered against the
wrong source would silently process garbage rather than declining. The
discriminator check and the "unknown event_source" report are the guard, and
every ticket ends by comparing QEMU message IDs against the recorded baseline:
**2 weak-cipher, 2 SNI-anomaly, 1 traffic-observed** across the five
ClientHello cases, plus a uprobe payload anomaly tearing down a live connection.

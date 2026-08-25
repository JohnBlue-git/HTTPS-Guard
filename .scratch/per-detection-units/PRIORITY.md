# Ticket priority — per-detection units

A single ticket, because the change is one coherent move: `submit()` taking a
detection list, hooks declaring their own, and `detections/sources/` dissolving
into the family directories are the same edit seen from three angles. Splitting
them would have produced intermediate states that do not compile.

| Order | Ticket | Why |
|---|---|---|
| ✅ | **01** — Each detection parses and evaluates itself; hooks declare their list | The last structural step: a detection directory now holds everything about that detection, and a hook names the ones it can feed. |

| | Count | Tickets |
|---|---|---|
| done | 1 | 01 |
| remaining | 0 | — |

## What this closed out, across four specs

`split-hooks-and-detectors` (4) → `extend-detection-coverage` (20) →
`detection-first-architecture` (8) → this (1). The arc: one god-object event and
inline classification, to a base class plus capability interfaces, to concepts
plus per-source handlers, to one directory per detection owning its event, its
parse, its rule and its document.

Two things were deleted along the way that had each been the right answer
earlier — the capability interfaces, then the concepts that replaced them. Both
went when the reason they existed stopped applying, rather than being kept as
ceremony, and both removals are recorded with the reasoning in their tickets.

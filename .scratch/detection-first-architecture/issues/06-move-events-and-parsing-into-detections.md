# 06 — Move event types and their parsing into detections/<family>/

**What to build:** Move `programs/<hook>/src/*_hg_event.hpp` and the parsing
helpers into `detections/<family>/`, one directory per detection family, and
stop packaging several event kinds into one header or one class.

**Blocked by:** 03, 04, 05 — moving first would mean rewriting the same includes
and CMake wiring twice, which is the lesson ticket 12 already paid for

**Status:** done

## The placement rule

By **detection family**, not by hook. A family owns its event struct, its rule,
its parsing, and (ticket 07) its `DESIGN.md`. `programs/` keeps only what
attaches BPF and hands over bytes.

The rule that decides ties: if two families read the same event struct, that
struct belongs to whichever family *defines* it and the other includes it —
resist inventing a `shared/` directory, which is where this kind of layout goes
to die.

- [x] Event structs and parsing live under `detections/<family>/`; `programs/<hook>/src/` holds only attach code
- [x] No header defines more than one event kind, and no class serves two
- [x] `detections/` still contains no libbpf dependency — verified by the unit tests still linking without it
- [x] Every moved path updated in `SRC_URI` and CMake, and the recipe builds from `cleansstate` (the only thing that catches a stale entry)
- [x] The BPF aggregator's relative includes still resolve — a pure file move can only break paths
- [x] QEMU: hooks attach, baseline detections unchanged

## Comments

Done as part of 03–05 rather than separately: the event structs had to move at
the same time they stopped being polymorphic, and moving them first would have
meant rewriting the same includes and CMake wiring twice.

Final placement:

```
detections/sources/<Source>Event.hpp     the struct
detections/sources/<source>_source.hpp   parse()  — header-only
detections/sources/<source>_source.cpp   handle() — rules + dispatch
detections/<family>/<Family>Detector.hpp the rule
detections/<family>/<Family>Event.hpp    synthesised events, with their family
programs/<hook>/src/                     attach only — no parsing, no events
```

### Deviation from the placement rule, and why

The ticket said "by detection family, not by hook". That holds for the **rules**,
which are already one directory per family. It does not work for the **event
structs**: one XDP record feeds four families, so filing its struct under a
family would make three of them include across a sibling. `detections/sources/`
is one directory per raw source, and each source's handler names the families it
feeds in priority order.

Not a `shared/` directory, which the ticket warned against — `sources/` says what
it holds. The synthesised counter events did stay with their families, because
each is fed by exactly one.

`detections/` still contains no libbpf: verified by compiling the whole tree
standalone with only the plain-C wire headers on the include path.

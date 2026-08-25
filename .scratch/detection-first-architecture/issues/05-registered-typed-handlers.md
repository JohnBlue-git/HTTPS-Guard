# 05 — DetectLoop dispatches through registered typed handlers

**What to build:** Replace the `DetectorRegistry` + `dynamic_cast` dispatch with
a **registered list of handlers**, one per `hg_event_source`. Each handler owns
the whole chain for its own type: parse the raw record, run that type's rules,
dispatch actions. `DetectLoop` picks a handler by the discriminator word it
already reads at offset 0.

**Blocked by:** 03, 04

**Status:** done

## What this removes

Today: `submit(raw)` → worker reads `event_source` → finds the owning hook →
`parseEvent()` returns `unique_ptr<hg_event>` → detectors `dynamic_cast` back to
the capability they need. The type is known exactly once, then erased, then
guessed.

After: the composition root registers a handler per source. The handler knows
its own concrete type statically end to end. The discriminator selects a
function, not a downcast.

## Where the parsing runs — and where it must not

Parsing stays **on `DetectLoop`'s thread**, not in the ring-buffer callback. The
callback still only submits. A slow callback lets the ring buffer fill and drops
events, which is a missed detection nothing reports (established by measurement
in ticket 11), and the handlers allocate. This ticket moves *which* code decides
the type, not *which thread* does the work.

- [x] Handlers are registered per `hg_event_source`, replacing `DetectorRegistry`
- [x] Each handler is statically typed end to end; no downcasting anywhere on the path
- [x] An unregistered/unknown `event_source` is still reported, not silently dropped
- [x] `ringBufferHandler()` still only submits — no parsing on the poll thread
- [x] The three sweeper-synthesised event types still cannot poach each other's work, and a test still pins it
- [x] The "no rule matched → HttpsTrafficObserved" fallback still fires for every source that had it
- [x] Per-item `try/catch` still bounds one throwing handler to one lost event
- [x] QEMU: all nine message IDs still reachable; the five-ClientHello baseline unchanged

## Comments

`DetectorRegistry` and the `dynamic_cast` chain are gone. `DetectLoop` now holds
`unordered_map<uint32_t, Handler>`, and a handler owns the whole chain for one
source: parse, run that source's rules in order, dispatch. The event-source word
selects a **function**; inside it the concrete type is known to the compiler.

`detections/` contains no `dynamic_cast` at all now. Exactly one remains in the
project, in `HttpGuardProgram::peerResolver()`, and it is a different kind of
question — which hook can resolve a tuple from /proc — asked **once at startup**
rather than per event.

Parsing stayed on `DetectLoop`'s threads. `ringBufferHandler()` still only
submits, so a slow callback cannot fill the ring buffer and drop events. This
ticket moved *which code decides the type*, not *which thread does the work*.

### A regression I introduced and had to undo

Putting `parse()` and `handle()` in the same translation unit coupled parsing to
the actions — so the unit tests could no longer link without `ActionLoop`,
`LogAction` and netlink. That quietly destroyed a deliberate property: the parse
step is supposed to be linkable on its own so the tests exercise the *real*
parser rather than a reimplementation.

Caught by the link errors, fixed by making each source's `parse()` header-only
and leaving `handle()` in the `.cpp`. The tests now link with no actions and no
libbpf, and that dependency-free seam covers all three sources rather than just
the uprobe, which is better than before.

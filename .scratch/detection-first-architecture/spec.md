# Detection-first architecture

## Problem Statement

The tree is organised around **hooks**, but the thing that matters to a user of
this tool is **detections**. Three consequences:

1. `HttpGuardProgram` *is-a* `BpfProgram`, which makes its ring-buffer plumbing
   read strangely: the orchestrator inherits a BPF lifecycle it does not really
   own, and the ring-buffer callback — whose whole job is now one line — sits on
   the orchestrator rather than on the thing that produced the record.
2. Event types live under `programs/<hook>/src/`, one class per hook, and a rule
   recovers what it needs with `dynamic_cast` through a polymorphic `hg_event`
   base plus capability interfaces. The type of a record is known exactly once —
   in the hook that parsed it — and then deliberately erased, only to be
   guessed again downstream.
3. `programs/<hook>/DESIGN.md` documents the mechanism (uprobe, XDP, LSM) rather
   than the detection, so a reader asking "how does Slowloris detection work"
   has to know which hook to look under first.

`DetectLoop` also cannot be exercised or reasoned about on its own: it is
constructed by `HttpGuardProgram`, unlike `ActionLoop`, which is a singleton with
its own `main.cpp` runner.

## Solution

Invert the organising axis. Hooks become thin BPF-attach + submit units;
everything about *what an event is* and *what it means* moves into
`detections/`, keyed by detection family rather than by hook.

- `DetectLoop` becomes a singleton with its own runner binary, matching
  `ActionLoop`.
- Each hook inherits `BpfProgram`; `HttpGuardProgram` composes and manages them.
- `BpfProgram::ringBufferHandler()` gets a default body that does nothing but
  `DetectLoop::getInstance().submit(data, size)`, overridable but normally not
  overridden.
- The polymorphic `hg_event` base and the `I*Info` capability interfaces go
  away. Each detection family owns its own plain event struct, composing a
  shared `EventMeta`. Rules that span hooks bind through a C++20 **concept**,
  not a virtual interface — static duck typing instead of `dynamic_cast`.
- `DetectLoop` holds a **registered list of typed handlers**, one per
  `hg_event_source`, and dispatches on the discriminator it already reads at
  offset 0. No RTTI anywhere in the pipeline.
- `programs/<hook>/DESIGN.md` is split and rewritten as
  `detections/<family>/DESIGN.md`.

## Two decisions taken deliberately, because the request as written is ambiguous

### Parsing does NOT move onto the poll thread

The request says parsing should "be called within `ringBufferCallback`", and
also that `ringBufferCallback` should "only submit". Those cannot both hold, and
the second is the one that matters: ticket 11 established by measurement that a
slow ring-buffer callback lets the buffer fill and **drops events**, which is a
missed detection nothing reports.

Resolved as: the per-type parse+detect callbacks are *registered with*
`DetectLoop`, and `DetectLoop` invokes the matching one **on its own thread**,
selected by the `event_source` word. That satisfies the actual goal — the
callback only submits, and the type is chosen from a registered list rather than
recovered by `dynamic_cast` — without putting allocation back on the poll
thread.

### Hooks inherit `BpfProgram`, but stop owning the BPF object

`BpfProgram` today owns a `bpf_object` **and** a `ring_buffer`. If three hooks
each inherit that as-is, the daemon ends up with three BPF objects, three ring
buffers and — the part that actually breaks — **three separate blocklist maps**.
`BlocklistAddAction` writes the map that the XDP program reads; separate objects
means enforcement silently stops working, which is the exact failure class this
project has been fixing.

Resolved as: `BpfProgram` keeps the per-hook half (attach its programs into an
already-loaded object, expose a ring-buffer handler) and `HttpGuardProgram` owns
the single object, the single ring buffer and the poll loop, handing the object
to each hook. Hooks do inherit `BpfProgram`; the shared-map invariant survives.

## User Stories

1. As a maintainer, I want to read `detections/slowloris/DESIGN.md` to learn how Slowloris detection works, without first knowing that XDP counters feed it.
2. As a maintainer adding a detection, I want to add one directory under `detections/` containing the event struct, the rule and the doc, and register one handler.
3. As a maintainer adding a hook, I want to write an attach function and get event submission for free from `BpfProgram`'s default handler.
4. As a reviewer, I want a rule's input type to be checked by the compiler, so a rule reading a field the event cannot supply fails to build rather than declining at runtime.
5. As a maintainer, I want `DetectLoop` to be runnable and inspectable on its own, the way `action_runner` already allows for `ActionLoop`.
6. As an operator, I want none of this to change what is detected or enforced.

## Out of Scope

- Changing any detection rule's logic, threshold, severity or message ID.
- Changing the raw BPF↔userspace ABI (`<hook>_event.h`) — that was just
  restructured and is deliberately left alone here.
- Splitting the single BPF object, ring buffer or blocklist map.

## Testing Decisions

The seam stays where it is: rules are pure functions of one event struct, so
`tests/test_detectors.cpp` keeps its shape and gains compile-time coverage it
could not have before (a rule bound to a concept cannot be instantiated with an
event lacking the field). `tests/detectloop/` covers the singleton's scheduling.
Every ticket ends with a QEMU run comparing message IDs against the current
baseline: **2 weak-cipher, 2 SNI-anomaly, 1 traffic-observed** for the five
ClientHello cases, and a uprobe payload anomaly that tears a live connection
down.

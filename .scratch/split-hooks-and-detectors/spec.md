# Split hook attachment and detection into separate, pluggable layers

Status: ready-for-agent

## Problem Statement

HTTPS-Guard's userspace daemon currently mixes three genuinely different concerns into one class and, in the ring-buffer callback, effectively one function: attaching and parsing BPF hook output (one code path per hook, e.g. the OpenSSL uprobe vs. the XDP program), deciding whether a given event represents a security violation (TLS-version check, payload pattern matching), and dispatching enforcement actions. Because all of this lives inline in a single class's attach method and a single growing if/else chain in its ring-buffer handler, every new hook or new detection rule means editing that same shared code, and the two concerns (parsing vs. classifying) can't be reasoned about or tested independently.

This is a near-term problem, not a hypothetical one: several more hook types (an LSM-based certificate-access guard, cipher-suite/SNI inspection) and several more detection rules (connection-rate abuse, TLS renegotiation storms) are planned next, and the maintainer wants to add each of those without re-touching the orchestrator or duplicating attach/parse boilerplate per hook.

## Solution

Restructure the daemon's source into three top-level concerns that map directly onto the project's own "Detect → Classify → Dispatch" pipeline language:

- **Hook/program layer** ("Detect") — one module per BPF hook family, each responsible only for attaching its BPF program(s) to the shared BPF object and parsing its raw ring-buffer event into the daemon's common event representation.
- **Detector layer** ("Classify") — one small class per detection rule, each a pure, synchronous function from the common event representation to a classification verdict (severity, message, actionability), with no knowledge of BPF, sockets, or enforcement.
- **Action layer** ("Dispatch") — unchanged; the existing asynchronous, side-effecting action classes and their dispatcher.

Two small interfaces make the orchestrator generic instead of hardcoded: one that every hook module implements (attach / identify its event source / parse an event), and one that every detector implements (evaluate an event, mutate it in place if it matches). The orchestrator becomes a thin runner: attach every registered hook module, and on each event, parse it via the matching hook module and run the ordered list of detectors registered for that event source, stopping at the first match. The daemon's entry point becomes the composition root — the one place that knows about every concrete hook module and detector — so the orchestrator's own code never needs to change when a hook or detector is added.

This is a pure structural refactor. No new detection capability and no behavior change versus today's daemon.

## User Stories

1. As a HTTPS-Guard maintainer, I want each BPF hook's attach-and-parse logic isolated in its own module, so that I can add a new hook (e.g. an LSM certificate-access guard) without touching existing hooks' code.
2. As a HTTPS-Guard maintainer, I want detection/classification rules (the TLS-version check, the payload pattern/anomaly check) implemented as standalone classes behind one interface, so that I can add a new detection rule without editing the ring-buffer dispatch code.
3. As a HTTPS-Guard maintainer, I want the mapping of "which detectors run for which event source" centralized in one place, so that a cross-cutting detector (used by more than one hook) is wired once instead of duplicated per hook.
4. As a HTTPS-Guard maintainer, I want the daemon's entry point to be the single place that knows about every concrete hook module and detector, so that the orchestrator class itself never needs to change when a hook or detector is added.
5. As a HTTPS-Guard maintainer, I want the generic BPF lifecycle wrapper (object open/load, attach delegation, ring-buffer registration, polling) kept separate from HTTPS-Guard-specific composition logic, so that the generic wrapper stays reusable and uncluttered by product-specific knowledge.
6. As a developer writing a new detector, I want to unit-test it by constructing an event value by hand and calling its evaluation method directly, so that I don't need a running kernel, root privileges, or a QEMU environment to verify classification logic.
7. As a code reviewer, I want each hook's kernel-side (BPF) source physically separated into its own unit, so that I can review a single hook's kernel-side behavior without reading unrelated hooks' code.
8. As a build maintainer, I want the build split per top-level concern (hook/program code, detector code, action code), so that adding a source file to one concern doesn't require editing a single large, shared source-file list.
9. As a HTTPS-Guard maintainer, I want the BPF side to remain a single compiled artifact sharing one ring buffer and one blocklist map, so that the daemon's deployment and map-sharing model doesn't get more complex than it is today.
10. As a HTTPS-Guard maintainer, I want today's exact runtime behavior (TLS-version-violation detection, payload-anomaly detection, enforcement dispatch, logging) preserved bit-for-bit through this refactor, so that I can be confident the restructuring introduced no regressions before building new detection capability on top of it.
11. As a HTTPS-Guard maintainer, I want the XDP hook's existing non-fatal attach-failure fallback (native mode, then generic/SKB mode, then a logged skip) preserved exactly, so that the daemon continues to run correctly on BMC platforms without XDP support.
12. As a future contributor adding the LSM certificate-access-guard hook, I want an established interface to implement, so that the new hook's shape is predictable and consistent with existing hooks.
13. As a HTTPS-Guard maintainer, I want each hook's raw wire-format event structure to live with the hook that owns it, so that nothing outside that hook needs to know its exact layout.
14. As a HTTPS-Guard maintainer, I want the Redfish message-formatting code relocated next to the logging action that consumes it, so that code which exists solely to build one action's input lives with that action.
15. As a HTTPS-Guard maintainer, I want detector evaluation order preserved (TLS-version check before payload-anomaly check, stopping at the first match), so that today's classification priority doesn't silently change.
16. As a HTTPS-Guard maintainer, I want the new files and classes to follow the project's existing naming conventions, so the result reads as part of the same codebase rather than a bolted-on style.

## Implementation Decisions

- The daemon continues to compile and load exactly one BPF object with one shared ring buffer and one shared blocklist map. Hook-specific BPF logic is organized into separate source units at the source level but still compiled into that single object — the same technique already used for the existing blocklist logic today. Per-hook independence is achieved at the *attach* layer (a hook failing to attach doesn't stop others), not by loading separate BPF objects; separate objects were considered and rejected for this phase because they'd require map pinning and multiple ring buffers for no corresponding benefit right now.
- Detection (deciding severity/message/actionability for an event) is modeled as a concept distinct from enforcement action. Classification is synchronous and pure; actions are asynchronous, side-effecting, and dispatched through the existing async action-loop mechanism. Forcing classification through the action-dispatch mechanism was considered and rejected, since the classification result is needed synchronously, before the dispatch decision can even be made.
- Detection logic lives in its own module area, separate from both hook-attachment code and action-dispatch code — a third top-level area alongside the existing action layer, mirroring the project's own three-stage "detect / classify / dispatch" pipeline framing.
- Detector implementations are shared across hook types where the underlying check applies to more than one hook's event (the TLS-version check and the payload-pattern check both apply to every existing hook's event today); hook-specific detectors are scoped under the hook that produces the fields they need.
- Hook modules (one per BPF hook family) are responsible only for attaching their BPF program(s) and parsing their raw event into the common event representation. They do not invoke detection logic themselves — this was decided specifically to avoid a shared/cross-cutting detector needing to be called from more than one hook module.
- A common interface for hook modules exposes three operations: attach (given the shared BPF object and a place to register any resulting links), report its event-source identifier, and parse a raw event into the common event representation. The orchestrator holds a collection of hook modules and treats them uniformly through this interface.
- A central registry, keyed by event-source identifier, maps each event source to its ordered list of applicable detectors. The orchestrator looks up and runs this list after parsing an event, stopping at the first detector that reports a match, and falls back to today's "no violation, traffic observed" classification when none match. Each hook module owning its own detector list was considered and rejected, since it would force a cross-cutting detector to be wired into more than one hook module.
- The daemon's entry point is the composition root: it constructs the concrete hook modules and the detector registry and injects both into the orchestrator (the orchestrator does not construct its own dependencies). This follows the same pattern already used today for injecting the action-loop dependency, extended to the two new collections.
- The generic BPF lifecycle wrapper (object open/load, attach delegation via a hook-module collection, ring-buffer registration, polling) is a separate, product-agnostic module from the HTTPS-Guard-specific orchestrator that composes hook modules and detectors, since the two change for different reasons: the wrapper changes only if the underlying BPF loader library's API changes, while the orchestrator changes whenever HTTPS-Guard's own hook/detector composition changes.
- The build is split per top-level concern (one build unit each for the hook/program layer, the detector layer, and the action layer, plus the root build definition), so that adding a source file to one concern's area doesn't require editing a single shared, growing source list. This is scoped to top-level concerns only — individual hook modules do not get their own build unit, since a single source file per hook doesn't warrant one.
- This restructuring changes no runtime behavior: attach fallback semantics, detector evaluation order and priority, and the final enforcement/logging dispatch are preserved exactly as they exist today.

## Testing Decisions

- A good test here exercises the detector interface's observable behavior only — given a fully-populated event value, does evaluation correctly decide severity, message, and actionability — not implementation details such as exact log line wording or private helper functions.
- The detector-evaluation interface is the primary (and, per the project's own "prefer the fewest seams" guidance, the only) seam under test for this change. It is the one piece of logic in this refactor that is pure, synchronous, and free of kernel/socket/filesystem dependencies, making it feasible to test without a running kernel, elevated privileges, or a QEMU environment.
- Each existing classification rule (the TLS-version-violation check, the payload-pattern/anomaly check) gets coverage for: a clearly-violating input, a clearly-clean input, and its documented boundary condition (e.g. the exact TLS-version threshold that separates a violation from a pass).
- Hook-module event parsing and the BPF programs themselves are explicitly not unit tested as part of this change — they require a real kernel/eBPF environment to execute meaningfully, and remain covered only by the project's existing manual/QEMU-based verification process described in `DESIGN.md`. This is an intentional scope boundary, not an oversight.
- There is no existing automated test suite or test framework wired into the build today. The closest existing artifact (`action_runner`) is a manual smoke-test/demo binary, not an automated test, so there is no directly reusable prior art — introducing detector unit tests also means introducing a minimal test framework and a corresponding build target.

## Out of Scope

- Adding the mirrored read-direction hook (capturing the inbound request payload, not just the outbound response payload) — planned as the next phase after this restructuring lands.
- The BPF-LSM certificate-access guard hook.
- Additional TCP/TLS attack detectors: cipher-suite/downgrade detection, SNI inspection, connection-rate/SYN-flood/port-scan detection, Slowloris detection, TLS renegotiation-storm detection.
- Extending the OEM security event message registry with new message types for the above.
- The `README.md` rewrite, the top-level `DESIGN.md` rewrite, and per-hook `DESIGN.md` documents.
- Multi-layer `CLAUDE.md` content beyond the agent-skills configuration block added by this project's tooling setup.
- Any change to the BitBake recipe's `PACKAGECONFIG` behavior or systemd unit behavior beyond updating file-path references to match the new layout.
- Any new detection capability or behavior change of any kind — this spec is a pure structural refactor.

## Further Notes

- This spec covers only the first of several phases discussed with the maintainer. The read-direction hook, the LSM certificate-access guard, and the other TCP/TLS detectors will each get their own spec once worked through in the same level of detail — they were sequenced but not yet architecturally decided to the same rigor as this phase.
- The existing top-level `DESIGN.md` contains exact line-number citations into the current (pre-refactor) file layout. Those will become inaccurate once this lands. It is intentionally left unrewritten for now, since a full documentation pass (including per-hook `DESIGN.md` files) is planned as a separate, later effort — rewriting it now would likely be thrown away or reworked during that pass.
- This project's issue-tracking setup was completed alongside this spec: tracking is local markdown under `.scratch/` for now, with the maintainer planning to handle migration to the project's GitHub remote themselves later.

# 11 — Move parse/classify/dispatch off the ring-buffer poll thread into a DetectLoop

**What to build:** A `DetectLoop`, shaped like the existing `ActionLoop`, that owns everything currently done inline inside libbpf's ring-buffer callback. `HttpGuardProgram::ringBufferHandler` shrinks to "copy the raw bytes, enqueue, return"; the loop thread does parse → `/proc` enrichment → classify → push actions.

**Blocked by:** None — can start immediately

**Supersedes:** 10 — Add an exception boundary so one bad event can't kill the daemon permanently (a per-item `try/catch` in the loop, matching `ActionLoop`'s existing pattern, is the natural place for that boundary and is part of this ticket's acceptance criteria)

**Status:** done

## Why — and why the obvious target is the wrong one

The motivating concern was that `ringBufferHandler` does too much, specifically `detector->evaluate(evt)`. Measured, `evaluate()` is the cheapest part of that handler:

| Work | Cost per event |
|---|---|
| `TlsVersionDetector::evaluate` | 2 integer compares |
| `SniDetector::evaluate` | one `tolower` + one string compare |
| `PayloadAnomalyDetector::evaluate` | substring search over ≤127 bytes × 17 rules |
| `CipherSuiteDetector::evaluate` | ≤32 suites × 22 table entries = ≤704 integer compares |
| **`ProcPeerResolver::getTcpSockets` (in `parseEvent`, runs *before* any detector)** | **opens and line-parses `/proc/<pid>/net/tcp` — 505 lines on the dev host — with an `istringstream`, a `vector<string>` split, and 3 `stoul`/`stoi` per line** |
| `RedfishEventMessage::format` | nlohmann::json build + `dump()`, allocating |

So moving only `evaluate()` to a worker thread would add a thread hand-off and leave the real cost exactly where it is. The boundary has to be drawn at the **raw event**, before parsing, for this to be worth doing.

The `/proc` walk runs on *every* `SSL_write` and `SSL_read` event, and a single HTTPS request produces several of those — so a handful of concurrent requests means repeatedly re-parsing a several-hundred-line file on the one thread libbpf needs back promptly.

## Why this is a security property, not just tidiness

A ring-buffer callback that runs long lets the buffer fill; a full ring buffer **drops events**, and a dropped event is a missed detection that nothing reports. Keeping the poll thread short is what makes detection coverage trustworthy under load, which is exactly when an attack is most likely to be happening.

- [x] `ringBufferHandler` does no parsing, no `/proc` access, no classification and no action construction — it copies the raw record and enqueues it
- [x] A `DetectLoop` worker consumes that queue and performs parse → enrich → classify → dispatch, pushing to `ActionLoop` exactly as the inline path does today, so observable behaviour (Redfish events, blocklist entries) is unchanged
- [x] Per-item `try/catch` in the loop, following `ActionLoop`'s existing pattern: a throw logs and drops that one event instead of terminating the daemon (this is ticket 10's requirement, absorbed here)
- [x] The queue has a bounded depth and an explicit, logged policy for what happens when it's full — silently growing without limit trades a dropped event for an OOM, which is worse on a BMC; whichever is chosen, the reasoning is recorded
- [x] Raw-record copying is safe: the ring-buffer sample pointer is only valid inside the callback, so the copy must be complete and size-checked before returning (the existing `size < sizeof(...)` guards move to the copy step, not the parse step)
- [x] Event ordering within a single event source is preserved, or the decision not to preserve it is documented with its consequence for correlating a request across `SSL_write`/`SSL_read` pairs
- [x] Verified on real QEMU that detection still works end to end after the change — at minimum: a payload-anomaly signature over a live request, and a crafted weak-cipher ClientHello — not just that the daemon starts
- [x] Verified that shutdown drains or abandons the queue deterministically, without a hang or a use-after-free on the `ActionLoop`/`DetectLoop` teardown path

## Parsing stays one stage, but splits by cost

Considered and rejected: giving parsing its own loop, or pushing it as an `ActionLoop` action.

- **Its own loop** buys nothing. Classification *consumes* enrichment output, so the two can only run serially — a third stage adds a thread hop plus a third queue (with its own depth bound, drop policy and drop counter) for zero concurrency gain, and every queue boundary is another place an event can be lost.
- **As an `ActionLoop` action** is worse than for classification: parse must precede classify, so it becomes actions spawning actions on the queue they're executing from, on top of the head-of-line blocking already noted.

What *is* worth splitting is the two very different things `parseEvent()` currently bundles:

| | Cost | Needed by |
|---|---|---|
| **Field mapping** (`parseUprobeEventFields`, `parse_client_hello_detail`) | microseconds, pure CPU | everything |
| **`/proc` enrichment** (`ProcPeerResolver`) | opens + line-parses a several-hundred-line file (505 on the dev host); ticket 13 will add `/proc/<pid>/fd` reads on top | almost nothing — see below |

Every consumer of the enriched 4-tuple sits behind `if (verdict.actionable)`: `BlockTcpAction`, `BlocklistAddAction`, and the "no TCP sockets found, cannot SOCK_DESTROY" warning. Nothing else reads it — `RedfishEventMessage` emits no `source_ip` field at all, the uprobe-path detectors (`TlsVersionDetector`, `PayloadAnomalyDetector`) build their messages from `process`/`pid`, and the two detectors that *do* use `source_ip` (`CipherSuiteDetector`, `SniDetector`) are XDP-only, where the address comes from the packet in BPF rather than from `/proc`.

So the single most expensive operation in the pipeline runs on every uprobe event and is discarded unused for the great majority of them — roughly 80–90%, judging by the OK-to-flagged ratio in observed logs (one HTTPS request produces 6–12 uprobe events, typically 1–2 flagged).

- [x] `/proc` enrichment is **lazy and memoized** — resolved on first access rather than eagerly during parse, so it runs only when a consumer actually asks for it. Lazy rather than simply relocated into the `actionable` branch, so a future detector that genuinely needs the address (e.g. ticket 05's per-source-IP rate logic) stays correct without reintroducing the eager cost for everyone else
- [x] A short-TTL cache fronts the resolution for the cases that do run: `/proc/<pid>/net/tcp` is network-namespace-scoped, so on a single-netns BMC every event re-parses identical content
- [x] Field mapping remains separable and unit-testable without libbpf, as it is today — that property is what lets the real parsers be tested rather than reimplementations
- [ ] Measured before/after on QEMU under repeated requests, so the improvement is demonstrated rather than assumed — and so the latency cost of resolving *later* (a short-lived socket being likelier to have closed) is observed rather than hand-waved

## Comments

`DetectLoop` lives in `detections/core/` rather than `programs/core/`, per
review feedback: it belongs to the detection concern, not to any hook.
Moving it there would have created a dependency cycle, so `IHookModule.hpp`
and `hg_event_source.h` moved with it and `IHookModule.hpp` now
forward-declares `bpf_object`/`bpf_link` instead of including
`<bpf/libbpf.h>`. The graph is strictly one-way:

    actions_lib  <--  detections_lib  <--  programs_lib

Removing that transitive libbpf include also forced each hook to declare the
dependency it actually uses -- three of them had been getting it for free.

`ringBufferHandler` is now three lines: copy, enqueue, return. Everything
else runs on the worker.

### Verified on QEMU

All three classification paths still fire through the new thread boundary,
confirmed from the Redfish event log rather than inferred from console
output:

| MessageId | Path exercised |
|---|---|
| `HttpsPayloadAnomalyDetected` (x2) | uprobe -> DetectLoop -> enforcement, connection torn down |
| `HttpsWeakCipherSuiteDetected` | XDP -> DetectLoop -> alert-only |
| `HttpsTrafficObserved` | clean traffic, OK verdict |

Shutdown is deterministic: `systemctl restart` completed in 4s with no hang,
and no "DetectLoop stopped" diagnostic appeared -- that line only prints when
something was dropped or abandoned, so its absence means the queue was empty
and nothing was lost.

The restart also reproduced ticket 09 (`XDP program already attached`,
`1 of 3 hooks`). That is the pre-existing attachment leak, not a regression
from this change, and this is independent confirmation of it.

### One criterion not met

Before/after timing was **not measured** on target. The mechanism is
verified -- unit tests prove enrichment is not invoked unless something asks,
and the `/proc` read is now behind both that check and a 50ms cache -- but
no latency or throughput numbers were taken, so the improvement is reasoned
rather than demonstrated. Worth doing if the pipeline is ever suspected of
dropping events under load, since that is the failure this ticket exists to
prevent and the only honest way to confirm headroom.

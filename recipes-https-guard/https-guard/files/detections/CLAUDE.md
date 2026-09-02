# detections/ — Classify layer, and the pipeline engine

Everything about **what an event is and what it means**: the event types, the
parsing that produces them, the rules that judge them, and the loop that drives
the whole thing. `../programs/` only attaches BPF and hands over bytes.

The tree is organised by **detection**, not by hook, because that is the question
a reader actually arrives with. Each detection family owns a directory with its
rule and its `DESIGN.md`.

## Layout

### `core/` — grouped by duty, four directories

```
core/contract/   what a detection must provide
  IDetection.hpp          inspect(data, size, meta) -> optional<Verdict>
  Verdict.hpp             {severity, message_id, message, actionable}
  detection_traits.hpp    concepts describing what a RAW RECORD carries

core/event/      the vocabulary every detection speaks
  hg_event_source.h       the discriminator + hg_event_hdr (compiled as C by the BPF side too)
  event_meta.hpp          EventMeta — composed into every event struct, not inherited
  event_meta_from.hpp     the shared envelope parse, in exactly one place
  IPeerResolver.hpp       lazy /proc tuple resolution, so only the enforcing path pays
  tls_version.hpp         TlsVersion: a wire code -> a display string

core/engine/     what drives the record path
  DetectLoop.{hpp,cpp}    the loop: singleton, asio, walks a submitted list
  dispatch.{hpp,cpp}      the shared tail: enforce if actionable, then log

core/sweep/      what drives the counter path
  ConnRateSweeper.{hpp,cpp}  timer-driven: reads the BPF per-source counters,
                             evaluates the three rate_sweep/ rules, dispatches
                             directly — the counter-path counterpart to
                             engine/'s record path, not a rule of its own

core/main.cpp    detect_runner — a standalone runner, like action_runner
```

Four directories rather than one flat pile of fifteen files, split by the
question each answers: *what must I implement*, *what do I speak*, *what runs
the record path*, *what runs the counter path*. `main.cpp` stays at the top
because it belongs to none of them.

**Includes stay unqualified** (`#include "event_meta.hpp"`, not
`"event/event_meta.hpp"`), matching the rest of the tree — all four directories
are on the include path, so moving a file between them touches no `#include`
anywhere.

`tls_version.hpp` sits in `event/` rather than in `detections/tls_version/`
because it is a display helper for a raw wire value, not a rule: both that
detection and `traffic_observed` need it.

### Detections — one directory per family, everything about it inside

A detection directory holds **all** of it:

```
detections/<family>/<Family>Event.hpp       what this rule reads, and nothing else
detections/<family>/<Family>Detector.hpp    the rule: one event in, optional Verdict out
detections/<family>/<Family>Detection.hpp   IDetection: parse + evaluate
detections/<family>/DESIGN.md               why it exists and what it cannot see
```

`IDetection` (in `core/`) is the seam:

```cpp
virtual std::optional<Verdict> inspect(const void* data, std::size_t size,
                                       EventMeta& meta) const = 0;
```

`nullopt` covers "not mine", "does not parse" and "no violation" alike — the
caller does not distinguish, it just tries the next entry.

**Parse and evaluate live together because they are the same decision.** What a
detection needs out of a record is determined entirely by what its rule reads.
Splitting them put half a detection in one directory and half in another, and
made adding one mean editing a shared per-source handler.

**A detection that serves two hooks is templated on the raw struct**, not
duplicated. `TlsVersionDetection<struct uprobe_event>` and
`TlsVersionDetection<struct xdp_event>` share one rule and one event struct; the
nested ABI means the parse is the same expression, and the places the layouts
genuinely differ (a connection tuple, a line-rate violation hint) are read with
`if constexpr` guarded by the concepts in `core/detection_traits.hpp`.

A detection that only one hook can feed says so in a `requires` clause, so
naming it in the wrong hook's list is a build error rather than a rule that
never fires.

### The detections

| Directory | Rule | Fed by | Actionable? |
|---|---|---|---|
| `tls_version/` | TLS below 1.2 (+ the `TlsVersion` name helper) | uprobe **and** XDP | yes |
| `payload_anomaly/` | SQLi / path-traversal / attack-signature substrings | uprobe **and** XDP | yes |
| `cipher_suite/` | weak offered suites (+ the code-point table) | XDP | **no** — alert only |
| `sni/` | malformed SNI always; mismatch only when configured | XDP | **no** — alert only |
| `cert_access/` | an unrecognised process opened the HTTPS key | LSM | **no** |
| `rate_sweep/` (connection rate) | connection attempts per source per window | synthesised | yes |
| `rate_sweep/` (Slowloris) | connections held open per source | synthesised | yes |
| `rate_sweep/` (renegotiation) | TLS handshake records per source per window | synthesised | yes |
| `traffic_observed/` | nothing — the always-matching terminal list entry | any | no |

## Why some rules enforce and others only alert

Understand this before adding a rule, because getting it wrong has caused an
outage. The blocklist applies to a source address on **every port**, so an
actionable verdict against a false positive removes all access to the BMC for
the TTL.

- `cipher_suite` and `sni` fire on a handshake bmcweb refuses anyway. The offer itself does no damage, so alerting is proportionate. Making them actionable locked an operator out of SSH during testing — that incident is why they are not.
- `conn_rate`, `slowloris` and `renegotiation` describe *ongoing harm*. An alert that does not stop it is close to useless, so these enforce — which makes their thresholds safety-critical rather than tuning details.
- `cert_access` is not actionable because there is no connection to act on.

## Why the rules take concrete types, and where concepts went

A rule takes exactly one event struct:

```cpp
std::optional<Verdict> evaluate(const TlsVersionEvent& evt) const;
```

There were concepts here, and before that six virtual `I*Info` interfaces. Both
existed for one reason: two rules applied to two different event types, so they
needed something other than a concrete type to bind to.

Once each detection got its **own** event struct, that reason evaporated. Every
rule has one input type, so handing it the wrong event is an ordinary type
mismatch the compiler reports at the call site — which is exactly what the
concepts were buying, at the cost of a layer of machinery. They were deleted
rather than kept as ceremony.

Concepts do survive in `core/detection_traits.hpp`, doing genuinely different
work: they describe what a **raw record** happens to carry
(`HasConnectionTuple`, `HasViolationHint`, `HasClientHello`), which is what lets
one templated detection serve two hooks without a specialisation per hook.

**`violation_hint` is the one field that looks redundant and is not.** A parsed
wire `legacy_version` of `0x0000` *is* a violation; `tls_version == 0` from a
uprobe only means "never observed". The XDP instantiation reads the BPF-computed
flag; the uprobe one leaves it false. Collapsing those two zeros shipped as a
real bug once.

## Stateful rules without stateful detectors

Three rules need to remember things across events, and **no rule holds any
state**. That purity is what makes every rule testable with a hand-built event,
and weakening it for three would weaken it for all eight. Instead:

```
BPF map (per-source counters)  ->  ConnRateSweeper  ->  synthesised event  ->  pure rule
      state lives here            aggregates on a timer      carries the aggregate
```

The counting lives in an `LRU_HASH` keyed on source address — LRU because a
plain hash keyed on source *is* a DoS vector once a spoofed-source flood fills
it. Rates reset with the window; `open_conns` is a **level** and survives the
roll, or a Slowloris that goes quiet would look idle.

## DetectLoop

A singleton (`getInstance()`), configured once with the action loop, the
blocklist TTL and the output path. It owns a queue, some threads and a timer,
and knows **nothing** about events: a record arrives together with the list of
detections to try against it, and the loop evaluates that list concurrently and
picks a winner by its order.

```cpp
// in the hook, on the poll thread
DetectLoop::getInstance().submit(data, size, detections_);
```

Three consequences:

- **Lowest-index match wins**, which is what keeps one record to one Redfish event. Every entry is evaluated regardless — the loop no longer stops at the first verdict, so a future I/O-bound detection can suspend without holding up its siblings (see `detections/DESIGN.md`) — but only the lowest-index verdict is ever dispatched.
- **Rule priority is the hook's list order.** That is the one real cost of this shape: which rule wins is a classification decision, and it is now expressed in `programs/`. Accepted deliberately — each list is 2–5 entries, readable at the point where the hook says what it can observe — and visible at runtime, because the loop logs which index claimed each record.
- **There is no "nothing matched" branch.** A hook puts an always-matching `TrafficObservedDetection` last, so an always-matching entry at the end covers it.

### Why the record's arrays are fixed-size, with the numbers

`RawRecord` is **1064 bytes** on the ARM32 target, and the split is not where it
looks:

| | bytes | share |
|---|---|---|
| `bytes[HG_MAX_RAW_EVENT_SIZE]` | 1024 | **96.2%** |
| `detections[8]` | 32 | **3.0%** |
| `size` + `detection_count` | 8 | 0.8% |

So making the **detection list** dynamic saves 3% and costs a heap allocation
per event. Three reasons not to:

- The pipeline does **exactly one allocation per record** today — Asio's handler
  allocation for the lambda capture. `std::vector` has no small-buffer
  optimisation, so it would add a second malloc/free per event on the path whose
  whole purpose is to return fast enough not to drop events.
- `submit()` is `noexcept` and runs inside libbpf's callback. A vector
  allocation there can throw, needs catching, and introduces a new failure mode:
  losing a security event because the *pointer list* would not allocate. A fixed
  array cannot fail.
- Scanning ≤5 pointers is a few cycles. There is nothing there to optimise.

**The payload buffer is the real cost**, and worth revisiting rather than the
list: the largest actual record is 352 bytes (`xdp_event`) against a 1024-byte
cap, so a uprobe record wastes 844 bytes and the queue's worst case is 4.16 MB,
about 3.4 MB of it padding. Lowering `HG_MAX_RAW_EVENT_SIZE` to 512 would halve
that; the `static_assert` in each hook's `.cpp` already guards the cap, so it is
a one-line change whenever the headroom is judged unnecessary.

### Why detections are identified by name but selected by position

`IDetection::name()` exists so diagnostics read `claimed by 'cipher_suite'`
rather than `claimed by detection 2 of 5`, which said nothing without the hook's
source open beside it. It costs **nothing per record** — a string literal in
rodata reached through the vtable, read once per record on a line that already
does iostream work.

It is deliberately **not** a lookup key. The list is walked in order and the
first verdict wins, so the order *is* the priority; a name-keyed map has no
order and would need a parallel order vector to recover what the array already
gives, while hashing a string per record to choose among two to five entries
would be slower than scanning them.

The submitted pointer list is **copied** into the queued record. `submit()`
returns immediately and the record is inspected later, so a view of a temporary
at the call site would dangle; the pointees are owned by the hook, which
outlives the loop. A harness test submits with a deliberately temporary view
under ASan to pin that.

Classification runs on the loop's threads, not in the ring-buffer callback: a
callback that runs long lets the ring buffer fill, and a full ring buffer **drops
events** — a missed detection nothing reports. Three properties of its shape are
deliberate, each because the obvious version was wrong: `co_spawn()`, ready for a
detection that awaits, even though nothing does yet (see "`co_spawn()`, ready for
a detection that awaits" in `DESIGN.md`); explicitly bounded admission (`post()`
— still used to arm the sweep timer, which never has anything to await — is an
unbounded queue, and on a ~1GB BMC an OOM takes *all* detection with it); and two
threads with the sweep timer off the record strand (a single-threaded loop
starves the timer by FIFO fairness — measured, one thread gave **zero** sweeps in
nine seconds where two gave one every two).

That last point makes rule statelessness a **threading requirement**: the sweep
runs concurrently with a record, so a detection must be safe to call from either
thread. All of them are const and hold no mutable state.

## Why `inspect()` is synchronous

Short version, because it comes up: a suspension point pays only when something
else can make progress while you wait on an **external party**, and nothing here
waits. `inspect()` is memcpy and integer compares; the nearby syscalls
(`readlink("/proc/<pid>/exe")`, the `/proc/<pid>/net/tcp` parse) are CPU work in
kernel context with no device to wait for. Awaiting *inside* `inspect()` would
add a frame per detection per record and buy no concurrency, which is why its
signature is still synchronous.

`DetectLoop` does now run a hook's list with `make_parallel_group` /
`wait_for_all` rather than a sequential loop — every submitted detection is
evaluated, not just the ones up to the first match — but that is the loop
fanning out *calls to* today's synchronous `inspect()`, in preparation for one
that eventually isn't. List order still decides the winner: results are
gathered back in order, and the lowest-index verdict wins exactly as the
sequential loop produced. See `core/engine/DetectLoop.hpp` and
`detections/DESIGN.md`.

The actions are the opposite case, which is why the coroutines live there. Full
reasoning, what would make it worth revisiting, and the one optimisation that *is*
available today (a different executor for peer resolution, which is not
unambiguously a win) are in [`DESIGN.md`](DESIGN.md).

## Testing

`../tests/test_detectors.cpp` covers all eight rules — a clearly-violating
input, a clearly-clean one, and each rule's real boundaries: the exact TLS
threshold, the `violation_hint` override, case-insensitivity, empty input, `N`
triggers while `N-1` does not for each counting rule, and
zero-threshold-means-disabled (the most consequential boundary, since treating 0
as a threshold everything exceeds would blocklist every source that ever
connects).

Alongside them are 12 `static_assert`s pinning which concepts each event does
and does not satisfy. `../tests/detectloop/` covers the loop's scheduling
separately; see its README for why it is a separate binary.

This is the one seam explicitly designed to be testable without a kernel, root
or QEMU. A new rule should get the same treatment before it is considered done.

# `detections/` — the pipeline

Everything about **what an event is and what it means**. One directory per
detection, each holding its own event struct, its parse, its rule and its
`DESIGN.md`; plus `core/`, which holds the seam they implement, the vocabulary
they share, and the loop that drives them.

Per-detection rationale is in each detection's own `DESIGN.md`. This document is
about `DetectLoop` and the shape of the pipeline around it.

## What DetectLoop is, and what it deliberately is not

```
libbpf poll thread                    │  DetectLoop, 2 threads
                                      │
hook->ringBufferHandler()             │
  └── submit(data, size, detections_) ─┼──▶ copy bytes + pointer list
        returns immediately            │        into a queued record
                                      │              │
══════════════ thread boundary ════════│══════════════▼═══════════════
                                      │   walk the list in order:
                                      │     detections[0]->inspect(...)
                                      │     detections[1]->inspect(...)   ◄─ first
                                      │     ...                              verdict
                                      │     detections[n-1] always matches   wins
                                      │              │
                                      │              ▼
                                      │   dispatchVerdict(meta, verdict, ctx)
                                      │              │
                                      │   ┌──────────┴──────────┐
                                      │   ▼                     ▼
                                      │  enforce, if the      LogAction
                                      │  verdict says so      (always)
```

`DetectLoop` owns a queue, some threads and a timer. It does **not** know what
an event is, which detections exist, or what any of them mean — a record arrives
carrying the list to try against it. That is the whole design: the type of a
record is known inside a detection, from the raw bytes through to the verdict,
and nowhere else.

Three properties of the loop's shape are deliberate, and each is there because
the obvious version was measurably wrong.

### Classification is off the poll thread — a detection property, not a latency one

libbpf needs its callback back promptly. A callback that runs long lets the ring
buffer fill, and a full ring buffer **drops events** — a missed detection that
nothing reports. That matters most under load, which is exactly when an attack
is most likely.

The boundary is drawn at the **raw record**, not after parsing. The original
complaint was that the callback ran `evaluate()`, but measured, evaluation is the
cheapest thing in the path (a few hundred integer compares worst case); the cost
is the `/proc` walk in peer resolution. A queue placed after parsing would have
added a thread hop and left the bottleneck untouched.

### `co_spawn()`, ready for a detection that awaits

`inspect()` is still straight-line code today — nothing on the classify path
awaits anything — so this buys nothing in the way `ActionLoop`'s coroutines do,
where two of three actions genuinely suspend on I/O. `submit()` schedules
`handleRecord()`/`process()` via `co_spawn()` anyway, and `process()` evaluates a
record's detections concurrently with `asio::experimental::make_parallel_group`
rather than stopping at the first verdict, so the shape is already in place for
the day a detection's `inspect()` needs to suspend — see `IDetection.hpp`'s "WHEN
THAT WOULD CHANGE" for what that would look like. Until then it costs one
coroutine frame per record for no behavioural difference: every submitted
detection is evaluated regardless, and results are gathered back in list order,
so the lowest-index verdict still wins exactly as the sequential loop produced.

The one place this remains `post()`, deliberately, is `enableRateSweeps()`
arming the sweep timer: that call never has anything to await, and turning it
into a coroutine would be pure overhead with no future case to prepare for.

### Admission is bounded explicitly

`asio::post()` is an unbounded queue. On a BMC with ~1GB of RAM, trading a
dropped event for an OOM is a bad trade: the daemon dying takes *all* detection
with it, where a drop costs one event. So depth is capped by an atomic in-flight
count claimed in `submit()` before posting, and the full-queue policy is to drop
the **newest** record and count it — the queue then holds a coherent prefix of
history rather than a hole in the middle, and dropping the oldest would discard
the earliest evidence of an attack in progress. Drops are counted and logged,
rate-limited; a drop nobody hears about would recreate the very failure this
class exists to prevent.

`submit()` is `noexcept` and runs inside libbpf's callback, which is why the
record's arrays are fixed-size: a `std::vector` there could throw, and would add
a second allocation per event to a path whose entire purpose is speed. See
`CLAUDE.md` in this directory for the measured breakdown — the detection list is
3% of the record; the payload buffer is 96%.

### Two threads, and the sweep timer off the record strand

Records go through an `asio::strand`, so they are classified one at a time and
in arrival order — which is what makes "drop the newest" leave a coherent
prefix. The connection-rate sweep timer is **not** on that strand, and the loop
runs two threads specifically so it need not be.

This is the fix for a bug that already shipped. The sweep originally ran only
when the record queue was empty, so a flood — which generates events — starved
it, and rate detection switched off precisely when it was needed. A
single-threaded `io_context` reintroduces a weaker form of the same thing by FIFO
fairness alone: an expiring timer queues *behind* every record already posted.
Measured against a deliberate 3000-event backlog over nine seconds:

| Threads | Sweeps in 9s |
|---|---|
| 1 | **0** |
| 2 | 4, one every 2s as intended |

Against a fixed 10s counting window, the single-threaded version can let a
window roll unobserved and lose a flood entirely.

**The cost of that choice, stated plainly:** the sweep can run concurrently with
a record, so detection statelessness stops being a design guideline and becomes a
threading requirement. Every detection is `const` and holds no mutable state, and
the harness runs under TSan to keep it that way.

## First match wins, and where the order lives

The loop stops at the first verdict. That is what keeps one record to one Redfish
event — running every entry would emit up to four for a single ClientHello.

**List order is priority order, and it lives in the hook.** That is the one real
cost of this shape: which detection wins is a classification decision now
expressed in `programs/`. Accepted deliberately, because each list is two to five
entries readable at the point where the hook says what it can observe, and
because it decides something that matters: `xdp_tls` puts its two enforcing
detections ahead of its two alert-only ones, so a legacy-TLS ClientHello that
*also* offers RC4 is reported as the TLS violation, which enforces.

The loop names which entry claimed each record, so the ordering is observable at
runtime rather than only in source:

```
event source=2 pid=0 (swapper/0) claimed by 'cipher_suite' (3 of 5): ...WeakCipherSuiteDetected
event source=1 pid=493 (openssl)  claimed by 'payload_anomaly' (2 of 3): ...PayloadAnomalyDetected
```

**There is no "nothing matched" branch.** A hook puts an always-matching
`traffic_observed` entry last, so first-match-wins covers it with no special
case — see [`traffic_observed/DESIGN.md`](traffic_observed/DESIGN.md).

## The enforcement gate

`dispatchVerdict()` is shared by every detection rather than duplicated, because
it is the most consequential logic here and has been got wrong once:

```cpp
if (verdict.actionable) {
    meta.ensurePeerResolved();          // the /proc walk, only here
    if (meta.remote_ip_v4 != 0) {       // ← gate on an ADDRESS, not on
        if (have_full_tuple) push(BlockTcpAction{...});   //  whether resolution ran
        push(BlocklistAddAction{meta.remote_ip_v4, ttl});
    } else {
        log("no connection could be attributed, declining to enforce");
    }
}
push(LogAction{...});                   // always, regardless of severity
```

Two things there are load-bearing:

**The `/proc` walk runs only on the actionable path.** It is the most expensive
step in the pipeline and the large majority of events never reach it, which is
why `EventMeta` carries a resolver rather than a resolved tuple.

**The gate keys on an address being present, not on resolution succeeding.**
Conflating those silently disabled enforcement for every event that already knows
its own address — XDP reads it from the packet, the rate sweeper sets it directly,
so neither carries a resolver, so `ensurePeerResolved()` returned false and the
whole branch was skipped. It stayed hidden because the only enforcement path
exercised live was a uprobe payload anomaly, which does have a resolver. A
regression test pins it now.

A verdict's actions are collected into a `std::vector` and handed over in **one**
call, so `ActionLoop` can run them as a group and report their outcomes together
— see [`actions/DESIGN.md`](../actions/DESIGN.md).

## Could a detection have a suspension point worth optimizing?

A fair question, given `IAction::execute_async()` next door returns an
`awaitable<void>` and a verdict's actions *are* run as an awaited group. The
answer today is no, and the reason is specific enough to be worth writing down —
along with what would have to change for it to become yes.

### The rule that decides it

**A suspension point pays only when something else can make progress while you
wait on an external party.** A socket, a timer, a disk. Not a memcpy, and — the
part that catches people — not a syscall that does its work synchronously in
kernel context.

### Measured against that rule, nothing on this path waits

| Work | Cost | Waits on an external party? |
|---|---|---|
| `inspect()` — memcpy, a few strings, integer compares | ~µs | no |
| `cert_access`: `readlink("/proc/<pid>/exe")` | one syscall | **no** — procfs generates the content *during* the read |
| peer resolution: `/proc/<pid>/fd` scan + `/proc/<pid>/net/tcp` parse | ~505 lines/event, the most expensive step in the pipeline | **no** — same; it is CPU work in kernel context |
| `ConnRateSweeper`: up to 8192 map syscalls per sweep | real, but off the record strand | **no** |

An async read of a procfs file completes almost immediately, because there is no
device to wait for. Awaiting it buys a coroutine frame and nothing else.

### What doing it anyway would cost

1. **A coroutine frame per detection per record**, where there are currently zero. On the path whose entire purpose is returning fast enough not to drop events.
2. **First-match-wins would be gone.** `wait_for_all` runs everything: all five detections would evaluate for one ClientHello, and a winner would be picked *after* doing all the work instead of before. That is strictly more work for the same emitted event.
3. **No parallelism regardless.** One strand plus no suspension points means they would run sequentially anyway.

### What would make it worth doing — the future case

If a detection ever needs to consult something **genuinely remote or slow**: an
IP-reputation lookup, a query to another daemon, a large file, anything over a
socket. Then:

- `IDetection::inspect()` becomes `awaitable<std::optional<Verdict>>`.
- A hook's list gets **split**, not wholesale grouped: keep the cheap ordered short-circuit first, and group only the genuinely-independent slow ones with `wait_for_all`. Paying a network round-trip to discover a TLS 1.0 ClientHello would be a poor trade.
- `DetectLoop::process()` becomes a coroutine, and the bounded-admission accounting has to survive that — the in-flight count is currently decremented at the top of a synchronous handler.

That is a real amount of work for a case that does not exist yet, which is why
the seam is synchronous now rather than speculatively async.

### The optimisation that *is* available today, and why it isn't obvious

It is not a coroutine — it is a **different executor**.

Peer resolution runs synchronously on a `DetectLoop` thread, so one of the two
classification threads is occupied for the duration of a `/proc` scan. Handing
`(meta, verdict)` to a small enforcement executor would free that thread, and it
would only affect the minority of events that reach the actionable branch at all.

**But it is not clearly a win**, and the reason is worth knowing before someone
tries it: it adds a hop before enforcement, and `SOCK_DESTROY` needs the
connection to *still exist*. The synchronous call maximises the chance the socket
is still there to destroy. Trading enforcement reliability for classification
throughput is a real trade, not a free one — and on a BMC that is mostly idle,
the throughput is not currently the constraint.

## Stateful detections without stateful rules

Three detections need to remember things across events, and **no rule holds any
state**. That purity is what makes every rule testable with a hand-built event
and safe to call from either thread, and weakening it for three would weaken it
for all of them. Instead:

```
BPF map (per-source counters) ─▶ ConnRateSweeper ─▶ synthesised event ─▶ pure rule
      state lives here          aggregates on a timer   carries the aggregate
```

Those three have no `IDetection` and never reach `submit()`: they have no
ring-buffer record at all. The sweeper reads the map every 2s and calls their
rules directly.

## A singleton, and its one honest cost

`getInstance()`, like `ActionLoop`. There is one pipeline per process and every
hook's handler needs to reach it; passing a reference down through the BPF
lifecycle to each hook just to call one method was the alternative, and it made
`BpfProgram` know about classification.

Unlike `ActionLoop` this loop needs configuration, so construction and
configuration are separate: `getInstance()` returns a loop whose threads are
already running but which has nothing to dispatch to yet, and `configure()`
supplies the rest exactly once. A record arriving before that is counted and
reported, never silently discarded.

The cost: a singleton is not constructible per-scenario, and `tests/detectloop/`
builds five separate loops on purpose, one per scheduling property. Rather than
lose four of those checks, `createForTesting()` exists as a documented, narrowly
named factory for the harness — a visible crack in the pattern instead of a
hidden loss of coverage.

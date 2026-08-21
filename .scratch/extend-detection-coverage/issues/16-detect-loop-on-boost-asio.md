# 16 — Rebuild DetectLoop on Boost.Asio, the same way ActionLoop is built

**What to build:** Make `DetectLoop` an Asio event loop — `io_context` +
`executor_work_guard` + worker thread(s), work posted onto the executor, and
the periodic sweep driven by an Asio timer — instead of the hand-rolled
`std::thread` + `std::mutex` + `std::condition_variable` + `std::deque` it
uses today. Behaviour must not change.

**Blocked by:** None — 11 (which created `DetectLoop`) and 05/06 (which added
the sweep) are both done.

**Status:** done

## Why

The project has two long-lived worker loops and they are built two different
ways. `ActionLoop` is an `io_context` with a work guard and a thread calling
`run()`; `DetectLoop` is a bespoke condvar queue with its own clock
arithmetic. One idiom for "background loop" is worth having on its own terms:
anyone who has read one loop can then read the other, and the concurrency
primitives that are easy to get subtly wrong (timed waits, spurious wakeups,
shutdown races) come from a library that has already got them right instead
of from this repo.

Concretely, three hand-rolled things go away:

- `cv_.wait_for(...)` with a predicate, plus the `next_sweep` deadline
  arithmetic at the top of `run()` — replaced by a `steady_timer` that
  rearms itself.
- The `stop()` dance that has to distinguish "already stopping, just join"
  from "first call, clear the queue and notify" — replaced by resetting the
  work guard and stopping the context.
- The `queue_`/`mutex_`/`cv_` triple, which exists only to hand bytes from
  the poll thread to the worker — that is what an executor is.

## The two properties that must survive

`DetectLoop.hpp`'s current class comment argues *against* Asio in two
sections (`WHY NOT AN ActionLoop ACTION`, `WHY A BOUNDED QUEUE RATHER THAN
ActionLoop's SHAPE`). Those arguments were about specific hazards, not about
Asio itself, and both hazards are avoidable while still using an
`io_context`. They are the acceptance criteria that matter:

**1. Admission stays bounded.** `asio::post` and `co_spawn(..., detached)`
are unbounded queues. On a ~1GB BMC, trading a dropped event for an OOM is a
bad trade — the daemon dying takes *all* detection with it, where a drop
costs one event. So the depth cap and the drop-newest-and-count policy have
to be preserved explicitly; the executor does not provide them. Note that
`submit()` is called from libbpf's ring-buffer callback and is `noexcept`,
so admission control cannot allocate-or-throw its way out of a full queue
either.

**2. The sweep does not starve under load.** This is the exact bug ticket 05
shipped and had to fix: the sweep originally ran only when the queue was
empty, so a flood — which generates events — starved it, and rate detection
switched off precisely when it was needed. A single-threaded `io_context`
reintroduces a weaker form of this by FIFO fairness alone: when the timer
expires its handler queues *behind* every record already posted, so a deep
backlog delays the sweep by (backlog × per-event cost). With a 2s sweep
interval against a fixed 10s counting window
(`HTTPS_GUARD_CONN_RATE_WINDOW_SEC`), a multi-second delay can let a window
roll unobserved and lose a flood entirely. Whatever shape is chosen, a
backlog of records must not be able to delay the sweep past its interval.

## Design notes

**Post, don't `co_spawn`.** `ActionLoop` uses `co_spawn` because `IAction`'s
entry point is a coroutine (`awaitable<void> execute_async()`). Nothing in
the classify path awaits anything — `process()` and `classifyAndDispatch()`
are straight-line synchronous code — so `asio::post` is the honest primitive
and a coroutine frame per event would be pure overhead. "Built like
ActionLoop" means the same loop scaffolding, not the same handler shape.

**Record ordering.** FIFO across records is worth keeping: the drop-newest
policy is justified by the queue holding "a coherent prefix of history", and
emitted log events reading in arrival order is worth something during an
incident. So records must be serialized against each other rather than run
concurrently on an arbitrary thread.

**Concurrent classification is safe, and that is load-bearing if the sweep
runs off the record path.** `classifyAndDispatch()` touches only:
`detectors_` (const, and every detector is documented stateless —
`detections/CLAUDE.md`, "Stateful rules without stateful detectors"),
`output_path_` (const), `action_loop_` (Asio's `co_spawn` is thread-safe),
and `std::cerr`. If the resolution to property 2 is to let the sweep run
off-thread from the record stream, then that statelessness invariant becomes
a threading requirement and needs saying where a future detector author will
see it — a detector that quietly grows a member would become a data race,
not just a design-guideline breach.

**One `hg_event` caveat.** `hg_event`'s lazy peer resolution mutates
`mutable` members (`peer_attempted_`, `peer_ok_`) inside
`ensurePeerResolved()`. That is fine only because each event object is
touched by exactly one classification at a time — worth checking still holds
under whatever concurrency shape lands, rather than assuming.

- [x] `DetectLoop` owns an `io_context`, a work guard and its worker
      thread(s), matching `ActionLoop`'s construction and teardown shape; no
      `condition_variable` and no hand-written deadline arithmetic remain
- [x] The sweep is driven by an Asio timer that rearms itself, not by a timed
      wait
- [x] Admission is still bounded at a fixed depth, with drop-newest, a drop
      counter, and the existing rate-limited "queue full" log line — verified
      by a test that floods `submit()` past the cap and asserts the count
      rises while memory does not grow without limit
- [x] A backlog of queued records cannot delay the sweep beyond its interval
      — demonstrated rather than asserted, since this is the failure ticket
      05 already shipped once
- [x] Per-item `try/catch` survives: one throwing event costs that event, not
      the daemon (`submit()` and the handlers stay `noexcept` at the seams
      libbpf calls)
- [x] Oversized-record rejection (`> HG_MAX_RAW_EVENT_SIZE`) and the
      undersized-record check are unchanged
- [x] Shutdown still abandons rather than drains the backlog, still reports
      how much was abandoned, and `stop()` is still idempotent — including
      the case where the worker thread failed to start at all
- [x] The enforcement gate is untouched: `evt.remote_ip_v4 != 0` decides,
      *not* whether `ensurePeerResolved()` returned true (ticket 11's
      regression — a resolver-less XDP or synthesised event must still
      enforce)
- [x] Host-side unit tests still build and pass; if `detections_lib` gaining
      a link-time Boost dependency affects the test target, that is resolved
      rather than worked around by excluding the file
- [x] Cross-compiles clean from `cleansstate` — Boost.Asio in a new
      translation unit is exactly the kind of change that builds host-side
      and fails on the target
- [x] Verified on QEMU: a uprobe payload anomaly still enforces end to end,
      and a connection-rate flood is still reported — the sweep timer is new
      code on the path that ticket 05's whole value depends on
- [x] `DetectLoop.hpp`'s class comment is rewritten: its two "why not Asio"
      sections are now wrong as written, and replacing them with how the two
      hazards are actually handled is the difference between a comment that
      documents a decision and one that misleads the next reader

## Comments

Landed as specified. `DetectLoop` is now an `io_context` + work guard +
threads calling `run()`, matching `ActionLoop`'s construction and teardown.
Gone: the `condition_variable`, the `deque`, the `next_sweep` deadline
arithmetic, and the two-branch `stop()` that had to distinguish "already
stopping" from "first call, clear and notify". Shutdown is now
`work_guard_.reset()` + `io_context_.stop()`, which abandons queued handlers
— the same policy as before, expressed by the library instead of by hand.

### The design decision that mattered

The two hazards the ticket flagged both needed handling, and one of them
turned out to be much more real than "flagged in a comment" suggests.

**Admission** is bounded by an atomic in-flight count claimed in `submit()`
before `post()` and released in the handler. Drop-newest, counted,
rate-limited log line — unchanged in behaviour.

**Sweep starvation** is handled by running **two** threads and putting
records on a `strand` while the sweep timer stays *off* it. Records therefore
stay serialized and in arrival order (which is what makes drop-newest leave a
coherent prefix), while an expiring timer can be picked up by the other
thread immediately rather than queueing behind the backlog.

That is not a theoretical concern. Measured against a deliberate 3000-event
backlog with 5ms parses, over a 9-second window:

| Threads | Sweeps in 9s | Worst gap |
|---|---|---|
| 1 | **0** | — (never ran) |
| 2 | 4 | 2000ms (== the interval) |

A single-threaded `io_context` reproduces ticket 05's bug in a subtler form:
rate detection switches off exactly under load, while looking present. Worth
recording that the naive translation of this class to Asio would have
silently regressed the feature it was most recently fixed for.

**The cost of that choice, stated plainly:** the sweep can now run
concurrently with a record's classification, so detector statelessness stops
being a design guideline and becomes a threading requirement. Verified rather
than assumed — the harness runs clean under TSan as well as ASan/UBSan — and
said explicitly in `DetectLoop.hpp` and `detections/CLAUDE.md`, because the
next person to add a detector needs to know a member variable is now a data
race and not a style breach.

**`post()`, not `co_spawn()`**, as the ticket anticipated: nothing on the
classify path awaits, so a coroutine frame per event would be pure overhead.

### On the acceptance criterion asking for tests

Met, but not the way the criterion implies, and the difference is worth
stating. `DetectLoop.cpp` cannot join `https_guard_tests`: that target is
deliberately free of kernel dependencies, and DetectLoop pulls in the actions
plus `nlohmann/json` while `ConnRateSweeper.cpp` calls libbpf. (`ActionLoop`
itself has no unit test at all for the same reason.)

So the tests live in `tests/detectloop/`, compiling the *real*
`DetectLoop.cpp` and `ConnRateSweeper.cpp` with link-time doubles for the
collaborators — nine checks covering bounded admission, arrival order, the
sweep-under-backlog property above, the throwing-detector boundary, the
oversized/null/empty `submit()` paths and `stop()` idempotence. Recording the
timestamp of each `bpf_map_get_next_key(fd, nullptr, …)` is how sweep cadence
is observed.

Folding it into CMake is a real follow-up, not a dead end: the top-level
`CMakeLists.txt` already requires `nlohmann_json` and `libbpf` to configure,
so a second test executable would build wherever the project does. It was
left out only because the development host used here has no `cmake` and the
change could not be verified — adding an unverifiable target to a build other
people depend on is worse than a documented build command that has been run.

### Verification

- 59/59 existing unit tests still pass (unchanged — they touch no scheduling).
- Harness: 9/9 pass under ASan/UBSan, and clean under TSan.
- The 1-thread counterfactual above, run deliberately to check the two-thread
  choice was not superstition.
- Clean cross-compile from `cleansstate`, twice — once for the rewrite and
  once after adding the two `SRC_URI` entries.
- QEMU, fresh boot of a fresh image: hooks attach (`2 of 3`, LSM expected to
  fail on ARM32); uprobe enforcement works end to end —

  ```
  BlockTcpAction: destroyed TCP connection 127.0.0.1:42570 -> 127.0.0.1:443
      reason=Attack signature detected from process 'openssl' (PID 521), rule '/etc/passwd'
  ```

  with the client observing it (`openssl s_client` exited 103, connection
  aborted), and both `HttpsPayloadAnomalyDetected` and `HttpsTrafficObserved`
  reaching the Redfish log. The sweep timer works against real counters: a
  150-connection burst from the host produced
  `per-source counters: 1 source(s); busiest 151 attempts` — 150 plus the SSH
  connection. A `systemctl restart` re-attached everything (`2 of 3` again),
  so ticket 09's fix still holds.

### Two things found on the way, neither in scope

- **A stale QEMU from an earlier session was still holding port 2222**, and
  the first journal I read came from an 18-hour-old daemon running the
  *previous* image. It looked at first like a sweep spinning in a tight loop.
  Worth knowing before trusting any QEMU observation: check the image
  timestamp in the `runqemu` line, not just that SSH answers.
- **`ConnRateSweeper`'s observability line goes to `std::cout`, which is
  block-buffered** when journald owns the pipe, so those lines arrive in ~4KB
  batches with identical timestamps — up to several minutes late, and only
  flushed in full when the daemon exits. Every other diagnostic in the daemon
  uses `std::cerr` and appears immediately. It is a one-line fix
  (`std::cerr`, or `std::unitbuf`) but it is pre-existing and unrelated to
  this ticket, so it is left alone and recorded here instead. It did make
  verification materially harder — the flush had to be forced with a daemon
  restart.

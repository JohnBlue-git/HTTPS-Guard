# 01 — Concurrent, await-ready classification in DetectLoop::process()

**What to build:** `submit()` posts onto `record_strand_` via `asio::co_spawn` (detached)
instead of `asio::post`. `handleRecord()`/`process()` become coroutines. `process()`
evaluates all of a record's submitted detections concurrently via
`asio::experimental::make_parallel_group` + `wait_for_all()`, then picks the
lowest-list-index verdict among the gathered results — order still decides the winner,
but there is no early-exit: every submitted detection is now invoked for every record,
in preparation for a future I/O-bound detection that needs to suspend inside
`inspect()`. `detections/DESIGN.md`'s "`post()`, not `co_spawn()`" section is rewritten
to state the new rationale instead of contradicting the shipped code.

**Blocked by:** None — can start immediately.

**Status:** ready-for-agent

- [ ] `submit()` schedules `handleRecord(rec)` via `asio::co_spawn(record_strand_, ..., asio::detached)`, not `asio::post`
- [ ] `handleRecord()` and `process()` are coroutines (`boost::asio::awaitable<void>`)
- [ ] `process()` fans out every submitted detection's `inspect()` call concurrently via `asio::experimental::make_parallel_group` + `wait_for_all()`, gathers results in original list order, and dispatches the lowest-index non-`nullopt` verdict — matching today's "first match in list order wins" outcome
- [ ] Every detection in a record's list is invoked even after an earlier one has already produced a verdict (no early-exit)
- [ ] `enableRateSweeps()`'s `asio::post(io_context_, ...)` call is left unchanged
- [ ] `rec.detections[]`'s array-of-`IDetection*` representation is left unchanged
- [ ] `detections/DESIGN.md`'s "`post()`, not `co_spawn()`" section is rewritten to explain the new tradeoff (readiness for a future I/O-bound detection) rather than contradicting the code
- [ ] All existing `tests/detectloop/detectloop_harness.cpp` checks pass unchanged: bounded admission (drop-newest past the cap), FIFO order across records (strand), the rate sweep not starved by a record backlog, a throwing detection costing one event not the daemon, the submitted pointer view not dangling, oversized/undersized records and `stop()` idempotence
- [ ] A new `detectloop_harness.cpp` case: a record submitted with more than one detection where an early-index detection matches — assert every later-index detection in that record's list was still invoked (no early-exit), and that the dispatched verdict is still the one from the lowest matching index

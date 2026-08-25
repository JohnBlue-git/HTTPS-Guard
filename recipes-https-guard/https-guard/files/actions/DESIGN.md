# `actions/` — carrying out the response

A verdict is a decision; this layer is what happens because of it. Three
countermeasures, one dispatcher, and a hard rule: **nothing here decides
anything.** By the time an action is constructed, the question has been answered.

```
detections/  ──── Verdict{severity, message_id, message, actionable} ────▶  actions/
                              │
                  dispatchVerdict() constructs:
                              │
        ┌─────────────────────┼─────────────────────┐
        ▼                     ▼                     ▼
   LogAction            BlockTcpAction       BlocklistAddAction
   (always)             (actionable +        (actionable +
                         full 4-tuple)        an address)
```

Per-action rationale: [`log/`](log/DESIGN.md), [`tcp/`](tcp/DESIGN.md),
[`blocklist/`](blocklist/DESIGN.md). This document is `ActionLoop`.

## ActionLoop

A singleton wrapping a Boost.Asio `io_context` with a work guard and one thread
calling `run()`. Two entry points:

`pushAction()` spawns one action detached — used by `action_runner` and by
anything with a single thing to do.

`pushActions()` takes a verdict's **whole response** and runs it as a group:

```cpp
std::vector<Op> ops;
for (auto& action : actions)
    ops.push_back(co_spawn(executor, action->execute_async(), deferred));

auto [order, exceptions] =
    co_await make_parallel_group(std::move(ops))
        .async_wait(wait_for_all(), use_awaitable);
```

Collect the launched operations, then wait on all of them. `co_spawn(...,
deferred)` yields an operation that has *not started*, and `parallel_group`
starts them together — this is what other coroutine libraries spell `when_all`;
Asio has no function by that name. The ranged overload is the one used, because
the count is a runtime property of the verdict.

### Why a group rather than three separate pushes

A verdict produces up to three actions, and **two of the three genuinely wait**:

| Action | Suspends on |
|---|---|
| `BlockTcpAction` | `co_await desc.async_wait(wait_write)`, then `wait_read` — the netlink round-trip, via epoll |
| `LogAction` | `co_await acquire_stream()` (a coroutine-aware file lock that can queue behind another writer), then `co_await async_write` |
| `BlocklistAddAction` | nothing — `bpf_map_update_elem()` is a synchronous syscall |

Pushed one at a time on a single-threaded loop, those two ran strictly one after
another: the netlink epoll wait was dead time during which the log write could
have been in flight. As a group they interleave at their suspension points.

The second reason matters more. Three detached spawns had **no completion
point**, so nothing anywhere knew when a verdict's response had finished or which
part of it had failed — each action logged into the void independently. The group
returns a per-operation `exception_ptr`, so the loop can say:

```
Error: 2 of 3 action(s) for this verdict did not complete
```

That is worth having here specifically, because a silently failing
countermeasure is this project's most-repeated bug: `SOCK_DESTROY` failed on
every single event for a long time while the Redfish log looked perfectly
healthy.

### Why coroutines here, and `post()` in DetectLoop

Because actions do I/O and `DetectLoop` does not. `LogAction` writes a file and
`BlockTcpAction` does a netlink round-trip — work that genuinely waits, and that
should not hold up the *next* action or the thread that queued it.
`IAction::execute_async()` is therefore an `awaitable<void>`, and `co_spawn` is
the natural primitive. (`BlocklistAddAction` is the exception that proves the
shape is about the interface rather than every implementation: it never suspends,
and costs nothing by being expressed the same way.)

`DetectLoop` is the opposite: `inspect()` is straight-line CPU work with nothing
to await, so it posts plain handlers and a coroutine frame per event would be
pure overhead. The two loops look similar and are not interchangeable.

The full argument — including what would make an awaitable `inspect()` worth
having, and why the obvious optimisation on that path is a different executor
rather than a coroutine — is in
[`detections/DESIGN.md`](../detections/DESIGN.md#could-a-detection-have-a-suspension-point-worth-optimizing).

### Why unbounded here, when DetectLoop is bounded

`co_spawn(..., detached)` is an unbounded queue, and `DetectLoop` went to real
trouble to avoid exactly that. The difference is what feeds them.

`DetectLoop` is fed by the ring buffer — an adversary can generate records at
line rate, so admission must be capped or a flood becomes an OOM, and on a ~1GB
BMC the daemon dying takes *all* detection with it.

`ActionLoop` is fed by `DetectLoop`, which is already bounded, and only for
events that produced a verdict. Its input rate is therefore capped by the stage
above it. Adding a second bound would cap a flow that is already capped, and
introduce a new failure mode — dropping a countermeasure for an attack that was
correctly detected, which is worse than the queue being briefly deep.

Worth stating rather than assuming, because "the other loop is bounded, why isn't
this one" is a reasonable question to arrive with.

### One failed action costs that action

`wait_for_all` means exactly that: a netlink call that fails, a log file that
cannot be opened, a BPF map that was never adopted — each is reported and the
others still run to completion. Enforcement is best-effort, and partial
enforcement beats none. The group's joint reporting is what stops a partial
failure being *invisible*, which is how
`SOCK_DESTROY` managed to fail on every single event for a long time while the
Redfish log looked healthy — see [`tcp/DESIGN.md`](tcp/DESIGN.md).

### Producers

The header carries a note that the loop is designed single-producer. That is now
understated: `asio::co_spawn` onto an `io_context` is thread-safe, and both
`DetectLoop` threads push actions concurrently. The note is conservative rather
than wrong, and the concurrency is exercised every time the connection-rate sweep
overlaps a record.

## `action_runner`

A standalone binary (`core/main.cpp`) that starts the loop on its own, the
counterpart to `detect_runner` for the detection pipeline. It exists so the layer
can be smoke-tested without a kernel, a BPF object, or root.

## What actions are *not* allowed to do

- **Decide.** No thresholds, no severity, no message text beyond formatting. All of that is in the verdict.
- **Block the dispatcher.** Anything slow is `co_await`ed, not called.
- **Assume they ran.** Nothing downstream depends on an action having succeeded; the Redfish event is emitted either way, which is why a failed countermeasure is a log line rather than a state change.

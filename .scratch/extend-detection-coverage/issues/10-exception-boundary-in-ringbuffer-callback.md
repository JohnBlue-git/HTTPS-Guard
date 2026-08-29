# 10 — Add an exception boundary so one bad event can't kill the daemon permanently

**What to build:** Make a throw anywhere in the detect→classify path cost one dropped event rather than the entire daemon. Today there is no exception boundary between libbpf's ring-buffer callback and everything it calls, and the callback is `noexcept` — so any escaping exception is `std::terminate()`.

**Blocked by:** None — can start immediately

**Status:** superseded by 11 — Move parse/classify/dispatch off the ring-buffer poll thread into a DetectLoop

**Superseded because:** ticket 11 moves this entire code path onto a worker thread shaped like `ActionLoop`, and a per-item `try/catch` there — the same pattern `ActionLoop` already uses — is exactly the boundary this ticket asks for, in a better place. Adding a `try/catch` inside `ringBufferHandler` first would be work thrown away by 11. The requirement itself is not dropped: it is carried as an acceptance criterion on 11, along with the `noexcept`-markers question raised below. Read this ticket for the *reasoning*; implement it as part of 11.

## The problem

`HttpGuardProgram::ringBufferHandler(void*, size_t) noexcept` is the single funnel every event passes through, and from there it calls, all inside that `noexcept`:

- each hook's `parseEvent()` (also `noexcept`) — which allocates `std::string`s via `boundedString`, and for XDP a `std::vector` via `cipher_suites.assign`
- `ProcPeerResolver::getTcpSockets()` (also `noexcept`) — `std::ifstream`, `std::istringstream`, `std::vector::push_back`, `std::stoi`/`std::stoul`
- `IDetector::evaluate()` — **not** declared `noexcept`, and builds verdict messages by string concatenation
- `RedfishEventMessage::format()` — nlohmann::json construction and `dump()`
- `std::make_unique` for each dispatched action

`noexcept` doesn't prevent throwing; it converts a throw into `std::terminate()` with no unwinding. So `std::bad_alloc` under memory pressure — plausible on a ~1GB BMC — or any unguarded parse failure aborts the process instead of degrading.

## Why the consequence is worse than "systemd restarts it"

Observed live this session: after repeated fast exits, systemd reported

```
https-guard-daemon.service: Start request repeated too quickly.
https-guard-daemon.service: Failed with result 'start-limit-hit'.
```

and the unit stayed `failed` until `systemctl reset-failed` was run by hand. So a *deterministic* crash doesn't self-heal — it permanently disables all detection with no alert, and requires console access to recover.

Ticket 09 compounds it: even a *successful* restart no longer reattaches XDP, so wire-level detection (TLS version on the wire, cipher suite, SNI) stays dead afterward even though the daemon reports itself healthy.

## Prior art in this repo

`ActionLoop` already does exactly the right thing on the dispatch side — `actions/core/ActionLoop.cpp` catches per-action exceptions (`catch (std::exception&)` then `catch (...)`), logs, and keeps the loop alive, so one failing countermeasure can't take the process down. The detect/classify side simply never got the same treatment. This ticket is about extending an established pattern, not introducing a new one.

- [ ] A throw originating anywhere inside the ring-buffer callback is caught at that boundary, logged with enough context to identify the event source, and results in the event being dropped while the poll loop continues
- [ ] Verified by deliberately injecting a throw (a temporary test-only detector or a forced allocation failure) that the daemon logs and keeps running, rather than aborting — asserting on the *observed* behavior, not just the presence of a `catch`
- [ ] Decide whether the `noexcept` markers on `parseEvent`/`getTcpSockets`/`ringBufferHandler` should stay: they are currently load-bearing in the wrong direction (promising something the bodies don't honor). Either drop them where the body genuinely allocates, or keep them and guarantee it — state which and why, since "noexcept function that allocates" is what makes this failure mode silent
- [ ] Confirm the catch does not swallow genuinely fatal programming errors in a way that hides bugs during development — a repeated-throw counter or rate-limited log is worth considering so a persistent failure is visible rather than an endless quiet drop
- [ ] Consider whether the systemd unit's restart policy should tolerate more retries, or whether permanent-failure-after-N is actually the safer default for a security daemon; either way, record the reasoning rather than leaving it implicit

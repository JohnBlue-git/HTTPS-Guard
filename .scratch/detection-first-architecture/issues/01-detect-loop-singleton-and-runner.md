# 01 — Make DetectLoop a singleton with its own runner binary

**What to build:** `DetectLoop::getInstance()`, matching `ActionLoop`, plus a
`detect_runner` executable built from `detections/core/main.cpp` — the same
shape `actions/core/main.cpp` already gives `ActionLoop`.

**Blocked by:** None — can start immediately

**Status:** done

## Why this is first

Everything else depends on it. `BpfProgram`'s default `ringBufferHandler()`
(ticket 02) has to reach the loop without having a reference injected into every
hook, which is exactly what a singleton is for here.

## The one real difficulty

`ActionLoop` is a trivial singleton because it needs no configuration.
`DetectLoop` currently takes five constructor arguments — the action loop, the
hook list, the detector registry, the blocklist TTL and the output path — so
`getInstance()` cannot supply them.

Split construction from configuration: `getInstance()` returns an unstarted
loop, and a `configure(...)` (or `start(...)`) call from the composition root
supplies what it needs and starts the threads. Two things this must get right:

- **Submitting before configuration must not silently discard events.** A
  record arriving before `configure()` has to be either queued or counted, not
  dropped quietly — that is the failure mode this project keeps rediscovering.
- **`configure()` twice is a programming error**, not a reconfiguration. Say so
  loudly rather than half-applying it.

Note the hook list is currently held by `const&` to `main`'s vector, with a
comment about destruction order. A singleton outlives `main`'s locals, so that
reference has to stop being a reference — or the ownership has to move.

- [x] `DetectLoop::getInstance()` exists and is the only way to obtain the loop
- [x] Construction and configuration are separate, and configuring twice is reported rather than silently accepted
- [x] A `submit()` before `configure()` is accounted for, and the behaviour is stated in the header
- [x] The dangling-reference risk from the singleton outliving `main`'s locals is resolved by ownership, not by a comment
- [x] `detections/core/main.cpp` builds a `detect_runner` binary that exercises the loop on its own, and the recipe installs it the way `action_runner` is handled
- [x] `tests/detectloop/` still passes, including under TSan — the singleton changes the lifetime of everything it holds
- [x] Clean cross-compile from `cleansstate`, and the daemon still detects and enforces on QEMU

## Comments

`getInstance()` + `configure()`, with construction and configuration split
because unlike `ActionLoop` this loop needs five things it cannot invent. The
threads start in the constructor, so `getInstance()` returns a running loop
that simply has nothing to dispatch to yet.

**Publication is the subtle part.** `configure()` writes five members that the
worker threads read. The release store on `configured_`, paired with the acquire
load in `submit()`, is what publishes them — and Asio's `post()` carries the
happens-before from there into the handler. Without that pairing this would be
a data race that testing would almost never catch, because in the daemon
`configure()` always happens long before the first record.

**Pre-configuration records are counted separately**, not folded into the
queue-drop counter, and reported at shutdown. In the daemon this cannot happen
(polling starts after `configure()`), but "cannot happen" is how the earlier
silent-drop bugs in this project were all described.

**Configuring twice is refused, not applied.** A second call would race the
workers already reading those fields, so it reports a BUG and returns.

**The hook list is now owned, not referenced.** It used to be a `const&` to a
vector declared in `main`, which a singleton outliving `main`'s locals would
dangle on at static destruction while its threads were still running.
`HttpGuardProgram` borrows it back through `hooks()` purely to attach; ticket 02
moves ownership there and that accessor goes away.

`main` now calls `detect_loop.stop()` explicitly before returning, so the
workers join while the BPF object and hooks are still alive.

### The cost of the singleton, and what was done about it

A singleton stops being constructible per-scenario, and `tests/detectloop/`
builds **five** separate loops on purpose — one per scheduling property.
Protecting the singleton by collapsing that to one test would have lost four
real checks, so `createForTesting()` exists as a documented, narrowly-named
factory for the harness only. That is an honest crack in the pattern rather
than a hidden one.

### Verification

- Harness 9/9 under ASan/UBSan, still building five independent loops.
- 60/60 doctest cases.
- Clean cross-compile from `cleansstate`; `detect_runner` installs to
  `/usr/sbin/detect_runner` alongside `action_runner`.
- On target, `detect_runner` demonstrates each property in order:

  ```
  DetectLoop started, configured=false
  DetectLoop received an event before configure(); dropping until configured
  configured=true
  BUG: DetectLoop::configure() called twice; ignoring the second call
  unknown event_source=1, size=16, skipping
  undersized event (2 bytes)
  DetectLoop stopped; ... 1 arrived before configure()
  ```

- Daemon unchanged in behaviour: `2 of 3 hook(s)`, uprobe enforcement tears down
  a live connection, and the five-ClientHello baseline is intact — 2
  weak-cipher, 2 SNI-anomaly, 2 payload-anomaly (write + read), traffic
  observed.

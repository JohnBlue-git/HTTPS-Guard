# actions/ — Dispatch layer

Asynchronous countermeasures, run through `ActionLoop` (Boost.Asio coroutines) so neither the ring-buffer poll thread in `../programs/` nor the classification threads in `../detections/` ever block on I/O. This directory predates the `programs`/`detections` split and was not restructured by it — its own shape, one subdirectory per action family with a `DESIGN.md` each, was already the pattern the rest of the tree later adopted.

`DESIGN.md` here covers `ActionLoop`: why coroutines belong on this side and plain handlers on the detection side, why the loop is deliberately unbounded when `DetectLoop` is bounded, and how a verdict's actions are run as one awaited group.

## Layout

- **`core/`** — `ActionLoop.{hpp,cpp}`, the dispatcher. Two entry points: `pushAction()` spawns one action detached, and **`pushActions()` takes a verdict's whole response and runs it as an awaited group** (`make_parallel_group` + `wait_for_all`), which is what gives a single completion point and joint failure reporting. `main.cpp` builds `action_runner`, a manual smoke-test binary for the loop alone — not part of the daemon.
- **`log/`** — `LogAction` (async file write via `AsyncFileStreamManager` in `async_mutex.hpp`) and `redfish_event_message.hpp` (`RedfishEventMessage`: formats a `Verdict` + `EventMeta` into the Redfish JSON the event log expects). Dispatched unconditionally for every verdict, regardless of severity. See its `DESIGN.md` for the four-field MessageId requirement and why file writes need a coroutine-aware lock.
- **`blocklist/`** — `Blocklist` (singleton wrapper around the shared BPF hash map) and `BlocklistAddAction`. `blocklist.bpf.h` here is the BPF-side counterpart, `#include`d by `../programs/xdp_tls/ebpf/xdp_tls.bpf.h` — the one place a raw BPF header lives outside `programs/`, because the map is genuinely an action-layer concern (enforcement state) rather than a hook concern. Its `DESIGN.md` covers the two-tier feedback loop and the every-port blast radius.
- **`tcp/`** — `TcpDestroyer` (RAII around a Netlink `SOCK_DESTROY` request, awaiting the socket through epoll rather than blocking) and `BlockTcpAction`. Its `DESIGN.md` carries the `-ENOENT` story: three wrong explanations recorded before the cause turned out to be a missing `CONFIG_INET_DIAG`.

## When an event is actionable

`dispatchVerdict()` (in `../detections/core/engine/`) is the only caller. It
reaches in here when a verdict's `actionable` is true **and** the event carries a
non-zero `remote_ip_v4` — the peer's address. `EventMeta`'s fields are named by
role (`local_*`/`remote_*`) rather than by direction precisely so "the thing you
would blocklist" is unambiguous; see its header for the bug that naming fixed.

The gate is on **an address being present**, not on whether resolution ran. Uprobe
events need `ProcPeerResolver` to have resolved a socket first and it can fail
(logged, fail-closed); XDP and synthesised rate events carry an address directly
and no resolver at all — so gating on resolution succeeding silently disabled
enforcement for both, once.

`BlockTcpAction` additionally needs a **full 4-tuple**, which a rate violation
does not have: it is attributed to an address, not a socket. All of the
applicable actions plus `LogAction` are collected into one vector and handed over
in a single `pushActions()` call.

## Adding a new action

Implement `IAction` — `boost::asio::awaitable<void> execute_async()` — and
construct it in `dispatchVerdict()`. `BlockTcpAction` is a reasonable template.

Two rules:

- **Decide nothing.** Severity, message ID and message text all arrive in the `Verdict`. An action formats and performs; it does not classify.
- **Await anything slow.** Do not call blocking I/O inside `execute_async()` — the loop is single-threaded, so a blocking call stalls every other action. `TcpDestroyer` shows the pattern: wrap the fd in a `posix::stream_descriptor` and `co_await async_wait()` for readiness.

Give it a `DESIGN.md` in its directory, like the three that exist.

# actions/ — Dispatch layer

Asynchronous countermeasures, run through `ActionLoop` (Boost.Asio coroutines) so the ring-buffer poll loop in `../programs/` never blocks on I/O. This directory predates the `programs`/`detectors` split and wasn't restructured by it — its own internal shape (one subdirectory per action family) was already the pattern the rest of the tree later adopted.

## Layout

- **`core/`** — `ActionLoop.{hpp,cpp}`, the dispatcher itself (`pushAction()` queues, a background thread runs `io_context`). `main.cpp` here builds `action_runner`, a manual smoke-test binary for `ActionLoop` alone — not part of the daemon.
- **`log/`** — `LogAction` (async file write via `AsyncFileStreamManager` in `async_mutex.hpp`) and `redfish_event_message.hpp` (`RedfishEventMessage`: formats a `Verdict` + `hg_event` into the Redfish JSON the event log expects). `LogAction` is dispatched unconditionally for every event, regardless of severity.
- **`blocklist/`** — `Blocklist` (singleton wrapper around the shared BPF hash map) and `BlocklistAddAction`. `blocklist.bpf.h` here is the BPF-side counterpart, `#include`d by `../programs/xdp_tls/xdp_tls.bpf.h` — the one place a `detectors`/`programs`-style raw BPF header lives outside `programs/`, because the map itself is genuinely an action-layer concern (enforcement state), not a hook concern.
- **`tcp/`** — `TcpDestroyer` (RAII around a Netlink `SOCK_DESTROY` request) and `BlockTcpAction`.

## When an event is actionable

`HttpGuardProgram::ringBufferHandler` (in `../programs/core/`) only reaches into here when a detector's `Verdict::actionable` is true *and* the event carries a non-zero `src_ip_v4` — uprobe events need `ProcPeerResolver` to have resolved a socket first (not guaranteed; logged as a warning if it fails), XDP events always carry one from the packet headers. On an actionable event: `BlockTcpAction` then `BlocklistAddAction`, both dispatched, then `LogAction` (always, actionable or not).

## Adding a new action

No formal `IAction` interface exists — each action is its own class taking whatever constructor arguments it needs, with an `execute_async()`-shaped coroutine method `ActionLoop` spawns. Follow an existing one's shape (`BlockTcpAction` is a reasonable template) rather than inventing a new pattern.

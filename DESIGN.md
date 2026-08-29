# HTTPS-Guard — Design Reference

> **This is the detailed reference.** For build instructions, QEMU setup, and deployment, see the [top-level README](README.md). For a diagram-first architecture walkthrough, see [DESIGN.html](DESIGN.html) (predates the current file layout — see the [Doc Rewrites ticket](.scratch/extend-detection-coverage/issues/07-doc-rewrites.md) once it lands).

This document covers the complete source code under `recipes-https-guard/https-guard/files/` — the eBPF programs, C++ daemon, enforcement actions, BitBake recipe, and security model. HTTPS-Guard implements a **Detect → Classify → Dispatch** pipeline, and the source tree is organized around exactly those three stages:

- **`programs/`** (Detect) — attaches BPF hooks (uprobe primary, XDP auxiliary) and parses their raw ring-buffer events into a common representation. Purely observational; makes no security decisions.
- **`detections/`** (Classify) — pure, synchronous rules that turn a parsed event into a verdict (severity, message, actionability), or no verdict at all.
- **`actions/`** (Dispatch) — asynchronous countermeasures (log, kill the TCP connection, blocklist the source) triggered by an actionable verdict.

## Table of Contents

- [Source Code Structure](#source-code-structure)
- [Build System](#build-system)
- [The Detect Layer: `programs/`](#the-detect-layer-programs)
- [The Classify Layer: `detections/`](#the-classify-layer-detectors)
- [The Dispatch Layer: `actions/`](#the-dispatch-layer-actions)
- [Event Processing Pipeline](#event-processing-pipeline)
- [Security Model](#security-model)
- [Configuration](#configuration)
- [BitBake Recipe](#bitbake-recipe)

## Source Code Structure

```
files/
├── CMakeLists.txt                          # Root: project setup, deps, add_subdirectory(actions|detectors|programs|tests)
├── https-guard.conf                        # EnvironmentFile for systemd units
├── scripts/
│   └── gen_ssl_offset.c                    # Build-time ssl_st.version offset detector
├── service/
│   ├── https-guard-daemon.{service,sh}
│   ├── https-guard-event-bridge.{service,sh}
│   └── simulated-event-generator.{service,sh}
├── programs/                               # Detect layer
│   ├── CMakeLists.txt                      # programs_lib (OBJECT) + the BPF object build
│   ├── core/
│   │   ├── BpfProgram.{hpp,cpp}            # Generic BPF lifecycle wrapper — knows nothing product-specific
│   │   ├── IHookModule.hpp                 # attach() / eventSource() / parseEvent() — one per hook family
│   │   ├── HttpGuardProgram.{hpp,cpp}      # Orchestrator: loops over hook modules, runs the detector registry
│   │   ├── hg_event_source.h               # Shared `enum hg_event_source` (BPF C and C++ both compile this)
│   │   ├── https_guard.bpf.c               # Thin aggregator: ring buffer map + #includes each hook's .bpf.h
│   │   └── main.cpp                        # Composition root — the only place that knows every concrete hook/detector
│   ├── ssl_uprobe/                         # PRIMARY hook — see programs/ssl_uprobe/DESIGN.md
│   │   ├── SslUprobeProgram.{hpp,cpp}      # IHookModule: attaches the uprobe, parses uprobe_event
│   │   ├── ssl_uprobe.bpf.h                # SEC("uprobe/ssl_write") program body
│   │   ├── ssl_uprobe_event.h              # struct uprobe_event (BPF + C++ shared layout)
│   │   └── proc_peer_resolver.hpp          # /proc/<pid>/net/tcp parser, PID → socket 4-tuple
│   ├── xdp_tls/                            # AUXILIARY hook — see programs/xdp_tls/DESIGN.md
│   │   ├── XdpTlsProgram.{hpp,cpp}         # IHookModule: attaches XDP (native → generic → skip), parses xdp_event
│   │   ├── xdp_tls.bpf.h                   # SEC("xdp") program body
│   │   └── xdp_tls_event.h                 # struct xdp_event
│   └── utils/
│       └── bounded_string.hpp              # Fixed-size char[] → std::string, shared by both hook modules
├── detections/                               # Classify layer
│   ├── CMakeLists.txt                      # detections_lib (INTERFACE — header-only)
│   ├── core/
│   │   ├── IDetector.hpp                   # evaluate(const hg_event&) -> std::optional<Verdict>
│   │   ├── hg_event.hpp                    # Common parsed-event representation (no classification fields)
│   │   └── Verdict.hpp                     # {severity, message_id, message, actionable} — a detector's output
│   ├── tls_version/
│   │   ├── TlsVersionDetector.hpp          # Flags TLS < 1.2, or any hook-provided tls_violation_hint
│   │   └── tls_version.hpp                 # TlsVersion: numeric code → display string
│   └── payload_anomaly/
│       └── PayloadAnomalyDetector.hpp       # SQLi / path-traversal substring rules
├── actions/                                 # Dispatch layer
│   ├── CMakeLists.txt                      # actions_lib (OBJECT) + the action_runner smoke-test binary
│   ├── core/
│   │   ├── ActionLoop.{hpp,cpp}            # Boost.Asio-based async action dispatcher
│   │   └── main.cpp                        # action_runner entry point
│   ├── blocklist/
│   │   ├── blocklist.bpf.h                 # BPF-side XDP_DROP check (shared with programs/xdp_tls)
│   │   ├── Blocklist.{hpp,cpp}             # Singleton BPF map wrapper
│   │   └── BlocklistAction.{hpp,cpp}       # BlocklistAddAction
│   ├── tcp/
│   │   ├── TcpDestroyer.{hpp,cpp}          # Netlink SOCK_DESTROY, RAII lifecycle
│   │   └── BlockTcpAction.{hpp,cpp}
│   └── log/
│       ├── async_mutex.hpp                 # AsyncFileStreamManager (coroutine-safe file I/O)
│       ├── LogAction.{hpp,cpp}
│       └── redfish_event_message.hpp       # Verdict + hg_event → Redfish JSON
└── tests/
    ├── CMakeLists.txt                      # doctest via FetchContent; host-only, off when cross-compiling
    ├── test_placeholder.cpp                # Proves the harness runs end-to-end
    └── test_detectors.cpp                  # Unit tests for both IDetector implementations
```

## Build System

### CMakeLists.txt

One `CMakeLists.txt` per top-level concern (`actions`, `detections`, `programs`, `tests`), each producing one library target (`actions_lib`, `detections_lib`, `programs_lib`) plus the root file tying them into the final executables. Adding a source file to one concern never requires touching another concern's build file.

**Key features:**
- Cross-compilation support for ARM 32-bit (ASpeed AST2600)
- BPF object compilation with clang targeting `bpf`
- CO-RE (Compile Once - Run Everywhere) via vmlinux.h
- Native host tool compilation (gen_ssl_offset) for OpenSSL struct offset detection
- Automatic Boost/doctest header fetching if not available in sysroot

**Build targets:**
- `https_guardd` - Main daemon binary (root `CMakeLists.txt`)
- `action_runner` - Test harness for ActionLoop (`actions/CMakeLists.txt`)
- `https_guard.bpf.o` - BPF object, when `HTTPS_GUARD_BUILD_BPF=ON` (`programs/CMakeLists.txt`)
- `https_guard_tests` - doctest unit tests, when `HTTPS_GUARD_BUILD_TESTS=ON` (default off when cross-compiling — see `tests/CMakeLists.txt`)

**A cross-compile trap worth knowing about:** a target's default output directory mirrors the *source* subdirectory it's defined in (`CMAKE_CURRENT_BINARY_DIR`), not the top-level build root. Moving a target's `add_executable`/custom-command into a concern's own `CMakeLists.txt` silently moves its output too. Three things the BitBake recipe expects to find flat under `${B}` are pinned back to `${CMAKE_BINARY_DIR}` explicitly for this reason: `https_guard.bpf.o` (`programs/CMakeLists.txt`), `action_runner`'s `RUNTIME_OUTPUT_DIRECTORY` (`actions/CMakeLists.txt`), and `ssl_version_offset.h`'s write location in the recipe's own `do_compile:prepend()`. `https_guardd` is unaffected — its `add_executable` stays in the root `CMakeLists.txt`, where `CMAKE_CURRENT_BINARY_DIR` already equals `CMAKE_BINARY_DIR`.

**BPF compilation flags:**
```cmake
-target bpf
-D__TARGET_ARCH_<arch>  # arm, arm64, x86, powerpc, riscv
-O2 -g
-I<vmlinux.h>
-I<sysroot>/usr/include  # For BPF kernel headers
-ffile-prefix-map for debug info
```

### gen_ssl_offset.c

A build-time host tool that determines the offset of `ssl_st.version` in OpenSSL's `ssl_st` struct.

**Why it exists:**
- OpenSSL 3.x made `struct ssl_st` opaque in public headers
- Cannot use `offsetof()` directly
- The offset is architecture-specific (ARM 32-bit: 36 bytes, x86_64: 20 bytes)

**How it works:**
1. Compiled with native compiler during `do_configure:prepend` in the bitbake recipe
2. Uses hardcoded architecture-specific offsets (empirically determined)
3. Generates `ssl_version_offset.h` with `#define SSL_VERSION_OFFSET <N>`, written under `programs/` to match where `programs/ssl_uprobe/ssl_uprobe.bpf.h`'s `#include` looks for it
4. Included by `programs/ssl_uprobe/ssl_uprobe.bpf.h` to read `ssl->version` at the correct offset

**Output:**
```c
/* auto-generated by gen_ssl_offset.c */
#ifndef SSL_VERSION_OFFSET
#define SSL_VERSION_OFFSET 36
#endif
```

## The Detect Layer: `programs/`

### `IHookModule` — the interface every hook implements

```cpp
class IHookModule {
public:
    virtual bool attach(bpf_object* obj, std::vector<bpf_link*>& links) noexcept = 0;
    virtual hg_event_source eventSource() const noexcept = 0;
    virtual std::optional<hg_event> parseEvent(const void* data, size_t size) const noexcept = 0;
};
```

A hook module does exactly two things: attach its own BPF program(s) to the already-loaded object, and parse its own raw ring-buffer struct into the shared `hg_event` representation. It never classifies (that's `detections/`) and never dispatches an action (that's `actions/`) — the same "BPF is observational, userspace decides" split the kernel side already enforces, pushed one layer up into the C++ classes too.

Two hooks exist today, each documented in depth in its own `DESIGN.md`:

| Hook | Role | Deep dive |
|------|------|-----------|
| `ssl_uprobe` | PRIMARY — uprobe on OpenSSL `SSL_write()` | [programs/ssl_uprobe/DESIGN.md](recipes-https-guard/https-guard/files/programs/ssl_uprobe/DESIGN.md) |
| `xdp_tls` | AUXILIARY — XDP on the NIC RX path | [programs/xdp_tls/DESIGN.md](recipes-https-guard/https-guard/files/programs/xdp_tls/DESIGN.md) |

### `https_guard.bpf.c` — the aggregator

Both hooks' BPF program bodies live in their own `<hook>.bpf.h`, but clang only ever compiles one translation unit: `programs/core/https_guard.bpf.c`. It declares the shared ring buffer map and the `enum hg_event_source` discriminator, then `#include`s each hook's header — so the result is a single BPF object with one ring buffer, one blocklist map, and one load/verify pass, regardless of how many hook headers get added.

### `HttpGuardProgram` — the orchestrator

The sole `BpfProgram` subclass. It holds a `vector<unique_ptr<IHookModule>>` and a `DetectorRegistry` (`unordered_map<hg_event_source, vector<unique_ptr<IDetector>>>`), both constructed and injected by `main.cpp` — it never constructs a concrete hook or detector itself. `attachProgram()` loops over the hooks calling `attach()`, requiring at least one to succeed; the ring-buffer callback reads the raw `event_source` discriminator, finds the hook whose `eventSource()` matches, calls its `parseEvent()`, then runs that source's registered detectors in order and dispatches on the resulting `Verdict`.

Because everything is expressed through `IHookModule`/`IDetector`, adding a new hook (e.g. the planned BPF-LSM certificate-access guard) or a new detection rule never requires touching `HttpGuardProgram` — only `main.cpp`'s composition root grows by a line.

## The Classify Layer: `detections/`

### `IDetector` and `Verdict`

```cpp
struct Verdict {
    std::string severity;
    std::string message_id;
    std::string message;
    bool        actionable = false;
};

class IDetector {
public:
    virtual std::optional<Verdict> evaluate(const hg_event& evt) const = 0;
};
```

A detector is a pure, synchronous function: given an already-parsed event, decide whether its rule matches and, if so, produce the `Verdict` to act on. No I/O, no BPF/socket access, no knowledge of which hook produced the event. `evaluate()` takes `hg_event` by `const&` and never mutates it — `hg_event` stays purely "what was observed," `Verdict` is purely "what a detector decided," and the two are never conflated.

### The registry

`HttpGuardProgram::DetectorRegistry` maps each `hg_event_source` to an ordered list of detectors. Both existing sources run the same two rules today, in the same priority order:

1. **`TlsVersionDetector`** — flags a negotiated version below TLS 1.2. `tls_version == 0` alone means "not observed" (the uprobe never resolves `ssl->version` before a violation) and is not itself a violation — *unless* the producing hook already determined otherwise via `hg_event.tls_violation_hint` (only `xdp_tls` sets this, since its BPF side already classifies `is_violation` from the wire — see its own `DESIGN.md`). Without that hint, a hook-agnostic zero-check would wrongly treat a genuinely-parsed `0x0000` `legacy_version` as "no data" instead of a violation — this exact bug shipped once and was caught by `/code-review`; the hint field exists specifically to prevent it recurring.
2. **`PayloadAnomalyDetector`** — SQLi / path-traversal / known attack-signature substrings in `payload_snippet`, case-insensitive.

The orchestrator runs a source's list in order and stops at the first match; no match falls back to an `OK` / `HttpsTrafficObserved` verdict built inline in `HttpGuardProgram`, not by a detector (there is nothing to detect in that case).

## The Dispatch Layer: `actions/`

Unchanged in shape by the `programs`/`detections` split — still three single-responsibility, asynchronously-dispatched countermeasures run through `ActionLoop`:

- **`LogAction`** — writes the formatted Redfish event JSON to the event log file (always dispatched, regardless of severity).
- **`BlockTcpAction`** — `SOCK_DESTROY` via `NETLINK_INET_DIAG` for the exact 4-tuple (`TcpDestroyer`).
- **`BlocklistAddAction`** — writes an expiry into the shared BPF blocklist map, which `xdp_tls`'s synchronous `blocklist_check()` reads on every subsequent packet.

The last two only fire when a `Verdict::actionable` is true and `hg_event::remote_ip_v4` is non-zero (uprobe events need `ProcPeerResolver` to have found a socket first; `xdp_tls` events always carry it from the packet headers).

## Event Processing Pipeline

### Ring Buffer → Classification → Enforcement

```
BPF Event (ring buffer)
    │
    ▼
HttpGuardProgram::ringBufferHandler()
    │
    ├─ Read the raw uint32_t event_source discriminator
    │
    ├─ Find the IHookModule whose eventSource() matches
    │   └─ (none found → log + skip)
    │
    ├─ hookModule->parseEvent(data, size) -> optional<hg_event>
    │   └─ nullopt (undersized/malformed) → skip
    │
    ├─ Run detectors_[event_source] in order, stop at first match
    │   ├─ TlsVersionDetector::evaluate(evt)      -> optional<Verdict>
    │   └─ PayloadAnomalyDetector::evaluate(evt)  -> optional<Verdict>
    │   └─ (no match → inline "OK / traffic observed" Verdict)
    │
    ├─ if Verdict::actionable && evt.remote_ip_v4 != 0:
    │   ├─ BlockTcpAction(local_ip, remote_ip, local_port, remote_port)
    │   │   └─ TcpDestroyer::execute() → SOCK_DESTROY via NETLINK_INET_DIAG
    │   └─ BlocklistAddAction(src_ip, ttl)
    │       └─ Blocklist::add() → bpf_map_update_elem()
    │
    └─ LogAction (always, regardless of severity)
        └─ RedfishEventMessage(evt, verdict) → JSON → event log file
```

Per-hook specifics — exactly what each `parseEvent()` extracts, and each hook's own attach fallback — live in `programs/ssl_uprobe/DESIGN.md` and `programs/xdp_tls/DESIGN.md`.

### ActionLoop - Async Dispatcher

Decouples event callback processing from I/O using Boost.Asio:

```
Main thread (ring_buffer__poll)
    │
    └─ ringBufferHandler() callback
        ├─ pushAction(LogAction)          → ActionLoop queue
        ├─ pushAction(BlocklistAddAction) → ActionLoop queue
        └─ pushAction(BlockTcpAction)     → ActionLoop queue
                │
                ▼
        Background thread (io_context::run)
                │
                ├─ co_spawn LogAction::execute_async()
                │   └─ AsyncFileStreamManager::acquire_stream()
                │       └─ async_write() to log file
                │
                ├─ co_spawn BlocklistAddAction::execute_async()
                │   └─ Blocklist::instance().add(src_ip, ttl)
                │
                └─ co_spawn BlockTcpAction::execute_async()
                    └─ SOCK_DESTROY via NETLINK_INET_DIAG
```

## Security Model

HTTPS-Guard combines two enforcement strategies that eBPF makes possible. It runs the second one as its primary detection path, and layers the first on top purely as an accelerator fed by the second's own decisions.

### Strategy 1: Synchronous Inline Enforcement

The eBPF program decides and enforces a verdict inside the kernel hook itself, in the same instant it inspects the packet. No event reaches userspace on this path — the decision must be made in nanoseconds.

```
Policy Authoring (control plane)
        │
        ▼
  Userspace engine pre-loads
  policies into eBPF Maps
  (e.g. blocklist IPs, allowed
   TLS versions, rate limits)
        │
        ▼
  ┌─────────────────────────────────────┐
  │  eBPF hook (XDP/tc/kprobe)          │
  │                                     │
  │  while (processing packet/event) {  │
  │     query eBPF map                  │
  │     if (match) → XDP_DROP / -EPERM  │
  │     else        → XDP_PASS / 0      │
  │  }                                  │
  └─────────────────────────────────────┘
        │
        ▼
   Immediate action (drop/allow)
   without any userspace round-trip
```

| Aspect | Property |
|--------|----------|
| Decision time | Sub-microsecond (single eBPF instruction) |
| Blocking capability | Yes — `XDP_DROP`, `bpf_override_return`, etc. |
| Policy complexity | Low — limited by the eBPF verifier (instruction count, loops, helpers) |
| Use case | DDoS filtering, IP blocklisting, simple allow/deny rules |

The limits that matter here: the verifier rules out regex and deep protocol parsing, multi-stage attack correlation across packets is impractical inside a single hook invocation, and any policy that needs to *learn* (e.g. "this IP just became suspicious") still needs a userspace feedback loop to populate the map in the first place.

### Strategy 2: Asynchronous Active Response

The eBPF hook defers the decision: it submits an observation to a ring buffer and immediately returns a non-blocking verdict (`XDP_PASS` / `0`). A userspace daemon in its own process context picks up the event milliseconds later, classifies it, and executes a countermeasure.

```
                            ┌──────────────────────────────────────┐
  eBPF hook                 │  eBPF hook                           │
  observes event            │  (Uprobe / XDP)                      │
      │                     │                                      │
      │  cannot decide      │  1. Reserve ring buffer entry        │
      │  (too complex)      │  2. Fill event fields                │
      ▼                     │  3. bpf_ringbuf_submit()             │
  ────┴─────────            │  4. return XDP_PASS / 0              │
  Return PASS               └─────────────────┬────────────────────┘
  immediately                                 │
                                              │  asynchronous
                                              ▼
                            ┌──────────────────────────────────────┐
                            │  Userspace daemon (HttpGuardProgram)  │
                            │                                      │
                            │  ring_buffer__poll() loop            │
                            │    → find the owning IHookModule     │
                            │      → parseEvent()                  │
                            │        → run detectors_[source]      │
                            │          (complex rules, regex,      │
                            │           cross-field logic)         │
                            │          → Verdict                   │
                            │      → countermeasure:               │
                            │          • SOCK_DESTROY TCP conn     │
                            │          • update eBPF blocklist     │
                            │          • log / alert               │
                            └──────────────────────────────────────┘
```

| Aspect | Property |
|--------|----------|
| Decision time | Milliseconds (userspace round-trip) |
| Blocking capability | Indirectly — `SOCK_DESTROY`, eBPF map updates, or signals |
| Policy complexity | Unlimited — full C++ stdlib, regex, ML, etc. |
| Use case | Intrusion detection, anomaly scoring, multi-vector correlation |

Why this wins for detection: full pattern matching and cross-connection state with no verifier pressure, plus a learning loop — if the daemon confirms a threat, it writes a block entry into the same eBPF map Strategy 1 reads, so the *next* packet from that source is dropped synchronously. It also fails safe: if the daemon crashes, the kernel hook still returns pass, so traffic keeps flowing instead of the enforcement layer taking the system down with it.

### Why HTTPS-Guard Combines Both

```
Packet arrives on port 443
       │
       ▼
  ┌────────────────────────────────┐
  │ Tier 1: blocklist_check()      │  ← Synchronous (XDP only)
  │  ├── IP active  → XDP_DROP     │
  │  ├── IP expired → delete, PASS │
  │  └── IP absent  → XDP_PASS     │
  └──────────┬─────────────────────┘
             │ (if PASS)
             ▼
  ┌────────────────────────────────┐
  │ Tier 2: Uprobe + XDP detection │  ← Asynchronous
  │  ├── SSL_write → ring buffer   │
  │  ├── ClientHello → ring buffer │
  │  ├── XDP: version viol → DROP │
  │  └── XDP_PASS (always uprobe)  │
  └──────────┬─────────────────────┘
             │
             ▼
  ┌────────────────────────────────┐
  │ Userspace daemon               │
  │  → parseEvent() via IHookModule│
  │  → classify via detectors_[]   │
  │  → if Verdict.actionable:      │
  │    → BlockTcpAction(src,dst)   │
  │    → SOCK_DESTROY connection   │
  │    → BlocklistAddAction(src_ip)│
  │    → writes expiry into BPF map│  ← Feeds Tier 1
  └────────────────────────────────┘
```

| Aspect | Tier 1 (Synchronous) | Tier 2 (Asynchronous) |
|--------|----------------------|-----------------------|
| Decision latency | Microseconds | Milliseconds |
| Policy complexity | Low (verifier-limited) | Unlimited (C++ stdlib) |
| Failure mode | Drops the packet | Logs, then reacts |
| HTTPS-Guard's use | Blocklist enforcement only | Primary detection path |
| Enforcement action | `XDP_DROP` (proactive, XDP platforms only) | `SOCK_DESTROY` + blocklist write (reactive, all platforms) |

Key design decisions this leads to:

1. **BPF is observational** — no classification fields exist in either raw event struct; `xdp_tls`'s `is_violation` is the one deliberate exception (a line-rate synchronous decision, not full classification), and it's surfaced to userspace as `hg_event.tls_violation_hint`, not baked into any detector's logic.
2. **Userspace is intelligent** — all classification lives behind `IDetector`, all hook-attach/parse logic behind `IHookModule`; neither knows about the other.
3. **Different structs per hook** — `uprobe_event` has no socket info; `xdp_event` does (available from packet headers, unlike from uprobe context).
4. **No CO-RE for userspace structs** — `ssl_st` is a userspace type, not in kernel BTF, hence `gen_ssl_offset.c`.

### Platform-Adaptive Enforcement

The uprobe attaches unconditionally; failing to attach it is logged as required but does not by itself stop the daemon (only zero hooks attaching does). XDP is attempted twice — native, then generic (SKB) — and skipped without error if neither is available. `HttpGuardProgram::attachProgram()` requires at least one hook of any kind to succeed; the summary line it logs (`"https_guard: enforcement active via N of M hook(s)"`) is intentionally hook-agnostic — the orchestrator has no hook names to report, only the generic `IHookModule` interface. Each hook still logs its own specific attach outcome internally (see the per-hook `DESIGN.md`s).

**x86 servers / QEMU TAP+BRIDGE with virtio-net** — both hooks load. XDP proactively drops TLS violations at the wire, the uprobe still resolves PID→socket for enforcement, and the blocklist protects future connections from repeat offenders. Generic (SKB) XDP hooks `netif_receive_skb()` in software, so `virtio-net-device` attaches successfully even without native driver support.

**AST2600 (johnblue)** — see [the top-level README](README.md#bridge-mode-recommended-for-xdp) for the TAP/bridge setup. Verified via a real QEMU boot (SLIRP mode) on the actual shipped kernel: both the uprobe *and* XDP (native mode) attached successfully — `journalctl` showed `"https_guard: enforcement active via 2 of 2 hook(s)"`. (Earlier notes on this machine assumed XDP would be uprobe-only under SLIRP; this build's kernel/QEMU combination supports native XDP attach even there — the attach *succeeding* doesn't necessarily mean real hardware offload semantics are exercised, since SLIRP's backend isn't a real NIC, but the driver-level `ndo_bpf` registration itself went through.)

**Any platform where XDP genuinely can't attach** — both native and generic XDP fail; both failures are logged but non-fatal, and detection continues via the uprobe alone:

```
Process calls SSL_write(ssl, buf, num)
       │
       ▼
  Uprobe fires on SSL_write
       │
       ├── Reads ssl->version (4-byte int at offset 36 of ssl_st
       │     on ARM 32-bit OpenSSL 3.x) using bpf_probe_read_user()
       │     → extracts lower 16 bits (e.g. 0x0303 = TLS 1.2)
       │
       ├── If version < 0x0303 (TLS 1.2) and version > 0:
       │     → TlsVersionDetector: Verdict{Critical, HttpsTlsVersionViolation, actionable=true}
       │
       └── Submits event to ring buffer (PID + TLS version, no socket info)
       │
       ▼
  Userspace daemon receives event
       │
       ├── SslUprobeProgram::parseEvent() → ProcPeerResolver::getTcpSockets(pid)
       │     → reads /proc/<pid>/net/tcp, parses "AABBCCDD:PPPP"
       │     → returns socket 4-tuple
       │
       ├── BlockTcpAction → TcpDestroyer::async_execute()
       │     → SOCK_DESTROY via NETLINK_INET_DIAG
       │
       ├── BlocklistAddAction(src_ip, ttl)
       │     → future XDP packets from this IP would be dropped, on platforms that have XDP
       │
       └── LogAction → Redfish event JSON line

  NOTE: the ssl_st offset is architecture-specific — 36 bytes on ARM
  32-bit (johnblue), 20 bytes on x86_64 with 8-byte pointers. If
  detection fails on a new platform, enable the bpf_printk diagnostic
  scanning code in gen_ssl_offset.c.
```

**Caveat when testing with `curl`:** OpenSSL 3.x removed TLS 1.0/1.1 support at compile time, so `--tlsv1.0`/`--tlsv1.1` are silently ignored — curl always negotiates TLS 1.3 regardless of the flag. Confirmed live against a real QEMU boot:

```
$ curl -sk https://<bmc>/redfish/v1 -u root:0penBmc --tlsv1.2
```
still produces a `tls_version=772` (0x0304 = TLS 1.3) uprobe event, classified `OK` / `HttpsTrafficObserved`. Testing the actual TLS < 1.2 violation path requires a legacy TLS client; the unit tests in `detections/` cover that path directly against synthetic input instead (see `tests/test_detectors.cpp`).

## Configuration

### https-guard.conf

Environment file for systemd services:

```bash
# Event sink mode: dbus | journal | both
HTTPS_GUARD_EVENT_MODE=both

# Network interface for XDP attachment
HTTPS_GUARD_IFACE=eth0

# Path to OpenSSL shared library (uprobe attachment point)
HTTPS_GUARD_SSL_LIB=/usr/lib/libssl.so.3

# JSON event archive read by the event bridge
HTTPS_GUARD_EVENT_FILE=/var/log/https_guard_events.log

# Redfish log directory watched by bmcweb for EventService dispatch
HTTPS_GUARD_REDFISH_LOG=/var/log/redfish
```

### PACKAGECONFIG Flags

**Service selection (from https-guard-openbmc.bb):**

| Flag | Daemon | Generator | Bridge |
|------|--------|-----------|--------|
| `simulation` (default) | ✗ | ✓ | ✓ |
| `daemon` | ✓ | ✗ | ✓ |
| `both` | ✓ | ✓ | ✓ |

**Event sink mode:**

| Flag | Behavior |
|------|----------|
| `dbus-only` | Emit via D-Bus `xyz.openbmc_project.Logging.Create` only |
| `journal-only` | Emit via systemd-cat + `/var/log/redfish/` filesystem |
| `event-both` (default) | Emit to both D-Bus and systemd-cat |

## BitBake Recipe

### https-guard-openbmc.bb

**DEPENDS:** libbpf, pkgconfig, clang-native, bpftool-native, nlohmann-json, boost, openssl

**Build flow:**

1. `do_configure[depends]` += `virtual/kernel:do_compile`
   - Requires kernel vmlinux for CO-RE header generation

2. `do_configure:prepend()`
   - Locates target kernel vmlinux
   - Creates symlink: `${WORKDIR}/target-kernel-vmlinux`
   - Compiles `gen_ssl_offset.c` with native compiler (BUILD_CC)

3. `do_compile:prepend()`
   - Runs `gen_ssl_offset` to produce `${B}/programs/ssl_version_offset.h` (note the `programs/` prefix — see the cross-compile trap called out under [Build System](#build-system))

4. `do_compile`
   - CMake builds C++ daemon and BPF object

5. `do_install`
   - Installs binaries to `${sbindir}` (`https-guardd`, `action_runner`, and the shell wrappers)
   - Installs BPF object to `${datadir}/https-guard/`
   - Installs systemd units to `${systemd_system_unitdir}`
   - Installs config to `${sysconfdir}/default/https-guard`
   - Stamps event mode into config from PACKAGECONFIG

**SRC_URI includes:** all shell scripts and systemd units under `service/`, `CMakeLists.txt` (root and per-concern), every C++ source/header under `programs/`, `detections/`, `actions/`, `tests/`, and `scripts/gen_ssl_offset.c`.

## Development

For top-level project overview, build instructions, and deployment guidance, see the root [README.md](README.md). For per-hook detection rationale and diagrams, see `programs/ssl_uprobe/DESIGN.md` and `programs/xdp_tls/DESIGN.md`.

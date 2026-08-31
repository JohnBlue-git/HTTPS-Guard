# HTTPS-Guard — Design Reference

> **This is the detailed reference.** For build instructions, QEMU setup, and deployment, see the [top-level README](README.md). For a diagram-first architecture walkthrough, see [DESIGN.html](DESIGN.html) — rendered via htmlpreview: [DESIGN.html (rendered)](https://htmlpreview.github.io/?https://github.com/JohnBlue-git/HTTPS-Guard//main/DESIGN.html) (predates the current file layout — see the [Doc Rewrites ticket](.scratch/extend-detection-coverage/issues/07-doc-rewrites.md) once it lands).

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
├── CMakeLists.txt                          # Root: project setup, deps, add_subdirectory(actions|detections|programs|tests)
├── https-guard.conf                        # EnvironmentFile for systemd units
├── scripts/gen_ssl_offset.c                # Build-time ssl_st.version offset detector
├── service/                                # systemd units + their shell wrappers
├── programs/                               # Detect — attach BPF, hand over bytes. The only tree linking libbpf.
│   ├── CMakeLists.txt                      # programs_lib (OBJECT) + the BPF object build
│   ├── core/
│   │   ├── ebpf/https_guard.bpf.c          # The ONLY file clang compiles: ring buffer map + #includes each hook's .bpf.h
│   │   ├── src/
│   │   │   ├── BpfProgram.{hpp,cpp}        # Base class every hook inherits; default ringBufferHandler() submits
│   │   │   └── HttpGuardProgram.{hpp,cpp}  # Owns the object, the ring buffer and the poll loop; HOLDS the hooks
│   │   └── main.cpp                        # Composition root — the only place naming concrete hooks and handlers
│   ├── ssl_uprobe/                         # PRIMARY hook — attachment mechanics in its DESIGN.md
│   │   ├── ebpf/{ssl_uprobe.bpf.h,ssl_uprobe_event.h}
│   │   └── src/{SslUprobeProgram.{hpp,cpp},proc_peer_resolver.hpp}
│   ├── xdp_tls/                            # AUXILIARY hook
│   │   ├── ebpf/{xdp_tls.bpf.h,xdp_tls_event.h,parse_client_hello.h,conn_rate.bpf.h}
│   │   └── src/XdpTlsProgram.{hpp,cpp}
│   ├── lsm_cert_guard/                     # AUXILIARY hook — cannot attach on ARM32, see LIMITATIONS.md
│   │   ├── ebpf/{lsm_cert_guard.bpf.h,lsm_cert_guard_event.h}
│   │   └── src/LsmCertGuardProgram.{hpp,cpp}
│   └── utils/bounded_string.hpp            # Fixed-size char[] → std::string
├── detections/                             # Classify — event types, parsing, rules, engine. No libbpf.
│   ├── CMakeLists.txt                      # detections_lib (OBJECT) + the detect_runner binary
│   ├── DESIGN.md                           # The pipeline: DetectLoop, admission, threading
│   ├── core/                               # Grouped by duty: contract / event / engine
│   │   ├── contract/                       #   what a detection must provide
│   │   │   ├── IDetection.hpp              #     inspect(data, size, meta) -> optional<Verdict>
│   │   │   ├── Verdict.hpp                 #     {severity, message_id, message, actionable}
│   │   │   └── detection_traits.hpp        #     concepts describing what a RAW RECORD carries
│   │   ├── event/                          #   the vocabulary they all speak
│   │   │   ├── hg_event_source.h           #     discriminator + hg_event_hdr (BPF C and C++)
│   │   │   ├── event_meta.hpp              #     EventMeta — composed into each event, not inherited
│   │   │   ├── event_meta_from.hpp         #     the shared envelope parse, in exactly one place
│   │   │   ├── IPeerResolver.hpp           #     lazy /proc resolution; only the enforcing path pays
│   │   │   └── tls_version.hpp             #     a wire version code -> a display string
│   │   ├── engine/                         #   what drives the pipeline
│   │   │   ├── DetectLoop.{hpp,cpp}        #     singleton, asio, walks a submitted detection list
│   │   │   └── dispatch.{hpp,cpp}          #     the shared tail: enforce if actionable, then log
│   │   └── main.cpp                        #   detect_runner — standalone runner for the loop
│   ├── tls_version/                        # event + rule + IDetection + DESIGN.md  (uprobe + XDP)
│   ├── payload_anomaly/                    # event + rule + IDetection + DESIGN.md  (uprobe + XDP)
│   ├── cipher_suite/                       # event + rule + IDetection + DESIGN.md  (XDP, alert-only)
│   ├── sni/                                # event + rule + IDetection + DESIGN.md  (XDP, alert-only)
│   ├── cert_access/                        # event + rule + IDetection + DESIGN.md  (LSM)
│   ├── conn_rate/                          # rule + event + ConnRateSweeper + rate_sources + DESIGN.md
│   ├── slowloris/                          # rule + event + DESIGN.md
│   ├── renegotiation/                      # rule + event + DESIGN.md
│   └── traffic_observed/                   # the always-matching terminal entry + DESIGN.md
├── actions/                                # Dispatch
│   ├── CMakeLists.txt                      # actions_lib (OBJECT) + the action_runner binary
│   ├── DESIGN.md                           # ActionLoop: why coroutines, why unbounded here
│   ├── core/{ActionLoop.{hpp,cpp},main.cpp}
│   ├── blocklist/                          # the BPF map XDP reads + DESIGN.md
│   ├── tcp/                                # netlink SOCK_DESTROY + DESIGN.md
│   └── log/                                # Redfish JSON + coroutine-safe file I/O + DESIGN.md
└── tests/                                  # Host-only, off when cross-compiling
    ├── test_detectors.cpp                  # All eight rules + 12 static_asserts on the concepts
    ├── test_uprobe_parsing.cpp             # The real detections, inspect()ing synthetic raw records
    ├── test_client_hello_parsing.cpp       # The real parse_client_hello.h against hand-built wire bytes
    └── detectloop/                         # Separate binary — DetectLoop scheduling; see its README
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

### `BpfProgram` — the base class every hook inherits

```cpp
class BpfProgram {
public:
    virtual bool attach(bpf_object*, std::vector<bpf_link*>&) noexcept = 0;
    virtual hg_event_source eventSource() const noexcept = 0;
    virtual void ringBufferHandler(const void* data, std::size_t size) noexcept;  // default: submit
};
```

Three methods, one of them already implemented. A hook says how to attach
itself, which event source its records carry, and — only if it must — what to do
with a record on the poll thread. The default `ringBufferHandler()` body is
`DetectLoop::getInstance().submit(data, size)` and nothing else, so a new hook
gets event submission for free.

**A hook does not parse its own records.** Parsing is part of deciding what an
event means, so it lives with the rule that needs it in `detections/<family>/`. That leaves a
hook down to the two things only it can do.

**`HttpGuardProgram` does not inherit this.** A hook *is* a `BpfProgram`; the
orchestrator *has* several. It used to inherit it, which put the ring-buffer
callback for records produced by hooks on the one class that is not a hook.

### The raw event ABI — one envelope, then per-hook detail

Each hook's `ebpf/<hook>_event.h` defines the exact bytes it puts on the ring
buffer. Both the BPF program and the C++ hook module compile the same header,
so there is no marshalling step and no version negotiation — but there is also
nothing to catch a mismatch, which is why the layout is structured rather than
flat.

Every record starts with the same envelope, defined once in
`detections/core/hg_event_source.h`:

```c
struct hg_event_hdr {
    uint32_t event_source;   /* enum hg_event_source — keep first */
    uint32_t reserved;
    uint64_t timestamp_ns;
    uint32_t pid;
    uint32_t tgid;
    char     comm[HG_COMM_LEN];
};
```

and then nests whatever that hook alone can observe:

| Hook | Layout | Size |
|---|---|---|
| `ssl_uprobe` | `hdr` · `direction` · `hg_uprobe_tls` | 184 B |
| `xdp_tls` | `hdr` · `hg_conn_tuple` · `hg_xdp_tls` · `hg_client_hello` | 352 B |
| `lsm_cert_guard` | `hdr` · `hg_cert_access` | 56 B |

All three fit the `HG_MAX_RAW_EVENT_SIZE` (1024 B) cap that `DetectLoop` sizes
its queue slots from; each hook's `.cpp` `static_assert`s that.

Three things this buys, none of them cosmetic:

- **The common fields cannot drift.** All three hooks previously carried their
  own copy of the same five members, in slightly different orders, and one of
  them called `comm` `process`. A shared struct is the difference between
  "they happen to match" and "they cannot diverge".
- **A parser can be handed a sub-struct instead of the whole event.**
  `parse_client_hello_detail()` now takes `struct hg_client_hello*`, so it is
  structurally incapable of touching the header, the tuple, or the TLS fields
  the caller already filled in. That used to rest on reviewer discipline.
- **Absent-together fields look absent-together.** The ClientHello block is
  entirely zero for a non-handshake packet. As a nested struct that reads as
  one optional group rather than nine fields that happen to be zero.

`event_source` **must** stay the first member of `hg_event_hdr`, and `hdr` the
first member of every event struct: `DetectLoop::process()` reads a `uint32` at
offset 0 to find the owning hook before it knows the type. Two `static_assert`s
per hook pin exactly that, rather than trusting that nobody reorders members.

### `https_guard.bpf.c` — the aggregator

Every hook's BPF program body lives in its own `ebpf/<hook>.bpf.h`, but clang only ever compiles one translation unit: `programs/core/ebpf/https_guard.bpf.c`. It declares the shared ring buffer map, then `#include`s each hook's header — so the result is a single BPF object with one ring buffer, one blocklist map, one per-source counter map, and one load/verify pass, regardless of how many hook headers get added.

### `HttpGuardProgram` — owns the object, manages the hooks

Holds the one `bpf_object`, the one ring buffer, the poll loop, and a
`vector<unique_ptr<BpfProgram>>` fed from `main.cpp` — it never constructs a
concrete hook itself. `attachHooks()` loops over them calling `attach()`,
requiring at least one to succeed.

**One object, one ring buffer, one blocklist map**, all singular on purpose:
`BlocklistAddAction` writes the map the XDP program reads, so splitting the
object per hook would give each its own map and enforcement would stop working
while still looking healthy.

Its ring-buffer callback reads the event source at offset 0, finds the owning
hook, and calls that hook's `ringBufferHandler()` — whose default body copies the
record into `DetectLoop` and returns. That trampoline lives here rather than on
`BpfProgram` because `ring_buffer__new()` takes one callback and one context for
the whole buffer, so a per-hook static could never be the thing libbpf calls.

Everything else happens on `DetectLoop`'s threads. libbpf needs that callback
back promptly — a slow callback lets the ring buffer fill, and a full ring buffer
silently drops events, which is a missed detection rather than merely added
latency.

Neither this class nor `DetectLoop` names a concrete hook, rule or event type, so
adding any of them only grows `main.cpp`'s composition root by a line.

## The Classify Layer: `detections/`

### A detection: one directory, parse and rule together

A detection owns everything about itself — its event struct, its parse, its rule
and its `DESIGN.md` — and plugs in through one seam:

```cpp
class IDetection {
public:
    virtual std::optional<Verdict> inspect(const void* data, std::size_t size,
                                           EventMeta& meta) const = 0;
};
```

`nullopt` covers "not mine", "does not parse" and "no violation" alike; the
caller does not distinguish, it tries the next entry.

Parse and evaluate live together because they are the same decision: what a
detection needs out of a record is determined entirely by what its rule reads.
Splitting them put half a detection in one directory and half in another.

The rule itself is a plain class taking one concrete event struct:

```cpp
std::optional<Verdict> evaluate(const TlsVersionEvent& evt) const;
```

No base class, no vtable, no concept. There *were* concepts here, and before
that six virtual capability interfaces; both existed so two rules could serve
two different event types. Once each detection got its own event struct that
reason evaporated — every rule has one input type, so handing it the wrong event
is an ordinary type mismatch — and the machinery was deleted rather than kept.

### Serving two hooks without duplicating a detection

`TlsVersionDetection<struct uprobe_event>` and
`TlsVersionDetection<struct xdp_event>` share one rule and one event struct. The
nested ABI makes the common parse a single expression (`raw->tls.version` for
both), and the places the layouts genuinely differ are read behind
`if constexpr`, guarded by concepts in `detections/core/detection_traits.hpp`
that describe what a raw record carries:

```cpp
if constexpr (HasConnectionTuple<RawT>) { fillConnection(raw->conn, meta); }
else                                    { meta.peer_resolver = resolver_; }
```

A detection only one hook can feed says so in a `requires` clause, so naming it
in the wrong hook's list does not compile.

### The hook declares its list; the loop walks it

```cpp
void XdpTlsProgram::ringBufferHandler(const void* data, std::size_t size) noexcept
{
    DetectLoop::getInstance().submit(data, size, detections_);
}
```

`DetectLoop` evaluates the list concurrently and picks a winner by its order.
Three things follow:

**Lowest-index match wins**, which is what keeps one record to one Redfish
event — every entry is evaluated regardless (so a future I/O-bound detection
can suspend without holding up its siblings; see `detections/DESIGN.md`), but
only the lowest-index verdict is ever dispatched.

**List order is priority order, and it lives in the hook.** That is the one real
cost of this shape: which rule wins is a classification decision now expressed in
`programs/`. Accepted deliberately, because each list is 2–5 entries readable at
the point where the hook says what it can observe — and because it decides
something that matters: `xdp_tls` puts the two enforcing rules ahead of the two
alert-only ones, so a legacy-TLS ClientHello that also offers RC4 is reported as
the TLS violation, which enforces. The loop logs which index claimed each
record, so the ordering is observable at runtime rather than only in source.

**There is no "nothing matched" branch anywhere.** A hook puts an
always-matching `TrafficObservedDetection` last, so there is always a
lowest-index entry to dispatch.

The pointer list is copied into the queued record: `submit()` returns
immediately and the record is inspected later, so a view of a temporary at the
call site would dangle. The pointees are owned by the hook, which outlives the
loop.

### Event structs, composed rather than inherited

Each detection's struct carries its own fields plus a shared `EventMeta`:

```cpp
struct TlsVersionEvent {
    EventMeta     meta;             // when, which process, which connection
    std::uint16_t tls_version = 0;
    bool          violation_hint = false;
};
```

There is no common base, so nothing downcasts. `EventMeta` also carries the lazy
`ensurePeerResolved()`, because resolving a uprobe event's tuple reads `/proc`
and only the enforcing path needs it. The envelope parse lives in exactly one
place (`event_meta_from.hpp`), since several detections inspect the same record.

`violation_hint` is the field that looks redundant and is not: a parsed wire
`legacy_version` of `0x0000` *is* a violation, while `tls_version == 0` from a
uprobe only means "never observed". Collapsing those two zeros shipped as a real
bug once.

## The Dispatch Layer: `actions/`

Unchanged in shape by the `programs`/`detections` split — still three single-responsibility, asynchronously-dispatched countermeasures run through `ActionLoop`:

- **`LogAction`** — writes the formatted Redfish event JSON to the event log file (always dispatched, regardless of severity).
- **`BlockTcpAction`** — `SOCK_DESTROY` via `NETLINK_INET_DIAG` for the exact 4-tuple (`TcpDestroyer`).
- **`BlocklistAddAction`** — writes an expiry into the shared BPF blocklist map, which `xdp_tls`'s synchronous `blocklist_check()` reads on every subsequent packet.

The last two only fire when a `Verdict::actionable` is true and the event has a peer address. For uprobe events that address comes from `ProcPeerResolver`, resolved lazily at this point and only if it can be attributed unambiguously; XDP events carry it from the packet headers, and synthesised counter events from the map key. `BlockTcpAction` additionally requires a *full* 4-tuple — a verdict attributed to an address rather than a connection (a rate or Slowloris finding) has no socket to tear down, and asking netlink to destroy a zero tuple only produces a misleading failure.

Note that gating on "do we have an address" rather than "did resolution run" matters: events that already know their own address carry no resolver, and conflating the two once disabled enforcement for every XDP and synthesised verdict while looking like it worked.

## Event Processing Pipeline

### Ring Buffer → Classification → Enforcement

```
BPF Event (ring buffer)                          BPF per-source counters
    │                                                     │
    ▼                                                     │
HttpGuardProgram::ringBufferHandler()   ── poll thread ────┼──────────────
    │                                                     │
    ├─ find the owning hook by event_source at offset 0    │
    └─ hook->ringBufferHandler(): submit(data, size,       │
       detections_) → asio::co_spawn(record_strand_)       │
           (returns immediately; nothing else happens here)│
                     │                                    │
════════════ thread boundary ═════════════════════════════ │ ════════════
                     ▼                                    ▼
   DetectLoop::handleRecord() ── io_context ──  steady_timer, every 2s:
     (on record_strand_: serialized,             ConnRateSweeper reads the
      arrival order preserved)                   counters and calls the three
                     │                           typed rate handlers directly.
                     │                           NOT on the strand, so a record
                     │                           backlog cannot delay it.
                     ▼                                    │
        fan out rec.detections concurrently, gather in order ◄──┘
                     │
                     ├─ detections[0]->inspect(bytes, size, meta)
                     ├─ detections[1]->inspect(...)      concurrent; each parses
                     ├─ ...                              only its own rule's fields
                     └─ detections[n-1] is TrafficObservedDetection,
                        which always matches — lowest-index verdict wins,
                        so there is no "nothing matched" branch anywhere
                     │
                     ▼
        dispatchVerdict(meta, verdict, ctx)
                     │
                     ├─ if Verdict::actionable:
                     │   ├─ ensurePeerResolved()   ← the /proc walk, only now
                     │   ├─ if remote_ip_v4 != 0:
                     │   │   ├─ BlockTcpAction   (only with a full 4-tuple:
                     │   │   │   an address-only verdict has no socket to kill)
                     │   │   └─ BlocklistAddAction(remote_ip, ttl)
                     │   └─ else: log "declining to enforce"
                     │
                     └─ LogAction (always, regardless of severity)
```

Three things in that diagram are load-bearing rather than incidental.

The `/proc` walk behind `ensurePeerResolved()` runs **only** on the
actionable path, because it is the most expensive step in the pipeline and
the large majority of events never reach it.

A per-item `try/catch` wraps each handler's body: everything below it
allocates and the handlers are `noexcept`, so without that boundary a
`bad_alloc` would be `std::terminate` rather than one dropped event.

And the loop runs **two** threads with the sweep timer deliberately off the
record strand. A single-threaded `io_context` starves the sweep by FIFO
fairness alone — an expiring timer queues behind every record already
posted, so a deep backlog delays it by (backlog × per-event cost), and
against a fixed 10s counting window that can lose a flood entirely.
Measured against a deliberate backlog: one thread produced **zero** sweeps
in nine seconds, two produced one every two seconds. Running the sweep
concurrently with a record is safe only because classification holds no
shared mutable state, which makes detector statelessness a threading
requirement here rather than a style preference.

Per-detection rationale — what each rule looks for, why it enforces or only alerts, and its limits — lives in `detections/<family>/DESIGN.md`, one document per detection. Hook *attachment* mechanics, and exactly what each hook can observe, live in `programs/<hook>/DESIGN.md`.

To actually *fire* each of these rules and see which message ID it produces, see [README.md § Exercising the Detections](README.md#exercising-the-detections); `DESIGN.html` § 4 has the class-relationship diagrams, the capability matrix and the ownership table.

### ActionLoop - Async Dispatcher

Decouples event callback processing from I/O using Boost.Asio:

```
DetectLoop worker thread
    │
    └─ classifyAndDispatch()
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
                            │    → fan out the detection list      │
                            │      → each inspect()s the record    │
                            │        → lowest-index verdict wins   │
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
  │  → detections evaluated        │
  │    concurrently; lowest-index  │
  │    verdict wins                │
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

1. **BPF is observational** — no classification fields exist in either raw event struct; `xdp_tls`'s `is_violation` is the one deliberate exception (a line-rate synchronous decision, not full classification), and it's surfaced to userspace as `XdpEvent::violation_hint`, not baked into any rule's logic.
2. **Userspace is intelligent** — the event types, the parsing and the rules all live in `detections/`; `programs/` only attaches and hands over bytes. Neither names a type belonging to the other.
3. **Different structs per hook** — `uprobe_event` has no socket info; `xdp_event` does (available from packet headers, unlike from uprobe context).
4. **No CO-RE for userspace structs** — `ssl_st` is a userspace type, not in kernel BTF, hence `gen_ssl_offset.c`.

### Platform-Adaptive Enforcement

The uprobe attaches unconditionally; failing to attach it is logged as required but does not by itself stop the daemon (only zero hooks attaching does). XDP is attempted twice — native, then generic (SKB) — and skipped without error if neither is available. `HttpGuardProgram::attachHooks()` requires at least one hook of any kind to succeed; the summary line it logs (`"https_guard: enforcement active via N of M hook(s)"`) is intentionally hook-agnostic — the orchestrator sees only the generic `BpfProgram` base. Each hook still logs its own specific attach outcome internally; the attach mechanics for all three are in [`programs/DESIGN.md`](recipes-https-guard/https-guard/files/programs/DESIGN.md).

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
       ├── the uprobe detections inspect() it; IPeerResolver only if one enforces
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
| `daemon` **(default)** | ✓ | ✗ | ✓ |
| `simulation` | ✗ | ✓ | ✓ |
| `both` | ✓ | ✓ | ✓ |

`daemon` and `both` additionally set `HTTPS_GUARD_BUILD_BPF=ON`, so the default
build compiles the BPF object and therefore needs a target kernel carrying BTF.
`simulation` is the fallback where that is not available.

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

For top-level project overview, build instructions, and deployment guidance, see the root [README.md](README.md).

For rationale one level down, every unit has its own document: `detections/<family>/DESIGN.md` per detection, `actions/<kind>/DESIGN.md` per countermeasure, and one per layer — `programs/DESIGN.md`, `detections/DESIGN.md`, `actions/DESIGN.md`.

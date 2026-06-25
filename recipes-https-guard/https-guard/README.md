# HTTPS-Guard Source Code Reference

This directory contains the complete source code for the **HTTPS-Guard** agent — an eBPF-based network security observability tool for OpenBMC. It implements a **Detect → Translate → Dispatch** pipeline using kernel-space uprobe (primary) and XDP (auxiliary) programs, a user-space C++ daemon, and Redfish EventService integration.

## Table of Contents

- [Source Code Structure](#source-code-structure)
- [Build System](#build-system)
- [eBPF Programs](#ebpf-programs)
- [Userspace Daemon](#userspace-daemon)
- [Event Processing Pipeline](#event-processing-pipeline)
- [Security Model](#security-model)
- [Configuration](#configuration)
- [BitBake Recipe](#bitbake-recipe)

## Source Code Structure

```
files/
├── CMakeLists.txt                          # CMake build definition
├── https-guard.conf                        # EnvironmentFile for systemd units
├── https-guard-daemon.service              # systemd unit for the eBPF daemon
├── https-guard-daemon.sh                   # Shell wrapper that launches https-guardd
├── https-guard-event-bridge.service        # systemd unit for the event bridge
├── https-guard-event-bridge.sh             # Shell bridge: tails log → D-Bus/journal/redfish
├── simulated-event-generator.service       # systemd unit for synthetic event generator
├── simulated-event-generator.sh            # Shell script that emits simulated events
├── scripts/
│   └── gen_ssl_offset.c                    # Build-time ssl_st.version offset detector
├── https_guard/
│   ├── events.h                            # Shared event structs & enums (BPF + C++)
│   ├── https_guard.bpf.c                   # eBPF programs (uprobe primary + XDP auxiliary)
│   ├── https_guard_program.hpp             # BPF object loader / ring-buffer adapter
│   ├── https_guard_program.cpp             # BPF lifecycle + event classification + PID→socket
│   ├── main.cpp                            # C++ daemon entry point
│   ├── pattern_detector.hpp                # User-space HTTP anomaly rules (inline)
│   ├── proc_peer_resolver.hpp              # /proc/<pid>/net/tcp parser for PID→socket (inline)
│   ├── redfish_event_message.hpp           # Redfish Event message with formatting (inline)
│   └── tls_version.hpp                     # TLS version helpers (inline)
├── actions/
│   ├── core/
│   │   ├── ActionLoop.hpp                  # Boost.Asio-based event dispatcher interface
│   │   ├── ActionLoop.cpp                  # Boost.Asio-based event dispatcher implementation
│   │   └── main.cpp                        # ActionLoop smoke-test / demo entry point
│   ├── blocklist/
│   │   ├── blocklist.bpf.h                 # BPF-side blocklist header (XDP_DROP check)
│   │   ├── Blocklist.hpp                   # Singleton blocklist manager (BPF map wrapper)
│   │   ├── Blocklist.cpp                   # Blocklist singleton implementation
│   │   ├── BlocklistAction.hpp             # Countermeasure action: add src IP to blocklist
│   │   └── BlocklistAction.cpp             # BlocklistAddAction implementation
│   ├── tcp/
│   │   ├── BlockTcpAction.hpp              # Countermeasure action: kill TCP 4-tuple via SOCK_DESTROY
│   │   ├── BlockTcpAction.cpp              # BlockTcpAction implementation (Netlink async)
│   │   ├── TcpDestroyer.hpp                # RAII wrapper: Netlink SOCK_DESTROY lifecycle
│   │   └── TcpDestroyer.cpp                # TcpDestroyer implementation
│   └── log/
│       ├── async_mutex.hpp                 # AsyncFileStreamManager (coroutine-safe file I/O)
│       ├── LogAction.hpp                   # Async file-logging action interface
│       └── LogAction.cpp                   # Async file-logging action implementation
└── ebpf/
    ├── bpf_program.hpp                     # BPF program attachment wrapper
    └── bpf_program.cpp                     # BPF program wrapper implementation
```

## Build System

### CMakeLists.txt

The build system handles both the C++ daemon and BPF object compilation:

**Key features:**
- Cross-compilation support for ARM 32-bit (ASpeed AST2600)
- BPF object compilation with clang targeting `bpf`
- CO-RE (Compile Once - Run Everywhere) via vmlinux.h
- Native host tool compilation (gen_ssl_offset) for OpenSSL struct offset detection
- Automatic Boost header fetching if not available in sysroot

**Build targets:**
- `https_guardd` - Main daemon binary
- `action_runner` - Test harness for ActionLoop
- `https_guard.bpf.o` - BPF object (when `HTTPS_GUARD_BUILD_BPF=ON`)

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
3. Generates `ssl_version_offset.h` with `#define SSL_VERSION_OFFSET <N>`
4. This header is included by `https_guard.bpf.c` to read `ssl->version` at the correct offset

**Output:**
```c
/* auto-generated by gen_ssl_offset.c */
#ifndef SSL_VERSION_OFFSET
#define SSL_VERSION_OFFSET 36
#endif
```

## eBPF Programs

### https_guard.bpf.c

Single C file containing two independent eBPF programs that share a ring buffer:

#### 1. Uprobe: `https_guard_ssl_write` (PRIMARY)

**Hook:** `SSL_write(SSL *ssl, const void *buf, int num)` in OpenSSL

**What it captures:**
- **TLS version** - Reads `ssl->version` using `bpf_probe_read_user()` at `SSL_VERSION_OFFSET` (36 bytes on ARM 32-bit)
- **Plaintext payload** - Copies up to 127 bytes from `buf` into `evt->payload_snippet`
- **Process info** - PID, TGID, and process name via `bpf_get_current_comm()`

**What it does NOT do:**
- Does NOT classify events (no event_type, no severity)
- Does NOT make security decisions
- Does NOT access socket info (not available from uprobe context)

**Design principle:** PURELY OBSERVATIONAL

**Event struct:** `struct uprobe_event` (~176 bytes)
```c
struct uprobe_event {
    uint32_t event_source;      // HG_SOURCE_UPROBE
    uint32_t reserved;          // Padding
    uint64_t timestamp_ns;
    uint32_t pid;
    uint32_t tgid;
    uint16_t tls_version;       // Raw TLS version from ssl->version
    uint16_t padding;
    char process[16];
    char payload_snippet[128];
};
```

**Return value:** Always returns 0 (pass) - defers all decisions to userspace

#### 2. XDP: `https_guard_xdp` (AUXILIARY)

**Hook:** Network driver RX path (or generic SKB mode)

**What it inspects:**
1. **Ethernet + IP + TCP headers** - Filters to IPv4/TCP on port 443
2. **TLS ClientHello** - Identifies ContentType 0x16 (Handshake)
3. **TLS version** - Extracts version from ClientHello fixed portion
4. **Plaintext HTTP** - Detects HTTP methods (GET, POST, PUT, DELETE, HEAD) on port 443

**Minimal classification:**
- Sets `is_violation` flag (1 if TLS < 1.2, 0 otherwise)
- This is the ONLY classification in BPF - all other decisions happen in userspace

**Enforcement:**
- **Synchronous:** `blocklist_check(ip->saddr)` → XDP_DROP for active blocklist entries
- **Synchronous:** `is_violation == 1` → XDP_DROP for TLS version violations
- **Asynchronous:** All other events → XDP_PASS + ring buffer submission

**Event struct:** `struct xdp_event` (~224 bytes)
```c
struct xdp_event {
    uint32_t event_source;      // HG_SOURCE_XDP
    uint32_t is_violation;      // 1 if TLS < 1.2, 0 otherwise
    uint64_t timestamp_ns;
    uint32_t pid;
    uint32_t tgid;
    uint32_t src_ip_v4;
    uint32_t dst_ip_v4;
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t tls_version;
    uint16_t padding;
    char process[16];
    char source_ip[32];
    char payload_snippet[128];
};
```

**Return values:**
- `XDP_DROP` - For blocklist hits and TLS version violations
- `XDP_PASS` - For all other traffic

### Blocklist Integration (blocklist.bpf.h)

Hybrid enforcement mechanism that enables synchronous XDP_DROP for known threats:

```c
static __always_inline int blocklist_check(__u32 src_ip)
{
    // 1. Look up src_ip in BPF hash map
    // 2. If found and not expired → XDP_DROP
    // 3. If found and expired → delete entry, return XDP_PASS
    // 4. If not found → XDP_PASS
}
```

**Map:** `BPF_MAP_TYPE_HASH` with 1024 max entries
- Key: Source IP (network byte order, 4 bytes)
- Value: Expiry timestamp (nanoseconds, 8 bytes)

## Userspace Daemon

### main.cpp

Entry point that orchestrates the full eBPF lifecycle:

**Initialization sequence:**
1. Parse CLI arguments (interface, OpenSSL lib path, output log, BPF object)
2. Seed ActionLoop with LogAction
3. Load and verify BPF object via libbpf
4. Create HttpGuardProgram (attaches uprobe + XDP, adopts blocklist map)
5. Open ring buffer consumer with `on_event` callback
6. Poll loop: `ring_buffer__poll()` every 200ms

### https_guard_program.cpp

BPF program lifecycle manager and event classifier:

**Responsibilities:**
- Attach/detach uprobe and XDP programs
- Handle XDP fallback (native → generic SKB mode)
- Ring buffer event processing (`ringBufferHandler`)
- Event classification (determine event_type and severity)
- PID-to-socket correlation via ProcPeerResolver
- Enforcement action dispatch

**Event classification logic:**

**Uprobe events (HG_SOURCE_UPROBE):**
```cpp
if (tls_version < 0x0303) {
    event_type = HG_EVENT_TLS_VERSION_VIOLATION;
    severity = Critical;
    actionable = true;
    // → BlockTcpAction + BlocklistAddAction
} else {
    // Apply anomaly detection to payload
    if (suspicious) {
        event_type = HG_EVENT_HTTP_ANOMALY_DETECTED;
        severity = Warning;
    } else {
        event_type = HG_EVENT_HTTP_PAYLOAD_OBSERVED;
        severity = Informational;
    }
}
```

**XDP events (HG_SOURCE_XDP):**
```cpp
if (is_violation) {
    event_type = HG_EVENT_TLS_VERSION_VIOLATION;
    severity = Critical;
    // Already dropped by XDP, just log
} else if (payload_snippet[0] != '\0') {
    // Apply anomaly detection
    if (suspicious) {
        event_type = HG_EVENT_HTTP_ANOMALY_DETECTED;
        severity = Warning;
    } else {
        event_type = HG_EVENT_HTTP_PAYLOAD_OBSERVED;
        severity = Informational;
    }
} else {
    event_type = HG_EVENT_TLS_HANDSHAKE_METADATA;
    severity = Informational;
}
```

## Event Processing Pipeline

### Ring Buffer → Classification → Enforcement

```
BPF Event (ring buffer)
    │
    ▼
ringBufferHandler()
    │
    ├─ Read event_source discriminator
    │
    ├─ if HG_SOURCE_UPROBE:
    │   ├─ Extract tls_version, payload_snippet
    │   ├─ Classify based on tls_version
    │   ├─ ProcPeerResolver::getTcpSockets(pid)
    │   │   └─ Read /proc/<pid>/net/tcp
    │   │   └─ Parse hex format "AABBCCDD:PPPP"
    │   │   └─ Return socket 4-tuple
    │   └─ Enforcement:
    │       ├─ LogAction (always)
    │       ├─ BlockTcpAction(src_ip, dst_ip, src_port, dst_port)
    │       │   └─ TcpDestroyer::execute()
    │       │       └─ SOCK_DESTROY via NETLINK_INET_DIAG
    │       └─ BlocklistAddAction(src_ip, ttl)
    │           └─ Blocklist::add()
    │               └─ bpf_map_update_elem()
    │
    └─ if HG_SOURCE_XDP:
        ├─ Extract is_violation, socket info, payload
        ├─ Classify based on is_violation + payload
        └─ Enforcement:
            ├─ LogAction (always)
            ├─ BlockTcpAction (direct 4-tuple from event)
            └─ BlocklistAddAction (if actionable)
```

### ActionLoop - Async Dispatcher

Decouples event callback processing from I/O using Boost.Asio:

```
Main thread (ring_buffer__poll)
    │
    └─ on_event() callback
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

HTTPS-Guard implements a **hybrid security model** combining synchronous and asynchronous enforcement strategies.

### Two-Tier Strategy

**Tier 1 — Synchronous Enforcement (XDP only):**
- Blocklist check happens in BPF before any inspection
- Active blocklist entries → immediate XDP_DROP
- Zero userspace round-trip, sub-microsecond latency
- Limited to simple allow/deny rules (eBPF verifier constraints)

**Tier 2 — Asynchronous Detection (Uprobe + XDP):**
- All events submitted to ring buffer
- Userspace daemon classifies events (unlimited complexity)
- Complex pattern matching, anomaly detection, state machines
- Enforcement via SOCK_DESTROY + blocklist updates (feeds Tier 1)

### Why This Approach?

| Aspect | Synchronous (Tier 1) | Asynchronous (Tier 2) |
|--------|----------------------|-----------------------|
| Decision latency | Microseconds | Milliseconds |
| Policy complexity | Low (verifier-limited) | Unlimited (C++ stdlib) |
| Detection capability | Simple rules | Complex patterns, correlation |
| Failure mode | Drops packet | Logs + reactive enforcement |
| HTTPS-Guard usage | Blocklist only | Primary detection path |

### Platform-Adaptive Behavior

**On x86 servers with XDP-capable NICs:**
- Both uprobe and XDP loaded
- XDP provides proactive TLS version violation dropping
- Blocklist enables synchronous enforcement of repeat offenders
- Uprobe provides PID-to-socket correlation for enforcement

**On BMC platforms (ASpeed AST2600, QEMU SLIRP):**
- XDP fails to load (no ndo_bpf, no generic XDP support)
- Daemon gracefully falls back to uprobe-only mode
- TLS violations detected reactively:
  1. Uprobe fires on SSL_write()
  2. Daemon reads /proc/<pid>/net/tcp
  3. SOCK_DESTROY kills TCP connection
  4. Source IP logged for follow-up

### Key Design Decisions

1. **BPF is OBSERVATIONAL** - No classification, no event_type/severity in BPF
2. **Userspace is INTELLIGENT** - All classification, anomaly detection, policy
3. **Different structs per hook** - `uprobe_event` (176B) vs `xdp_event` (224B)
4. **No CO-RE for userspace structs** - ssl_st is userspace, not in kernel BTF
5. **Build-time offset detection** - gen_ssl_offset.c for ssl_st.version field

## Configuration

### https-guard.conf

Environment file for systemd services:

```bash
# Event sink mode: dbus, journal, or both
HTTPS_GUARD_EVENT_MODE=both

# Network interface to monitor
HTTPS_GUARD_INTERFACE=eth0

# OpenSSL shared library path
HTTPS_GUARD_SSL_LIB=/usr/lib/libssl.so.3

# Output log file path
HTTPS_GUARD_OUTPUT=/var/log/https_guard_events.log
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
   - Generates `ssl_version_offset.h`

3. `do_compile:prepend()`
   - Runs `gen_ssl_offset` to produce `ssl_version_offset.h`
   - Passes to CMake for BPF compilation

4. `do_compile`
   - CMake builds C++ daemon and BPF object

5. `do_install`
   - Installs binaries to `${sbindir}`
   - Installs BPF object to `${datadir}/https-guard/`
   - Installs systemd units to `${systemd_system_unitdir}`
   - Installs config to `${sysconfdir}/default/https-guard`
   - Stamps event mode into config from PACKAGECONFIG

**SRC_URI includes:**
- All shell scripts and systemd units
- CMakeLists.txt
- All C++ source/headers under `https_guard/`, `actions/`, `ebpf/`
- `scripts/gen_ssl_offset.c`

## Security Strategy: Asynchronous Active Response

This document describes the two fundamental strategies for implementing security enforcement with eBPF, and explains why HTTPS-Guard adopts the **Asynchronous Active Response** approach, with Uprobe as the primary detection path on BMC platforms.

### Strategy 1: Synchronous Inline Enforcement ("The Immediate Return")

In a synchronous inline model, the eBPF program itself **decides and enforces** a security policy within the kernel hook, returning a verdict before the operation completes. No event is sent to userspace for the decision path — the decision must be made in nanoseconds.

#### How it works

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

#### Characteristics

| Aspect | Property |
|--------|----------|
| Decision time | Sub-microsecond (single eBPF instruction) |
| Blocking capability | Yes — `XDP_DROP`, `bpf_override_return`, etc. |
| Policy complexity | Low — limited by eBPF verifier (max instructions, loops, helpers) |
| Userspace involvement | Only at policy pre-load time |
| Use case | DDoS filtering, IP blocklisting, simple allow/deny rules |

#### Limitations

- The eBPF verifier restricts program complexity — you cannot run regex, parse deeply nested protocols, or maintain complex state across connections without significant effort.
- Multi-stage attack detection (e.g. "a probe followed by an exploit 5 seconds later") is impractical because the eBPF program must decide on a single packet/event in isolation.
- Map-based policies must be pre-computed; dynamic learning (e.g. "this IP is now suspicious") requires a userspace feedback loop anyway.

### Strategy 2: Asynchronous Active Response ("The Fast Action Pipeline")

In an asynchronous model, the eBPF hook **defers** the decision to userspace. It emits an observation event via a ring buffer (or perf buffer) and immediately returns a non-blocking verdict (`XDP_PASS` / `0`). The userspace daemon, running in its own process context, receives the event milliseconds later, classifies it, and executes a countermeasure.

#### How it works

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
                            │  Userspace daemon                    │
                            │                                      │
                            │  ring_buffer__poll() loop            │
                            │    → on_event() callback             │
                            │      → pattern_detector (complex     │
                            │        rules, regex, state machine)  │
                            │      → classifier                    │
                            │      → countermeasure:               │
                            │          • SOCK_DESTROY TCP conn     │
                            │          • update eBPF blocklist     │
                            │          • kill process (optional)   │
                            │          • log / alert               │
                            └──────────────────────────────────────┘
```

#### Characteristics

| Aspect | Property |
|--------|----------|
| Decision time | Milliseconds (userspace round-trip) |
| Blocking capability | Indirectly — the daemon can terminate TCP connections via SOCK_DESTROY, update eBPF maps to block future events, or send signals to processes |
| Policy complexity | Unlimited — C++ code with full standard library, regex, machine learning, etc. |
| Userspace involvement | Every event is classified by userspace |
| Use case | Intrusion detection, anomaly scoring, multi-vector attack correlation |

#### Advantages over synchronous enforcement

1. **Complex threat detection** — Userspace can run full pattern matching (e.g. SQL injection signatures, path traversal), maintain cross-connection state, and correlate events from multiple eBPF hooks (uprobe + XDP in our case).

2. **No eBPF verifier pressure** — The kernel hook is kept minimal; the heavy work is done in C++ where there are no instruction limits or helper restrictions.

3. **Dynamic countermeasures** — The daemon can learn over time: if a source IP triggers multiple anomalies, the daemon can write a block entry into an eBPF map, and future packets from that IP will be dropped **synchronously** by the XDP program (a hybrid approach). The initial detection remains asynchronous.

4. **Fail-safe by default** — If the daemon crashes, the eBPF hook still returns `XDP_PASS` / `0`, so the system continues operating. The kernel path never blocks userspace recovery.

### Why HTTPS-Guard uses Strategy 2

#### Evidence in the source code

| Location | Evidence |
|----------|----------|
| `https_guard/https_guard.bpf.c:217-292` | Uprobe `SSL_write`: **PURELY OBSERVATIONAL** — reads ssl->version via `bpf_probe_read_user()` at offset 36, captures payload snippet, submits `uprobe_event` (no event_type, no severity), returns 0 |
| `https_guard/https_guard.bpf.c:370-518` | XDP program: **MINIMAL CLASSIFICATION** — sets `is_violation` flag (1 if TLS < 1.2, 0 otherwise), includes socket info, submits `xdp_event`; returns `XDP_DROP` for violations and blocklist hits |
| `https_guard/https_guard.bpf.c:56` | `blocklist_check(ip->saddr)` — hybrid enforcement: active blocklist entries trigger `XDP_DROP` before any inspection (must stay in BPF for line-rate) |
| `actions/blocklist/blocklist.bpf.h:22-36` | `blocklist_check()` inline function — performs `XDP_DROP` for active blocklist entries; prunes expired entries via `bpf_map_delete_elem()` |
| `https_guard/events.h:23-34` | `enum hg_event_source` — discriminator field (HG_SOURCE_UPROBE=1, HG_SOURCE_XDP=2) as first field in all event structs |
| `https_guard/events.h:44-62` | `struct uprobe_event` — purely observational: timestamp, pid/tgid, tls_version, process, payload_snippet (NO event_type, NO severity) |
| `https_guard/events.h:69-87` | `struct xdp_event` — minimal classification: adds is_violation flag, socket info (src/dst IP, port), source_ip string |
| `https_guard/events.h:36-57` | `struct hg_event` — legacy struct kept for backward compatibility with RedfishEventMessage |
| `https_guard/https_guard_program.cpp:144-346` | `ringBufferHandler()` — **USERSIDE CLASSIFICATION**: reads event_source discriminator, handles both uprobe_event and xdp_event, determines event_type/severity/message, applies anomaly detection, takes enforcement actions |
| `https_guard/https_guard_program.cpp:177-188` | Uprobe event classification: checks tls_version < 0x0303 → Critical violation; else applies anomaly detection |
| `https_guard/https_guard_program.cpp:196-226` | XDP event classification: checks is_violation flag → Critical; else checks payload → anomaly detection or informational |
| `https_guard/https_guard_program.cpp:38-61` | `https_guard_ssl_write` uprobe attached first (PRIMARY); XDP attached second (optional) |
| `https_guard/https_guard_program.cpp:245-282` | For uprobe events: calls `ProcPeerResolver::getTcpSockets(pid)` to read `/proc/<pid>/net/tcp` |
| `https_guard/https_guard_program.cpp:253-281` | Issues `BlockTcpAction` with resolved socket 4-tuple → SOCK_DESTROY + `BlocklistAddAction` |
| `https_guard/main.cpp:71` | `kDefaultBlocklistTtl = 5 minutes` — configurable blocklist TTL |
| `actions/blocklist/Blocklist.cpp:46-61` | `Blocklist::add()` — computes expiry and writes via `bpf_map_update_elem()` into the kernel BPF map |
| `actions/tcp/TcpDestroyer.cpp:69-182` | `TcpDestroyer::execute()` — sends `SOCK_DESTROY` via `NETLINK_INET_DIAG` to tear down the exact TCP 4-tuple |
| `actions/tcp/BlockTcpAction.cpp:29-57` | `BlockTcpAction::execute_async()` — constructs `TcpDestroyer` and offloads blocking call via `std::async` |
| `https_guard/proc_peer_resolver.hpp` | Parses `/proc/<pid>/net/tcp` to extract socket 4-tuples for uprobe-originated events |
| `https_guard/pattern_detector.hpp` | Complex string matching (SQL injection, path traversal) — impossible under eBPF verifier limits, runs in userspace |
| `https-guard-event-bridge.sh` | Full shell-level dispatch to D-Bus, journal, or filesystem — decisions made entirely in userspace |

### The pipeline is hybrid — asynchronous detection with synchronous enforcement (when XDP is available)

HTTPS-Guard's eBPF programs implement a **two-tier** strategy when XDP is available:

**Tier 1 — Synchronous enforcement (Strategy 1):** Before any packet inspection, the XDP hook calls `blocklist_check(ip->saddr)` which queries the shared BPF blocklist map. If the source IP has a non-expired entry, the packet is immediately dropped (`XDP_DROP`) with zero userspace round-trip. Expired entries are deleted opportunistically within the same BPF helper.

**Tier 2 — Asynchronous detection (Strategy 2):** If the packet is not blocklisted, the XDP program proceeds with TLS ClientHello and HTTP anomaly inspection. Events are submitted via `bpf_ringbuf_submit()` and the hook returns either `XDP_DROP` (for version violations) or `XDP_PASS`. The uprobe hook on `SSL_write` always returns `0` (pass).

```
Packet arrives on port 443
       │
       ▼
  ┌────────────────────────────────┐
  │ Tier 1: blocklist_check()      │  ← Synchronous enforcement (XDP only)
  │  ├── IP active  → XDP_DROP     │
  │  ├── IP expired → delete, PASS │
  │  └── IP absent  → XDP_PASS     │
  └──────────┬─────────────────────┘
             │ (if PASS)
             ▼
  ┌────────────────────────────────┐
  │ Tier 2: Uprobe + XDP detection │  ← Asynchronous detection
  │  ├── SSL_write → ring buffer   │
  │  ├── ClientHello → ring buffer │
  │  ├── XDP: version viol → DROP  │
  │  └── XDP_PASS (always uprobe)  │
  └──────────┬─────────────────────┘
             │
             ▼
  ┌────────────────────────────────┐
  │ Userspace daemon               │
  │  → classify event              │
  │  → for uprobe events:          │
  │    → ProcPeerResolver(pid)     │
  │    → read /proc/<pid>/net/tcp  │
  │    → get socket 4-tuple        │
  │  → if actionable:              │
  │    → BlockTcpAction(src,dst)   │
  │    → SOCK_DESTROY connection   │
  │    → BlocklistAddAction(src_ip)│
  │    → writes expiry into BPF map│  ← Feeds Tier 1
  └────────────────────────────────┘
```

### Platform-Aware Enforcement

HTTPS-Guard adapts to the capabilities of the underlying platform:

**On platforms with XDP support (e.g., x86 servers with supported NICs):**
- Both uprobe and XDP programs are loaded.
- XDP provides proactive TLS version violation dropping (XDP_DROP).
- The blocklist enables synchronous enforcement of future connections.
- Uprobe provides TLS version detection and PID-to-socket correlation for enforcement.

**On QEMU TAP+BRIDGE with virtio-net-pci:**
- The daemon tries native XDP first (XDP_FLAGS_UPDATE_IF_NOEXIST).
- If native XDP fails (no driver ndo_bpf), it falls back to generic XDP (XDP_FLAGS_SKB_MODE).
- Generic XDP hooks into `netif_receive_skb()` in software — no driver support needed.
- virtio-net supports both modes, so XDP attaches successfully in SKB mode.
- Expected daemon log: `"https_guard: XDP attached in generic (SKB) mode"`
- See [the top-level README](../README.md#enabling-xdp-in-qemu-bridge-mode) for setup steps.

**On BMC platforms without XDP (e.g., ASpeed AST2600 ftgmac100, QEMU SLIRP):**
- Native XDP fails (ftgmac100 has no ndo_bpf).
- Generic XDP also fails (SLIRP has no real netdev; real ftgmac100 lacks generic XDP too).
- Both failures are logged but non-fatal — the daemon continues with uprobe only.
- TLS version violations are detected reactively: the uprobe fires after `SSL_write()`,
  the daemon reads `/proc/<pid>/net/tcp` to find the socket, and issues SOCK_DESTROY
  to kill the TCP connection. The source IP is logged for follow-up.
- Verified: `ip link show eth0` shows no `xdp` or `prog/xdp` line on these platforms.

### How Uprobe-Only Enforcement Works

When the XDP program is not available (as on ASpeed AST2600), the enforcement flow is:

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
       ├── If version < 0x0303 (TLS 1.2):
       │     → HG_EVENT_TLS_VERSION_VIOLATION
       │     → Severity: CRITICAL
       │
       └── Submits event to ring buffer (with PID + TLS version, no socket info)
       │
       ▼
  Userspace daemon receives event
       │
       ├── ProcPeerResolver::getTcpSockets(pid)
       │     → reads /proc/<pid>/net/tcp
       │     → parses hex address format "AABBCCDD:PPPP"
       │     → returns socket 4-tuple (src_ip, dst_ip, src_port, dst_port)
       │
       ├── BlockTcpAction(src_ip, dst_ip, src_port, dst_port)
       │     → TcpDestroyer::async_execute()
       │     → SOCK_DESTROY via NETLINK_INET_DIAG
       │     → Kernel tears down the TCP socket
       │
       ├── BlocklistAddAction(src_ip, ttl)
       │     → Blocklist::add() → bpf_map_update_elem()
       │     → Future XDP packets from this IP would be dropped
       │
       └── LogAction → Redfish event JSON line
       │
       NOTE: The ssl_st offset is architecture-specific. On ARM 32-bit
       (johnblue) the version field is at offset 36. On x86_64 with
       8-byte pointers it would be at offset 20. If detection fails on
       a new platform, enable the bpf_printk diagnostic scanning code.
```

### The challenge: curl + OpenSSL 3.x always uses TLS 1.3

Modern OpenSSL 3.x has removed support for TLS 1.0 and TLS 1.1 at compile time.
The `--tlsv1.0` and `--tlsv1.1` flags are silently ignored — curl always negotiates
TLS 1.3 regardless of the flag:

```
curl -4 --tlsv1.0 -v -ku root:0penBmc https://localhost/redfish/v1
...
* TLSv1.3 (OUT), TLS handshake, Client hello (1):
* SSL connection using TLSv1.3 / TLS_AES_256_GCM_SHA384 / ...
```

This means the negotiated TLS version read by the uprobe will always be 0x0304
(TLS 1.3) for all curl connections on this platform. To test actual TLS < 1.2
detection, a legacy TLS client would be required.

### Architecture vs. x86

On a typical x86 Linux host with a supported NIC, HTTPS-Guard can load both the
XDP program and the uprobe. In an OpenBMC QEMU environment or real BMC hardware
with the ASpeed AST2600 ftgmac100 NIC, only the uprobe program functions. The
daemon handles this seamlessly: XDP is treated as an optional auxiliary program,
and the enforcement path adapts accordingly.

### Validation on ASpeed AST2600

The following has been verified on the target platform:

- `CONFIG_BPF=y`, `CONFIG_BPF_SYSCALL=y`, `CONFIG_UPROBE_EVENTS=y` ✅
- `ip link show eth0` shows **no XDP program loaded** (no `xdp` or `prog/xdp` line)
- `CONFIG_XDP` not present in kernel config
- Daemon logs: `"https_guard: enforcement active via uprobe(SSL_write)"`
- Uprobe fires on `SSL_write()` calls, events reach the ring buffer
- The daemon correctly handles the absence of XDP without crashing

### Summary

| | Synchronous (Strategy 1) | Asynchronous (Strategy 2) |
|---|---|---|
| **Decision location** | eBPF kernel hook | Userspace daemon |
| **Latency to action** | Microseconds | Milliseconds |
| **Policy complexity** | Limited (verifier) | Unlimited (C++/Python/Go) |
| **HTTPS-Guard choice** | ✅ (XDP blocklist enforcement, when available) | ✅ (primary detection pipeline) |
| **Detection path** | XDP: wire-level packet inspection | Uprobe: ssl->version + PID→socket lookup |
| **Enforcement** | XDP_DROP (proactive, on XDP platforms) | SOCK_DESTROY + blocklist (reactive, all platforms) |

---

*HTTPS-Guard implements a hybrid security model: asynchronous anomaly detection via uprobe (primary) with synchronous blocklist enforcement via XDP (when available). On BMC platforms without XDP support, the uprobe path provides reactive enforcement through PID-to-socket correlation and SOCK_DESTROY. The userspace daemon classifies events, and for actionable threats (TLS version violations, confirmed attack signatures), reads the process TCP sockets from /proc/<pid>/net/tcp, kills the connection via NETLINK_INET_DIAG, and logs the event for Redfish EventService dispatch.*

## Development

For top-level project overview, build instructions, and deployment guidance, see the root [README.md](../../README.md).

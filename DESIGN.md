# HTTPS-Guard — Design Reference

> **This is the detailed reference.** For build instructions, QEMU setup, and deployment, see the [top-level README](README.md). For a diagram-first architecture walkthrough, see [DESIGN.html](DESIGN.html).

This document covers the complete source code under `recipes-https-guard/https-guard/files/` — the eBPF programs, C++ daemon, enforcement actions, BitBake recipe, and security model. HTTPS-Guard implements a **Detect → Classify → Dispatch** pipeline: kernel-space eBPF programs (uprobe primary, XDP auxiliary) observe traffic and submit events via a ring buffer; the userspace daemon classifies events and triggers countermeasures.

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

| Aspect | Tier 1 (Synchronous) | Tier 2 (Asynchronous) |
|--------|----------------------|-----------------------|
| Decision latency | Microseconds | Milliseconds |
| Policy complexity | Low (verifier-limited) | Unlimited (C++ stdlib) |
| Failure mode | Drops the packet | Logs, then reacts |
| HTTPS-Guard's use | Blocklist enforcement only | Primary detection path |
| Enforcement action | `XDP_DROP` (proactive, XDP platforms only) | `SOCK_DESTROY` + blocklist write (reactive, all platforms) |

Evidence in the source:

| Location | Evidence |
|----------|----------|
| `https_guard/https_guard.bpf.c:217-292` | Uprobe `SSL_write`: purely observational — reads `ssl->version` via `bpf_probe_read_user()` at offset 36, captures a payload snippet, submits `uprobe_event` (no event_type, no severity), returns 0 |
| `https_guard/https_guard.bpf.c:370-518` | XDP: minimal classification — sets `is_violation` (1 if TLS < 1.2), includes socket info, submits `xdp_event`; returns `XDP_DROP` for violations and blocklist hits |
| `https_guard/https_guard.bpf.c:56` | `blocklist_check(ip->saddr)` — must stay in BPF for line-rate; active entries drop before any inspection |
| `actions/blocklist/blocklist.bpf.h:22-36` | `blocklist_check()` — drops active entries, prunes expired ones via `bpf_map_delete_elem()` |
| `https_guard/events.h:23-34` | `enum hg_event_source` discriminator (`HG_SOURCE_UPROBE=1`, `HG_SOURCE_XDP=2`) — first field in every event struct |
| `https_guard/https_guard_program.cpp:144-346` | `ringBufferHandler()` — the only place classification happens: reads the discriminator, applies anomaly detection, dispatches actions |
| `actions/blocklist/Blocklist.cpp:46-61` | `Blocklist::add()` — computes expiry, writes via `bpf_map_update_elem()`, the write Tier 1 later reads |
| `actions/tcp/TcpDestroyer.cpp:69-182` | `TcpDestroyer::execute()` — sends `SOCK_DESTROY` via `NETLINK_INET_DIAG` for the exact TCP 4-tuple |
| `https_guard/pattern_detector.hpp` | SQLi / path-traversal string matching — impossible under verifier limits, runs entirely in userspace |

Key design decisions this leads to:

1. **BPF is observational** — no `event_type`/`severity` fields exist in either BPF struct.
2. **Userspace is intelligent** — all classification, anomaly detection, and policy live in `https_guard_program.cpp`.
3. **Different structs per hook** — `uprobe_event` (176B) has no socket info; `xdp_event` (224B) does.
4. **No CO-RE for userspace structs** — `ssl_st` is a userspace type, not in kernel BTF, hence `gen_ssl_offset.c`.

### Platform-Adaptive Enforcement

The uprobe attaches unconditionally and never fails. XDP is attempted twice — native, then generic (SKB) — and skipped without error if neither is available:

**x86 servers / QEMU TAP+BRIDGE with virtio-net** — both programs load. XDP proactively drops TLS violations at the wire, the uprobe still resolves PID→socket for enforcement, and the blocklist protects future connections from repeat offenders. Generic (SKB) XDP hooks `netif_receive_skb()` in software, so `virtio-net-device` attaches successfully even without native driver support.

**AST2600 (johnblue) in bridge mode** — see [the top-level README](README.md#bridge-mode-recommended-for-xdp) for the TAP/bridge setup. The built-in `ftgmac100` may support native XDP if `CONFIG_XDP` is enabled in the kernel config; if not, the daemon falls back to uprobe-only below. Verified on the kernel actually shipped: `CONFIG_BPF=y`, `CONFIG_BPF_SYSCALL=y`, `CONFIG_UPROBE_EVENTS=y`, but `CONFIG_XDP` absent — `ip link show eth0` shows no `xdp`/`prog/xdp` line, and the daemon logs `"https_guard: enforcement active via uprobe(SSL_write)"`.

**QEMU SLIRP, or any platform without XDP** — native XDP fails (no `ndo_bpf`); generic XDP also fails (SLIRP has no real netdev). Both failures are logged but non-fatal. TLS violations are still caught, just reactively:

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
       │     → HG_EVENT_TLS_VERSION_VIOLATION, Severity: CRITICAL
       │
       └── Submits event to ring buffer (PID + TLS version, no socket info)
       │
       ▼
  Userspace daemon receives event
       │
       ├── ProcPeerResolver::getTcpSockets(pid)
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

**Caveat when testing with `curl`:** OpenSSL 3.x removed TLS 1.0/1.1 support at compile time, so `--tlsv1.0`/`--tlsv1.1` are silently ignored — curl always negotiates TLS 1.3 regardless of the flag:

```
curl -4 --tlsv1.0 -v -ku root:0penBmc https://localhost/redfish/v1
...
* TLSv1.3 (OUT), TLS handshake, Client hello (1):
* SSL connection using TLSv1.3 / TLS_AES_256_GCM_SHA384 / ...
```

The uprobe will read `0x0304` (TLS 1.3) for every curl connection on this platform; testing the actual TLS < 1.2 violation path requires a legacy TLS client.

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

## Development

For top-level project overview, build instructions, and deployment guidance, see the root [README.md](README.md).

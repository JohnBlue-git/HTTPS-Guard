# Source Code Reference: recipes-https-guard/https-guard/files/

This directory contains the complete source code of the **HTTPS-Guard** agent — an eBPF-based network security observability tool for OpenBMC. It implements a **Detect → Translate → Dispatch** pipeline using kernel-space XDP/uprobe programs, a user-space C++ daemon, a shell-based event bridge, and Redfish EventService integration.

> For a top-level project overview, build instructions, and deployment guidance, see the root [`README.md`](../../README.md).

---

## Table of Contents

- [Directory Layout](#directory-layout)
- [eBPF Programs (`https_guard/https_guard.bpf.c`)](#ebpf-programs-https_guardhttps_guardbpfc)
  - [XDP Hook: Wire-Level TLS Inspection](#xdp-hook-wire-level-tls-inspection)
  - [Hybrid Enforcement — XDP Blocklist (XDP_DROP)](#hybrid-enforcement--xdp-blocklist-xdp_drop)
  - [Uprobe Hook: Plaintext Payload Capture](#uprobe-hook-plaintext-payload-capture)
- [Event Data Model (`https_guard/events.h`)](#event-data-model-https_guardeventsh)
- [C++ Daemon (`https_guard/main.cpp`)](#c-daemon-https_guardmaincpp)
- [Pattern Detector (`https_guard/pattern_detector.hpp`)](#pattern-detector-https_guardpattern_detectorhpp)
- [ActionLoop — Async Event Dispatcher (`actions/ActionLoop.hpp`)](#actionloop--async-event-dispatcher-actionsactionloophpp)
- [LogAction — Async File Writer (`actions/LogAction.hpp`)](#logaction--async-file-writer-actionslogactionhpp)
- [Blocklist — Source IP Blocklist Manager (`actions/Blocklist.hpp`)](#blocklist--source-ip-blocklist-manager-actionsblocklisthpp)
- [BlocklistAddAction — Countermeasure Action (`actions/BlocklistAction.hpp`)](#blocklistaddaction--countermeasure-action-actionsblocklistactionhpp)
- [BlockTcpAction — TCP Connection Teardown (`actions/BlockTcpAction.hpp`)](#blocktcpaaction--tcp-connection-teardown-actionsblocktcpaactionhpp)
- [Blocklist BPF Header (`actions/blocklist.bpf.h`)](#blocklist-bpf-header-actionsblocklistbpfh)
- [AsyncFileStreamManager — Coroutine-Safe File Writer (`coroutine/async_mutex.hpp`)](#asyncfilestreammanager--coroutine-safe-file-writer-coroutineasync_mutexhpp)
- [Redfish Event Message (`https_guard/redfish_event_message.hpp`)](#redfish-event-message-https_guardredfish_event_messagehpp)
- [TLS Version (`https_guard/tls_version.hpp`)](#tls-version-https_guardtls_versionhpp)
- [CMake Build (`CMakeLists.txt`)](#cmake-build-cmakeliststxt)
- [Configuration (`https-guard.conf`)](#configuration-https-guardconf)
- [Security Strategy](SECURITY_STRATEGY.md)
- [OpenBMC Recipe (`https-guard-openbmc.bb`)](#openbmc-recipe-https-guard-openbmcbb)

---

## Directory Layout

```
files/
├── CMakeLists.txt                                    # CMake build definition
├── https-guard.conf                                  # EnvironmentFile for systemd units
├── https-guard-daemon.service                        # systemd unit for the eBPF daemon
├── https-guard-daemon.sh                             # Shell wrapper that launches https-guardd
├── https-guard-event-bridge.service                  # systemd unit for the event bridge
├── https-guard-event-bridge.sh                       # Shell bridge: tails log → D-Bus/journal/redfish
├── simulated-event-generator.service                 # systemd unit for synthetic event generator
├── simulated-event-generator.sh                      # Shell script that emits simulated events
├── coroutine/
│   └── async_mutex.hpp                               # AsyncFileStreamManager (coroutine-safe file I/O)
├── ebpf/
│   ├── bpf_program.hpp                                # BPF program attachment wrapper
│   └── bpf_program.cpp                                # BPF program wrapper implementation
├── https_guard/
│   ├── events.h                                      # Shared event struct & enums (BPF + C++)
│   ├── https_guard.bpf.c                              # eBPF programs (XDP + uprobe)
│   ├── https_guard_program.hpp                        # BPF object loader / ring-buffer adapter
│   ├── https_guard_program.cpp                        # BPF lifecycle implementation
│   ├── main.cpp                                      # C++ daemon entry point
│   ├── pattern_detector.hpp                          # User-space HTTP anomaly rules (inline)
│   ├── redfish_event_message.hpp                     # Redfish Event message with formatting (inline)
│   └── tls_version.hpp                               # TLS version helpers (inline)
├── actions/
│   ├── main.cpp                                      # ActionLoop smoke-test / demo entry point
│   ├── ActionLoop.hpp                                # Boost.Asio-based event dispatcher interface
│   ├── ActionLoop.cpp                                # Boost.Asio-based event dispatcher implementation
│   ├── LogAction.hpp                                 # Async file-logging action interface
│   ├── LogAction.cpp                                 # Async file-logging action implementation
│   ├── Blocklist.hpp                                 # Singleton blocklist manager (BPF map wrapper)
│   ├── Blocklist.cpp                                 # Blocklist singleton implementation
│   ├── BlocklistAction.hpp                           # Countermeasure action: add src IP to blocklist
│   ├── BlocklistAction.cpp                           # BlocklistAddAction implementation
│   ├── BlockTcpAction.hpp                            # Countermeasure action: kill TCP 4-tuple via tcp_drop
│   ├── BlockTcpAction.cpp                            # BlockTcpAction implementation (std::async wrapper)
│   ├── TcpDestroyer.hpp                              # RAII wrapper: Netlink SOCK_DESTROY lifecycle
│   ├── TcpDestroyer.cpp                              # TcpDestroyer implementation
│   └── blocklist.bpf.h                               # BPF-side blocklist header (XDP_DROP check)
```

---

## eBPF Programs (`https_guard/https_guard.bpf.c`)

The single BPF C file compiles to one BPF object that contains **two independent hook sections**, both writing to the same shared `events` ring buffer map:

| Section | Type | Hook Point | Purpose |
|---------|------|------------|---------|
| `SEC("xdp")` — `https_guard_xdp` | XDP | Network driver (RX path) | Inspects TLS ClientHello on port 443; detects TLS version violations and plaintext HTTP on the HTTPS port; performs hybrid enforcement by dropping packets from blocklisted source IPs |
| `SEC("uprobe/ssl_write")` — `https_guard_ssl_write` | Uprobe | Userspace function `SSL_write` in OpenSSL | Captures plaintext payload snippets just before encryption |

### XDP Hook: Wire-Level TLS Inspection

**What is inspected:**

1. **Ethernet + IP + TCP headers** — filters to IPv4, TCP-only traffic on port 443 (source or destination).
2. **TLS ClientHello record** — identifies packets whose first byte is `0x16` (TLS Handshake ContentType).
3. **TLS version field** — extracted from the ClientHello fixed portion at offset 5+4 (after the record header and handshake header). The version bytes `[major, minor]` are compared against `0x0303` (TLS 1.2):
   - `< 0x0303` → `HG_EVENT_TLS_VERSION_VIOLATION` (severity `CRITICAL`)
   - `>= 0x0303` → `HG_EVENT_TLS_HANDSHAKE_METADATA` (severity `INFO`)
4. **SNI (Server Name Indication)** — walks the TLS extensions to find extension type `0x0000` and extracts the first hostname into `evt->sni`.
5. **Plaintext HTTP on port 443** — after the TLS handshake is expected to have occurred, detects unencrypted HTTP method verbs (`GET`, `POST`, `PUT`, `DELETE`, `HEAD`, `PATCH`, `OPTIONS`, `CONNECT`, `TRACE`) appearing on the wire. This is an anomaly signal that raw HTTP is being sent over a port that should carry TLS-encrypted traffic.

**Filtering actions:**

- The XDP program **observes and reports** (`XDP_PASS`) all TLS handshake and HTTP anomaly events — it does **not** drop packets based on protocol violations alone.
- However, the XDP program **does** perform **hybrid enforcement**: before any inspection, it calls `blocklist_check(ip->saddr)` (see [`actions/blocklist.bpf.h`](#blocklist-bpf-header-actionsblocklistbpfh)). If the source IP is found in the shared blocklist BPF map with a non-expired entry, the packet is **immediately dropped** (`XDP_DROP`) before any further processing.
- The blocklist map is populated by the userspace daemon after classifying an event as actionable (e.g., TLS version violation or confirmed attack signature). The daemon computes an expiry timestamp and writes it into the map via the `Blocklist` singleton.
- Expired entries are pruned opportunistically by `blocklist_check()` when the current time exceeds the stored expiry.

### Hybrid Enforcement — XDP Blocklist (XDP_DROP)

The blocklist mechanism is the **only** path in the XDP program that returns a non-PASS verdict. It enables a dynamic enforcement loop:

```
Kernel:  XDP hook sees packet → blocklist_check(ip->saddr)
          ├── IP not in blocklist → XDP_PASS (continue inspection)
          ├── IP expired         → delete entry → XDP_PASS
          └── IP active          → XDP_DROP     ← enforcement
                 ▲
Userspace: daemon classifies event → actionable?
          ├── yes → BlocklistAddAction(src_ip, ttl)
          │        → Blocklist::add() writes expiry into BPF map
          └── no  → log only, no blocklist action
```

The blocklist map (`src_blocklist`) is a `BPF_MAP_TYPE_HASH` with a maximum of 1024 entries (see `HTTPS_GUARD_BLOCKLIST_MAX_ENTRIES`). Each entry maps a source IP (network byte order) to an absolute expiry timestamp in nanoseconds (using `bpf_ktime_get_ns()` clock).

**Design rationale:** keeping expiry checking in BPF avoids the latency and complexity of a userspace timer. The daemon only writes new entries; the kernel handles both enforcement and garbage collection.

### Uprobe Hook: Plaintext Payload Capture

**What is hooked:**

- The OpenSSL library function `SSL_write(SSL *ssl, const void *buf, int num)`.

**What is captured:**

- **Plaintext buffer** (`buf`) — the unencrypted data that the application is about to send.
- **Length** (`num`) — number of bytes of plaintext.
- **Snippet** — up to 127 bytes of the plaintext payload are copied into `evt->payload_snippet` using `bpf_probe_read_user()`.

**Filters applied:**

- `num <= 0` or `buf == NULL` → skip (no event emitted).
- All nonzero-length writes produce an `HG_EVENT_HTTP_PAYLOAD_OBSERVED` event (severity `INFO`).

**How the two hooks share the ring buffer:**

```
Network traffic (port 443)
       │
       ├── blocklist_check(ip->saddr)  ← hybrid enforcement
       │   └── active → XDP_DROP
       │
       ├── XDP hook reads TLS ClientHello
       │   ├── version < 1.2  → TLS_VERSION_VIOLATION event
       │   └── version ≥ 1.2  → TLS_HANDSHAKE_METADATA event (with SNI)
       │
       └── XDP hook detects plaintext HTTP
           └── HTTP_ANOMALY_DETECTED event

Process writing to OpenSSL
       │
       └── Uprobe hook on SSL_write
           └── HTTP_PAYLOAD_OBSERVED event (with plaintext snippet)

Both hooks write events into the same `events` ring buffer map.
The C++ daemon polls this single ring buffer via a single `ring_buffer__poll()` loop
and classifies events by their `event_type` field.
```

---

## Event Data Model (`https_guard/events.h`)

The header is dual-purposed: it is included both by the BPF C program (compiled with `clang -target bpf`) and by the C++ daemon. When compiled for BPF, it provides its own minimal integer types; when compiled for C++, it uses `<stdint.h>`.

### Event Types (`enum hg_event_type`)

| Value | Name | Source | Meaning |
|-------|------|--------|---------|
| 1 | `HG_EVENT_TLS_VERSION_VIOLATION` | XDP | Client offered TLS version < 1.2 (could be 1.0 or 1.1) |
| 2 | `HG_EVENT_TLS_HANDSHAKE_METADATA` | XDP | Client offered TLS ≥ 1.2; event carries SNI and version info |
| 3 | `HG_EVENT_HTTP_PAYLOAD_OBSERVED` | Uprobe | A plaintext payload was observed via SSL_write |
| 4 | `HG_EVENT_HTTP_ANOMALY_DETECTED` | XDP | Plaintext HTTP verbs observed on port 443 (suggesting a protocol violation) |

### Severity Levels (`enum hg_severity`)

| Value | Name | Used For |
|-------|------|----------|
| 0 | `HG_SEV_INFO` | TLS handshake metadata, payload observations |
| 1 | `HG_SEV_WARNING` | HTTP anomalies (may indicate probing/misconfiguration) |
| 2 | `HG_SEV_CRITICAL` | TLS version violations (insecure protocol in use) |

### Event Struct (`struct hg_event`)

```
timestamp_ns (uint64)    — BPF ktime in nanoseconds
event_type   (uint32)    — hg_event_type enum
severity     (uint32)    — hg_severity enum
pid          (uint32)    — Kernel PID of the process
tgid         (uint32)    — Kernel TGID (thread group = process ID)
src_ip_v4    (uint32)    — Source IPv4 address (network byte order)
dst_ip_v4    (uint32)    — Destination IPv4 address (network byte order)
src_port     (uint16)    — Source TCP port (host byte order)
dst_port     (uint16)    — Destination TCP port (host byte order)
tls_version  (uint16)    — TLS version code (e.g. 0x0301 = 1.0, 0x0304 = 1.3)
tls_record_type (uint16) — TLS record ContentType (reserved for future use)
process      (char[16])  — Comm name of the process (from bpf_get_current_comm)
source_ip    (char[32])  — Dotted-decimal string of source IP (filled by XDP)
sni          (char[64])  — SNI hostname extracted from TLS ClientHello
uri          (char[128]) — URI field (reserved for future use)
payload_snippet (char[128]) — Plaintext snippet from uprobe or HTTP anomaly
```

---

## C++ Daemon (`https_guard/main.cpp`)

The daemon's `main()` function orchestrates the full eBPF lifecycle and event dispatch pipeline via the ActionLoop:

### Initialization Flow

1. **Parse CLI arguments** (4 positional):
   - `argv[1]` — Network interface (default: `eth0`).
   - `argv[2]` — OpenSSL shared library path (default: `/usr/lib/x86_64-linux-gnu/libssl.so.3`).
   - `argv[3]` — Output log path (default: `/var/log/redfish/https_guard_events.log`).
   - `argv[4]` — BPF object file path (default: `./build/https_guard.bpf.o`).

2. **Seed the ActionLoop** — obtains the singleton `ActionLoop::getInstance()` and pushes a `LogAction` that writes to the configured output path. The ActionLoop runs a background Boost.Asio `io_context` that processes actions asynchronously.

3. **Load and verify** the BPF object via `libbpf`:
   - `bpf_object__open_file()` — parses the ELF BPF object.
   - `bpf_object__load()` — loads programs into the kernel and creates maps.

4. **Create `HttpGuardProgram`** — passing the BPF object path, the `ActionLoop` reference, OpenSSL library path, network interface index, a default blocklist TTL of 5 minutes, and the configured output path. The program:
   - Attaches the XDP program to the network interface.
   - Attaches the uprobe to `SSL_write` in the specified OpenSSL shared library.
   - **Adopts the blocklist BPF map** (`src_blocklist`) so the daemon can populate it with offending source IPs.

5. **Open ring buffer consumer** — `ring_buffer__new()` maps the `events` BPF map and registers the `on_event` callback.

6. **Poll loop** — `ring_buffer__poll()` is called in a 200ms interval loop until SIGINT or SIGTERM is received.

### Event Processing (`on_event` callback via `ringBufferHandler`)

The callback classifies incoming ring buffer events:

1. **Size validation** — drops undersized (< `sizeof(hg_event)`) records.
2. **Event type dispatch**:
   - `HG_EVENT_TLS_VERSION_VIOLATION` →
     - Sets severity to `"Critical"`.
     - Uses message ID `OemSecurityEvent.1.0.0.HttpsTlsVersionViolation`.
     - Composes a human-readable message including process name, PID, and TLS version string.
     - Marks the event as **actionable** (triggers blocklist insertion and TCP teardown).
   - `HG_EVENT_HTTP_PAYLOAD_OBSERVED` or `HG_EVENT_HTTP_ANOMALY_DETECTED` →
     - Runs user-space anomaly detection via `detector_.isSuspicious()`.
     - If the payload matches a rule (or was already flagged by the kernel as an anomaly), the event is promoted to `"Warning"`.
     - Uses message ID `OemSecurityEvent.1.0.0.HttpsPayloadAnomalyDetected`.
     - Includes the matched rule name in the message.
     - If suspicious, marks the event as **actionable** (triggers blocklist insertion and TCP teardown).
   - All other event types are silently dropped.

3. **Dispatch actions via ActionLoop**:
   - **LogAction** — always pushed for every actionable event. Formats the event via `RedfishEventMessage::format()` and writes it asynchronously to the configured output path (`output_path_`, from `cfg.output_path`) using the `AsyncFileStreamManager`.
   - **BlocklistAddAction** — pushed for actionable events with a non-zero `src_ip_v4`. Creates a blocklist entry with the configured TTL (default: 5 minutes). This causes the XDP program to drop subsequent packets from that source IP.
   - **BlockTcpAction** — pushed for actionable events with a non-zero `src_ip_v4`. Kills the specific TCP connection 4-tuple (src/dst IP, src/dst port) via the kernel's `tcp_drop` facility (`SOCK_DESTROY` over `NETLINK_INET_DIAG`). This tears down the kernel socket without touching the owning process, causing the remote peer to receive RST/EPIPE on its next I/O operation.

### Cleanup

On signal, the poll loop exits, the ring buffer is freed, BPF links are destroyed, and the BPF object is closed. The ActionLoop's destructor stops its `io_context` and joins the background thread.

---

## Pattern Detector (`https_guard/pattern_detector.hpp`)

The user-space anomaly detection engine applies a set of **static signature rules** to plaintext payload snippets. The implementation is **inline** in the header, so no separate `.cpp` file is needed.

### Rule Set

| Rule | Description | Example Attack |
|------|-------------|----------------|
| `../..` | Directory traversal | Path traversal in query parameters |
| `union select` | SQL injection | Classic SQLi union-based extraction |
| `or 1=1` | SQL tautology | Authentication bypass via `' OR '1'='1` |
| `drop table` | SQL DDL injection | Destructive database manipulation |
| `/etc/passwd` | File inclusion | Reading sensitive system files |
| `%2e%2e%2f` | URL-encoded path traversal | `%2e%2e%2f` = `../` URL-encoded |
| `cmd.exe` | Windows command execution | Remote command execution on Windows targets |
| `wget http` | Remote payload download | Wget used to download malicious payloads |

### Detection Algorithm

1. The payload string is **lowercased** (case-insensitive matching).
2. Each rule pattern is searched using `std::string::find()` (substring match).
3. On the first match, `matched_rule` is set to the matched pattern and the function returns `true`.
4. If no rules match, returns `false`.

### Design Notes

- The rule set is **static** and compiled into the binary. Future versions should load rules from a configuration file.
- Substring matching generates false positives on benign payloads containing rule substrings (e.g., a legit path `/etc/passwd` in an error message). This is a known limitation of signature-based detection.
- The detector runs **after** the eBPF layer has already forwarded the event, so it acts as a secondary classification filter.

---

## ActionLoop — Async Event Dispatcher (`actions/ActionLoop.hpp`)

The `ActionLoop` is a singleton that decouples eBPF event callback processing from downstream I/O (logging, D-Bus, blocklist updates, TCP teardown). It wraps a Boost.Asio `io_context` running on a dedicated background thread:

### Architecture

```
main thread (ring_buffer__poll)
  │
  └── on_event() callback
       ├── pushAction(LogAction)          → ActionLoop queue
       ├── pushAction(BlocklistAddAction) → ActionLoop queue
       └── pushAction(BlockTcpAction)     → ActionLoop queue
              │
              ▼
       Background thread (io_context::run)
              │
              ├── co_spawn LogAction::execute_async()
              │    └── AsyncFileStreamManager::acquire_stream()
              │         └── async_write() to log file
              │
              ├── co_spawn BlocklistAddAction::execute_async()
              │    └── Blocklist::instance().add(src_ip, ttl)
              │         └── bpf_map_update_elem() on blocklist BPF map
              │
              └── co_spawn BlockTcpAction::execute_async()
                   └── SOCK_DESTROY via NETLINK_INET_DIAG
```

### Key Design Decisions

- **Non-blocking callbacks** — `pushAction()` enqueues the action and returns immediately. The `on_event()` callback never blocks on file I/O, BPF map updates, or Netlink operations.
- **Background execution** — `ActionLoop` spawns a single background thread that runs `io_context.run()`. All action execution happens on this thread.
- **Exception safety** — exceptions thrown by `execute_async()` are caught and logged; they never propagate to the main thread.
- **Lifetime** — the `ActionLoop` is a process-level singleton (`getInstance()`). Its destructor joins the background thread to ensure orderly shutdown.

### `IAction` Interface

All actions implement `boost::asio::awaitable<void> execute_async()`, enabling coroutine-based async execution.

---

## LogAction — Async File Writer (`actions/LogAction.hpp`)

`LogAction` writes a JSON event line to a log file asynchronously, cooperating with the `ActionLoop` and `AsyncFileStreamManager`.

### Behavior

1. **Acquire** a locked stream to the target file via `AsyncFileStreamManager::acquire_stream()`.
2. **Write** the payload (JSON line + newline) using `boost::asio::async_write()`.
3. **Handle errors** — if `async_write()` fails, the error is logged to stderr but does **not** crash the ActionLoop.

### Why async writes?

Writing to the filesystem directly from the eBPF ring-buffer callback would block the poll loop, risking dropped events. By delegating the write to the ActionLoop's background thread and using `co_await async_write()`, the callback returns instantly and the kernel can continue delivering events.

---

## Blocklist — Source IP Blocklist Manager (`actions/Blocklist.hpp`)

`Blocklist` is a singleton that wraps the shared BPF map (`src_blocklist`, a `BPF_MAP_TYPE_HASH`) that stores source IP → expiry timestamp mappings. It is the userspace interface for **hybrid enforcement**.

### API

| Method | Description |
|--------|-------------|
| `adopt(int map_fd)` | Adopts an existing BPF map file descriptor. Called once during daemon startup after the BPF object is loaded. |
| `contains(uint32_t src_ip_v4)` | Checks if a source IP has a non-expired blocklist entry (reads from the BPF map). |
| `add(uint32_t src_ip_v4, seconds ttl)` | Inserts or refreshes a blocklist entry with an absolute expiry. Returns 0 on success, negative errno on failure. |
| `formatIp(uint32_t src_ip_v4)` | Converts a network-byte-order IPv4 address to a dotted-decimal string. |

### Design Notes

- The BPF map stores values as `uint64_t` absolute expiry timestamps (nanoseconds since boot, matching `bpf_ktime_get_ns()` in kernel space).
- `add()` computes `now_ns + ttl_ns` and writes the result to the BPF map using `bpf_map_update_elem()` with `BPF_ANY`.
- `contains()` reads the map value and compares against the current time. Expired entries are **not** deleted from userspace — that responsibility is left to the BPF `blocklist_check()` function for efficiency.
- The singleton is thread-safe via its internal design (single background thread writes, main thread only reads during shutdown).

---

## BlocklistAddAction — Countermeasure Action (`actions/BlocklistAction.hpp`)

`BlocklistAddAction` is an `IAction` that adds a single source IP address to the blocklist with a configurable TTL. It is pushed by `ringBufferHandler` when an event is classified as **actionable** (TLS version violation or confirmed attack signature).

```cpp
class BlocklistAddAction final : public IAction {
    // src_ip_v4:  IP to block (network byte order)
    // ttl:        How long to block (default: 5 minutes)
    // reason:     Human-readable reason (included in stderr log)
    BlocklistAddAction(uint32_t src_ip_v4,
                       std::chrono::seconds ttl,
                       std::string reason);
    boost::asio::awaitable<void> execute_async() override;
};
```

On execution, it calls `Blocklist::instance().add(src_ip_v4_, ttl_)`. Success/failure is logged to stderr.

---

## BlockTcpAction — TCP Connection Teardown (`actions/BlockTcpAction.hpp`)

`BlockTcpAction` is an `IAction` that instantly kills a specific TCP socket tuple using the kernel's `tcp_drop` facility (available via `NETLINK_INET_DIAG` + `SOCK_DESTROY`). It is pushed by `ringBufferHandler` alongside `BlocklistAddAction` whenever an event is classified as **actionable**.

Unlike the blocklist action (which prevents future connections from a source IP), `BlockTcpAction` targets the **current active connection** by its exact 4-tuple (source IP, destination IP, source port, destination port).

```cpp
class BlockTcpAction final : public IAction {
    // src_ip_v4 / dst_ip_v4:  IPv4 addresses (network byte order)
    // src_port / dst_port:    TCP ports (host byte order)
    // reason:                 Human-readable reason (included in stderr log)
    BlockTcpAction(uint32_t src_ip_v4,
                   uint32_t dst_ip_v4,
                   uint16_t src_port,
                   uint16_t dst_port,
                   std::string reason);
    boost::asio::awaitable<void> execute_async() override;
};
```

### Architecture

The TCP teardown logic is split across two classes:

| Class | Role | File |
|-------|------|------|
| `TcpDestroyer` | RAII wrapper: opens a `NETLINK_INET_DIAG` socket in the constructor, closes it in the destructor. Provides a synchronous `execute()` method that performs the Netlink SOCK_DESTROY send/recv. | `TcpDestroyer.hpp`, `TcpDestroyer.cpp` |
| `BlockTcpAction` | `IAction` adapter that constructs a `TcpDestroyer` in its `execute_async()` coroutine and offloads the blocking call via `std::async`. | `BlockTcpAction.hpp`, `BlockTcpAction.cpp` |

### How it works

`BlockTcpAction::execute_async()` is a Boost.Asio coroutine that:

1. **Constructs a `TcpDestroyer`** via `std::make_shared<TcpDestroyer>(...)` — the constructor opens a `NETLINK_INET_DIAG` socket (`SOCK_DGRAM | SOCK_CLOEXEC`). The `shared_ptr` keeps the destroyer alive across the `std::async` boundary.
2. **Offloads the blocking call** with `std::async(std::launch::async, ...)` — the synchronous `TcpDestroyer::execute()` runs on a C++ runtime-managed thread pool:
   - Builds an `inet_diag_req_v2` struct with `SOCK_DESTROY` as the Netlink message type, matching `AF_INET`, `IPPROTO_TCP`, and all TCP states (`0xFFF`).
   - Sets `idiag_cookie[0]` and `idiag_cookie[1]` to `~0ULL` — the kernel interprets this as "don't care / match any socket".
   - Sends the destroy command via `sendmsg()` to the kernel.
   - Reads the kernel's reply via `recvmsg()` — `NLMSG_ERROR` with `error == 0` indicates the destroy request was accepted.
   - Logs success or failure (with `strerror(errno)` on error).
3. **Polls the returned `std::future<bool>`** — a tight loop checks `future.wait_for(1ms)` and yields back to the ActionLoop's `io_context` via `co_await boost::asio::post(boost::asio::use_awaitable)` between each check, ensuring other coroutines are not starved.
4. **RAII cleanup** — when the `shared_ptr`'s last copy goes out of scope (after the `std::async` task completes), the `TcpDestroyer` destructor closes the Netlink fd automatically, eliminating any risk of fd leaks.

### `tcp_drop` / `SOCK_DESTROY` semantics (Linux 4.10+)

- The kernel tears down the TCP socket that matches the given 4-tuple **without touching the owning process**.
- The process receives a standard error (typically `EPIPE` / `ECONNRESET`) on its next I/O operation.
- The operation is asynchronous from the kernel's perspective: the Netlink reply only confirms that the request was **accepted**, not that the socket has already been destroyed.

### Design Rationale

- **Not killing the PID** — The action operates entirely at the kernel TCP socket layer, never sending signals to the process. This is safe even if multiple connections share the same process.
- **Complementary to blocklist** — The blocklist prevents new connections from the offending IP. `BlockTcpAction` terminates the current connection immediately, providing instant response without waiting for the TCP keepalive or timeout.

---

## Blocklist BPF Header (`actions/blocklist.bpf.h`)

This header is shared between the BPF C code and the C++ userspace. It defines:

- **Map name constant**: `HTTPS_GUARD_BLOCKLIST_MAP_NAME` → `"src_blocklist"`
- **Max entries constant**: `HTTPS_GUARD_BLOCKLIST_MAX_ENTRIES` → `1024`
- **BPF map definition** (compiled only in `__cplusplus`-false context): a `BPF_MAP_TYPE_HASH` named `src_blocklist` with `__u32` keys and `__u64` values.
- **`blocklist_check(__u32 src_ip_v4)`** — inline function that:
  1. Looks up the source IP in the blocklist map.
  2. If not found → returns `XDP_PASS`.
  3. If expired (now >= expiry) → deletes the entry → returns `XDP_PASS`.
  4. If active → returns `XDP_DROP` (packet is dropped before any inspection).

The XDP program in `https_guard.bpf.c` includes this header via `#include "../actions/blocklist.bpf.h"` and calls `blocklist_check(ip->saddr)` as its first packet-processing step.

---

## AsyncFileStreamManager — Coroutine-Safe File Writer (`coroutine/async_mutex.hpp`)

The `AsyncFileStreamManager` provides coroutine-safe, asynchronous file writing for the `ActionLoop` framework. It solves the problem of multiple concurrent coroutines needing to write to the same log file without blocking or interleaving lines.

### Key Features

- **Coroutine-based locking** — each coroutine requests a `LockedStream` via `acquire_stream(filename)`. If another coroutine is currently writing to the same file, the requesting coroutine is suspended until the lock is released.
- **Stream caching** — open file descriptors are cached in `stream_cache_`. Once a file is opened, future `acquire_stream()` calls reuse the same `asio::posix::stream_descriptor`.
- **RAII unlock** — when the `LockedStream` goes out of scope (or is destroyed), the destructor calls `unlock()`, which either resumes the next waiting coroutine or removes the file state entry.

### Usage in LogAction

```cpp
asio::awaitable<void> LogAction::execute_async()
{
    auto locked_stream = co_await g_file_mgr.acquire_stream(path_);
    if (!locked_stream) co_return;
    co_await asio::async_write(locked_stream.stream(),
                               asio::buffer(payload), ...);
    // locked_stream destructor releases the lock
}
```

---

## Redfish Event Message (`https_guard/redfish_event_message.hpp`)

A data class that encapsulates event information (hg_event, message_id, message, severity) and provides JSON formatting for Redfish EventService. Replaces the previous `RedfishFormatter` class by combining data storage with formatting capability. The implementation is **inline** in the header, using the [nlohmann/json](https://github.com/nlohmann/json) library for safe, standards-compliant serialization.

### Class Structure

```cpp
class RedfishEventMessage {
public:
    RedfishEventMessage(const hg_event& event,
                        std::string message_id,
                        std::string message,
                        std::string severity);

    std::string format() const;  // Returns JSON-formatted Redfish event

    const hg_event& getEvent() const;
    const std::string& getMessageId() const;
    const std::string& getMessage() const;
    const std::string& getSeverity() const;
};
```

### Output Format

The `format()` method returns a Redfish Event JSON line following the [Redfish Event v1.7.0](https://redfish.dmtf.org/) specification:

```json
{
  "@odata.type": "#Event.v1_7_0.Event",
  "Name": "Platform Security Anomaly Event",
  "Id": "<timestamp_ns>",
  "Events": [
    {
      "EventId": "<timestamp_ns>-<pid>",
      "Severity": "<severity>",
      "MessageId": "<message_id>",
      "Message": "<escaped_message>",
      "EventTimestamp": "<ISO8601_UTC>",
      "OriginOfCondition": {
        "@odata.id": "/redfish/v1/Managers/BMC"
      }
    }
  ]
}
```

### Fields

| Field | Source |
|-------|--------|
| `Id` | `hg_event.timestamp_ns` (unique per event) |
| `EventId` | `timestamp_ns` + `-` + `pid` (unique per process-event) |
| `Severity` | `"OK"`, `"Warning"`, or `"Critical"` (passed to constructor) |
| `MessageId` | `OemSecurityEvent.1.0.0.HttpsTlsVersionViolation` or `OemSecurityEvent.1.0.0.HttpsPayloadAnomalyDetected` |
| `Message` | Human-readable string containing process, PID, TLS version, or matched rule |
| `EventTimestamp` | Current UTC time in ISO 8601 format (`YYYY-MM-DDTHH:MM:SSZ`) |

---

## TLS Version (`https_guard/tls_version.hpp`)

A utility class that converts TLS version codes (as extracted from wire-level TLS ClientHello packets) into human-readable strings. The implementation is **inline** in the header.

### `TlsVersion` Class

```cpp
class TlsVersion {
public:
    explicit TlsVersion(uint16_t value);
    std::string toString() const;  // Returns human-readable version string
};
```

### Supported Versions

| Code | String |
|------|--------|
| `0x0301` | `TLS 1.0` |
| `0x0302` | `TLS 1.1` |
| `0x0303` | `TLS 1.2` |
| `0x0304` | `TLS 1.3` |
| Other | `Unknown` |

---

## CMake Build (`CMakeLists.txt`)

- **C++ Standard**: C++20.
- **Dependencies**: `libbpf` (found via pkg-config), `nlohmann_json` (found via `find_package`), and Boost.Asio headers.
- **Boost handling**: Uses system Boost headers when available; otherwise fetches Boost 1.86 headers via CMake `FetchContent` and compiles Asio in header-only mode.
- **BPF object build** (optional via `HTTPS_GUARD_BUILD_BPF`):
  - Generates a target-kernel `vmlinux.h` using `bpftool btf dump`.
  - Compiles `https_guard/https_guard.bpf.c` with `clang -target bpf` and CO-RE flags.
- **Target**: `https_guardd` — compiles `https_guard/main.cpp`, `https_guard/https_guard_program.cpp`, `actions/ActionLoop.cpp`, `actions/Blocklist.cpp`, `actions/LogAction.cpp`, `actions/BlocklistAction.cpp`, `actions/BlockTcpAction.cpp`, and `ebpf/bpf_program.cpp`.
- **Secondary target**: `action_runner` — compiles `actions/main.cpp` plus `actions/ActionLoop.cpp` for exercising the dispatcher loop in isolation.
- **Include paths**: `https_guard/`, `actions/`, `coroutine/`, `ebpf/`, libbpf headers, nlohmann_json headers, and Boost headers.
- **Libraries**: `libbpf` + `nlohmann_json::nlohmann_json`.
- **Compile definitions**: `BOOST_ERROR_CODE_HEADER_ONLY` for all targets.

---

## Configuration (`https-guard.conf`)

The config file uses shell variable syntax and is sourced as an `EnvironmentFile` by systemd units.

| Variable | Default | Purpose |
|----------|---------|---------|
| `HTTPS_GUARD_IFACE` | `eth0` | Network interface for XDP attachment |
| `HTTPS_GUARD_BPF_OBJ` | `/usr/share/https-guard/https_guard.bpf.o` | Installed BPF object path |
| `HTTPS_GUARD_SSL_LIB` | `/usr/lib/x86_64-linux-gnu/libssl.so.3` | OpenSSL library path for uprobe |
| `HTTPS_GUARD_SIMULATE_INTERVAL` | `15` | Seconds between simulated events (generator mode) |
| `HTTPS_GUARD_EVENT_MODE` | `@@EVENT_MODE@@` (build-time placeholder) | `dbus`, `journal`, or `both` |
| `HTTPS_GUARD_EVENT_FILE` | `/var/log/https_guard_events.log` | JSON event archive (daemon output) |
| `HTTPS_GUARD_REDFISH_LOG` | `/var/log/redfish` | Plain-text log watched by bmcweb |

The `@@EVENT_MODE@@` placeholder is replaced at build time by the OpenBMC recipe with the actual value from `PACKAGECONFIG`.

---

## OpenBMC Recipe (`https-guard-openbmc.bb`)

See the top-level [README.md](../../README.md) for detailed usage. Key points:

### Build Steps

1. `do_configure[depends]` — adds a dependency on `virtual/kernel:do_compile` to ensure the kernel vmlinux is available for CO-RE header generation.
2. `do_configure:prepend` — locates the target kernel `vmlinux` (from `STAGING_KERNEL_BUILDDIR`, or via `find` in tmpdir) and symlinks it into the work directory as `target-kernel-vmlinux`. Used by the CMake `HTTPS_GUARD_TARGET_VMLINUX` variable.
3. `do_compile:append` — the CMake build handles BPF compilation via `add_custom_target(https_guard_bpf)`, triggered by `HTTPS_GUARD_BUILD_BPF=ON`.
4. `do_install` — installs shell wrappers (stripping `.sh` extension), the compiled daemon binary (`https-guardd`), the `action_runner` demo binary, the BPF object file, systemd unit files, and the processed config file with the event mode stamped in.

### PACKAGECONFIG Flags

**Service selection** (which systemd services are auto-enabled):

| Flag | Daemon | Generator | Bridge | Use Case |
|------|--------|-----------|--------|----------|
| `simulation` (default) | ✗ | ✓ | ✓ | QEMU slirp testing, no eBPF |
| `daemon` | ✓ | ✗ | ✓ | Real hardware/TAP with eBPF |
| `both` | ✓ | ✓ | ✓ | Debugging, comparing real vs. simulated |

**Event sink mode** (how events reach Redfish EventService):

| Flag | Config Value | D-Bus | systemd-cat | /var/log/redfish | Delivery |
|------|-------------|-------|-------------|-------------------|----------|
| `event-both` (default) | `both` | ✓ | ✓ | ✗ | D-Bus monitor (bmcweb) |
| `dbus-only` | `dbus` | ✓ | ✗ | ✗ | D-Bus monitor (bmcweb) |
| `journal-only` | `journal` | ✗ | ✓ | ✓ | FilesystemLogWatcher (bmcweb) |

### SRC_URI

The recipe sources include all source files under `files/`:
- Shell wrappers (`https-guard-daemon.sh`, `https-guard-event-bridge.sh`, `simulated-event-generator.sh`)
- systemd unit files
- Config file (`https-guard.conf`)
- CMake build definition (`CMakeLists.txt`)
- All C++ source and header files under `https_guard/`, `actions/`, `ebpf/`, and `coroutine/`, including the new `BlockTcpAction.hpp` and `BlockTcpAction.cpp`.

---

## Event Flow Summary

### Service / Shell-Script / Binary Mapping

Each systemd unit file (`*.service`) invokes a shell wrapper script installed on the target image. The wrapper in turn may invoke the compiled C++ binary. The table below shows the complete mapping from recipe sources to the installed image paths:

| Recipe source (`.service`) | Install path (executable) | Source script | Binary launched | Role |
|----------------------------|---------------------------|---------------|-----------------|------|
| `https-guard-daemon.service` | `/usr/sbin/https-guard-daemon` | `https-guard-daemon.sh` | `https-guardd` (C++ compiled) | Real-time eBPF event capture, anomaly detection, JSON logging, hybrid enforcement (blocklist + TCP teardown) |
| `https-guard-event-bridge.service` | `/usr/sbin/https-guard-event-bridge` | `https-guard-event-bridge.sh` | — (pure shell) | Tails the event log, dispatches events to D-Bus / journal / Redfish log |
| `simulated-event-generator.service` | `/usr/sbin/simulated-event-generator` | `simulated-event-generator.sh` | — (pure shell) | Generates synthetic events for QEMU / simulation testing |

**Important:** The shell scripts are installed **without** the `.sh` extension. For example, the source file `https-guard-event-bridge.sh` is installed as `/usr/sbin/https-guard-event-bridge` on the target image — the `.sh` suffix is stripped by the recipe's `do_install` step (see `install -m 0755 ${S}/https-guard-event-bridge.sh ${D}${sbindir}/https-guard-event-bridge`).

### Why is the bridge a shell script and not direct C++ code?

The `https-guard-event-bridge.sh` script exists as a separate process **decoupled** from the C++ daemon for several reasons:

1. **Avoid direct D-Bus / sd_journal / filesystem calls from the hot path** — The C++ daemon's `on_event()` callback runs inside the `ring_buffer__poll()` loop. Calling D-Bus (`busctl`/`sd_bus`), `sd_journal_send()`, or appending to `/var/log/redfish` directly from the daemon's event callback would block the ring buffer consumer, risking dropped eBPF events under load. Instead, the daemon dispatches actions to the `ActionLoop` (a background Boost.Asio thread), which writes a single JSON line to a log file asynchronously. The bridge script tails that file as a **separate process**.

2. **Race-condition-free dispatch** — Because the bridge is a separate `tail -F` consumer, multiple event lines are processed one-at-a-time in a single-threaded `while read` loop. This eliminates any need for locks, mutexes, or synchronisation primitives that would be necessary if the C++ daemon dispatched events directly to three different sinks (D-Bus, journal, filesystem) from multiple threads or callback invocations. The shell pipeline acts as a **natural serialisation barrier**: `tail -F` guarantees line-by-line delivery, and the `while read` loop processes each line synchronously.

3. **Fail-fast isolation** — If the D-Bus call (`busctl`) fails (e.g. `xyz.openbmc_project.Logging` is not yet up), it does **not** crash or stall the daemon. The bridge script handles the failure with `|| true` and continues tailing the next line. The daemon's event-capture pipeline is never impacted by downstream dispatch failures.

4. **Flexible sink selection without recompilation** — The event sink mode (`dbus`, `journal`, or `both`) is configured at build time via `PACKAGECONFIG` and stamped into `/etc/default/https-guard`. The bridge script reads this at runtime. Changing the dispatch strategy requires only a recipe rebuild, not C++ code changes. This also makes it easy to add new sinks (e.g. Kafka, syslog) by modifying only the shell script.

### Complete Event Pipeline

```
         Kernel space                              User space
         ===========                              ==========

Wire: TLS ClientHello on TCP/443          Process: SSL_write(buf, num)
  │                                               │
  ▼                                               ▼
eBPF XDP hook                              eBPF Uprobe hook
  │  (blocklist_check → XDP_DROP?)                │  (payload snippet)
  │  (TLS version, SNI, HTTP anomaly)             │
  │                                               │
  └─────────────┬─────────────────────────────────┘
                │  shared `events` ring buffer (BPF_MAP_TYPE_RINGBUF)
                ▼
   ┌──────────────────────────────────────────────────────────┐
   │  C++ daemon: https-guardd                                │
   │  Invoked by: https-guard-daemon.service                  │
   │  Shell wrapper: /usr/sbin/https-guard-daemon             │
   │  Source: https-guard-daemon.sh                           │
   │                                                          │
   │  ┌────────────────────────────────────────────────────┐  │
   │  │ ring_buffer__poll() loop (200ms interval)          │  │
   │  │   → on_event() callback                            │  │
   │  │     → pattern_detector.hpp (inline anomaly rules)  │  │
   │  │     → Classify event + mark actionable             │  │
   │  │     └── pushAction(LogAction)                      │  │
   │  │     └── pushAction(BlocklistAddAction)             │  │
   │  │     └── pushAction(BlockTcpAction)                 │  │
   │  └──────────────────────┬─────────────────────────────┘  │
   │                         │ ActionLoop background thread   │
   │  ┌──────────────────────▼─────────────────────────────┐  │
   │  │ ActionLoop (Boost.Asio io_context)                 │  │
   │  │                                                    │  │
   │  │  ┌─────────────────────────────────────────────┐   │  │
   │  │  │ LogAction::execute_async()                  │   │  │
   │  │  │  → acquire_stream(cfg.output_path)          │   │  │
   │  │  │  → async_write(JSON line + "\n")            │   │  │
   │  │  └─────────────────────────────────────────────┘   │  │
   │  │                                                    │  │
   │  │  ┌─────────────────────────────────────────────┐   │  │
   │  │  │ BlocklistAddAction::execute_async()         │   │  │
   │  │  │  → Blocklist::add(src_ip, ttl)              │   │  │
   │  │  │  → bpf_map_update_elem(blocklist_fd, ...)   │   │  │
   │  │  └─────────────────────────────────────────────┘   │  │
   │  │                                                    │  │
   │  │  ┌─────────────────────────────────────────────┐   │  │
   │  │  │ BlockTcpAction::execute_async()             │   │  │
   │  │  │  → SOCK_DESTROY via NETLINK_INET_DIAG       │   │  │
   │  │  │  → Kernel tears down TCP 4-tuple            │   │  │
   │  │  └─────────────────────────────────────────────┘   │  │
   │  └────────────────────────────────────────────────────┘  │
   └──────────────────────┬───────────────────────────────────┘
                          │  writes JSON lines (async)
                          ▼
                 /var/log/https_guard_events.log
                          │
                          │  tail -n 0 -F (follow)
                          ▼
   ┌──────────────────────────────────────────────────────────┐
   │  Bridge: https-guard-event-bridge                        │
   │  Invoked by: https-guard-event-bridge.service            │
   │  Shell wrapper: /usr/sbin/https-guard-event-bridge       │
   │  Source: https-guard-event-bridge.sh                     │
   │                                                          │
   │  ┌────────────────────────────────────────────────────┐  │
   │  │ while read line; do                                │  │
   │  │   extract_field "MessageId" "$line"                │  │
   │  │   extract_field "Severity"  "$line"                │  │
   │  │   extract_field "Message"   "$line"                │  │
   │  │   extract_field "EventTimestamp" "$line"           │  │
   │  │                                                    │  │
   │  │   case "$MODE" in                                  │  │
   │  │     dbus)                                          │  │
   │  │       busctl call ... Create ...                   │  │
   │  │       ;;                                           │  │
   │  │     journal)                                       │  │
   │  │       systemd-cat -t https-guard-event ...         │  │
   │  │       emit_redfish_log "$ts" "$msg"                │  │
   │  │       ;;                                           │  │
   │  │     both)                                          │  │
   │  │       busctl call ... Create ...                   │  │
   │  │       systemd-cat -t https-guard-event ...         │  │
   │  │       ;;                                           │  │
   │  │   esac                                             │  │
   │  │ done                                               │  │
   │  └────────────────────────────────────────────────────┘  │
   └──────────────────────┬───────────────────────────────────┘
                          │
         ┌────────────────┼────────────────┐
         ▼                ▼                ▼
   ┌──────────┐   ┌──────────────┐   ┌──────────────┐
   │  D-Bus   │   │  journald    │   │ /var/log/    │
   │  Call    │   │  (systemd-   │   │ redfish      │
   │  (busctl)│   │   cat)       │   │ (plain-text  │
   │          │   │              │   │  log)        │
   └────┬─────┘   └──────┬───────┘   └──────┬───────┘
        │                │                  │
        ▼                │                  ▼
   ┌──────────────┐      │   ┌──────────────────────────────┐
   │ bmcweb       │      │   │ bmcweb                       │
   │ D-Bus        │      │   │ FilesystemLogWatcher         │
   │ monitor      │      │   │ (inotify on /var/log/redfish)│
   └──────┬───────┘      │   └──────────────┬───────────────┘
          │              │                  │
          └──────────────┼──────────────────┘
                         ▼
           ┌─────────────────────────┐
           │  Redfish EventService   │
           │  (SSE / HTTPS push)     │
           └─────────────────────────┘
```

### Dispatch modes at a glance

| Mode | D-Bus (`busctl`) | `systemd-cat` | `/var/log/redfish` | EventService Delivery |
|------|:----------------:|:-------------:|:------------------:|:---------------------:|
| `dbus` | ✓ | ✗ | ✗ | D-Bus monitor (bmcweb) |
| `journal` | ✗ | ✓ | ✓ | FilesystemLogWatcher (bmcweb) |
| `both` (default) | ✓ | ✓ | ✗ | D-Bus monitor (bmcweb) |

Notes:
- In `dbus` and `both` modes, the filesystem Redfish log (`/var/log/redfish`) is **not** written to prevent duplicate EventService delivery (bmcweb would pick it up via both D-Bus and inotify).
- In `journal` mode, D-Bus is skipped entirely; delivery relies on bmcweb's `FilesystemLogWatcher` tailing the plain-text log at `/var/log/redfish`.
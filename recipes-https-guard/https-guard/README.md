# Source Code Reference: recipes-https-guard/https-guard/files/

This directory contains the complete source code of the **HTTPS-Guard** agent — an eBPF-based network security observability tool for OpenBMC. It implements a **Detect → Translate → Dispatch** pipeline using kernel-space uprobe (primary) and XDP (auxiliary) programs, a user-space C++ daemon, a shell-based event bridge, and Redfish EventService integration.

> For a top-level project overview, build instructions, and deployment guidance, see the root [`README.md`](../../README.md).

---

## Table of Contents

- [Directory Layout](#directory-layout)
- [eBPF Programs (`https_guard/https_guard.bpf.c`)](#ebpf-programs-https_guardhttps_guardbpfc)
  - [Uprobe Hook: TLS Version Detection & Payload Capture (PRIMARY)](#uprobe-hook-tls-version-detection--payload-capture-primary)
  - [XDP Hook: Wire-Level TLS Inspection (AUXILIARY)](#xdp-hook-wire-level-tls-inspection-auxiliary)
  - [Hybrid Enforcement — XDP Blocklist (XDP_DROP)](#hybrid-enforcement--xdp-blocklist-xdp_drop)
- [Platform Limitations](#platform-limitations)
- [Event Data Model (`https_guard/events.h`)](#event-data-model-https_guardeventsh)
- [C++ Daemon (`https_guard/main.cpp`)](#c-daemon-https_guardmaincpp)
- [Pattern Detector (`https_guard/pattern_detector.hpp`)](#pattern-detector-https_guardpattern_detectorhpp)
- [ProcPeerResolver — PID-to-Socket Correlation (`https_guard/proc_peer_resolver.hpp`)](#procpeerresolver--pid-to-socket-correlation-https_guardproc_peer_resolverhpp)
- [ActionLoop — Async Event Dispatcher (`actions/core/ActionLoop.hpp`)](#actionloop--async-event-dispatcher-actionscoreactionloophpp)
- [LogAction — Async File Writer (`actions/log/LogAction.hpp`)](#logaction--async-file-writer-actionsloglogactionhpp)
- [Blocklist — Source IP Blocklist Manager (`actions/blocklist/Blocklist.hpp`)](#blocklist--source-ip-blocklist-manager-actionsblocklistblocklisthpp)
- [BlocklistAddAction — Countermeasure Action (`actions/blocklist/BlocklistAction.hpp`)](#blocklistaddaction--countermeasure-action-actionsblocklistblocklistactionhpp)
- [BlockTcpAction — TCP Connection Teardown (`actions/tcp/BlockTcpAction.hpp`)](#blocktcpaaction--tcp-connection-teardown-actionstcpblocktcpaactionhpp)
- [Blocklist BPF Header (`actions/blocklist/blocklist.bpf.h`)](#blocklist-bpf-header-actionsblocklistblocklistbpfh)
- [AsyncFileStreamManager — Coroutine-Safe File Writer (`actions/log/async_mutex.hpp`)](#asyncfilestreammanager--coroutine-safe-file-writer-actionslogasync_mutexhpp)
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
├── ebpf/
│   ├── bpf_program.hpp                                # BPF program attachment wrapper
│   └── bpf_program.cpp                                # BPF program wrapper implementation
├── https_guard/
│   ├── events.h                                      # Shared event struct & enums (BPF + C++)
│   ├── https_guard.bpf.c                              # eBPF programs (uprobe primary + XDP auxiliary)
│   ├── https_guard_program.hpp                        # BPF object loader / ring-buffer adapter
│   ├── https_guard_program.cpp                        # BPF lifecycle + event classification + PID->socket
│   ├── main.cpp                                      # C++ daemon entry point
│   ├── pattern_detector.hpp                          # User-space HTTP anomaly rules (inline)
│   ├── proc_peer_resolver.hpp                        # /proc/<pid>/net/tcp parser for PID->socket (inline)
│   ├── redfish_event_message.hpp                     # Redfish Event message with formatting (inline)
│   └── tls_version.hpp                               # TLS version helpers (inline)
├── actions/
│   ├── core/
│   │   ├── ActionLoop.hpp                            # Boost.Asio-based event dispatcher interface
│   │   ├── ActionLoop.cpp                            # Boost.Asio-based event dispatcher implementation
│   │   └── main.cpp                                  # ActionLoop smoke-test / demo entry point
│   ├── blocklist/
│   │   ├── blocklist.bpf.h                           # BPF-side blocklist header (XDP_DROP check)
│   │   ├── Blocklist.hpp                             # Singleton blocklist manager (BPF map wrapper)
│   │   ├── Blocklist.cpp                             # Blocklist singleton implementation
│   │   ├── BlocklistAction.hpp                       # Countermeasure action: add src IP to blocklist
│   │   └── BlocklistAction.cpp                       # BlocklistAddAction implementation
│   ├── tcp/
│   │   ├── BlockTcpAction.hpp                        # Countermeasure action: kill TCP 4-tuple via SOCK_DESTROY
│   │   ├── BlockTcpAction.cpp                        # BlockTcpAction implementation (Netlink async)
│   │   ├── TcpDestroyer.hpp                          # RAII wrapper: Netlink SOCK_DESTROY lifecycle
│   │   └── TcpDestroyer.cpp                          # TcpDestroyer implementation
│   └── log/
│       ├── async_mutex.hpp                           # AsyncFileStreamManager (coroutine-safe file I/O)
│       ├── LogAction.hpp                             # Async file-logging action interface
│       └── LogAction.cpp                             # Async file-logging action implementation
```

---

## eBPF Programs (`https_guard/https_guard.bpf.c`)

The single BPF C file compiles to one BPF object that contains **two independent hook sections**, both writing to the same shared `events` ring buffer map:

| Section | Type | Hook Point | Purpose | Availability |
|---------|------|------------|---------|-------------|
| `SEC("uprobe/ssl_write")` — `https_guard_ssl_write` | Uprobe (PRIMARY) | Userspace function `SSL_write` in OpenSSL | Reads ssl->version for TLS violation detection; captures plaintext payload snippets | All platforms with CONFIG_UPROBE_EVENTS |
| `SEC("xdp")` — `https_guard_xdp` | XDP (AUXILIARY) | Network driver (RX path) or generic SKB mode | Inspects TLS ClientHello on port 443; detects TLS version violations and plaintext HTTP | Native: NICs with ndo_bpf (not ftgmac100). Generic (SKB): any NIC including virtio-net in QEMU TAP+BRIDGE mode |

### Uprobe Hook: TLS Version Detection & Payload Capture (PRIMARY)

**What is hooked:**

- The OpenSSL library function `SSL_write(SSL *ssl, const void *buf, int num)`.

**What is captured:**

- **TLS version** (`ssl->version`) — read from the OpenSSL SSL object using `bpf_probe_read_user()`. The `ssl_st` struct layout in OpenSSL 3.x on ARM 32-bit places `version` at **offset 36** (not offset 0 — the struct has many pointer fields before it). Values:
  - `0x0301` = TLS 1.0
  - `0x0302` = TLS 1.1
  - `0x0303` = TLS 1.2
  - `0x0304` = TLS 1.3
- **Plaintext buffer** (`buf`) — the unencrypted data that the application is about to send.
- **Length** (`num`) — number of bytes of plaintext.
- **Snippet** — up to 127 bytes of the plaintext payload are copied into `evt->payload_snippet`.

**Filters applied:**

- `num <= 0`, `buf == NULL`, or `ssl == NULL` → skip (no event emitted).
- TLS version < 0x0303 → `HG_EVENT_TLS_VERSION_VIOLATION` (severity CRITICAL).
- Otherwise → `HG_EVENT_HTTP_PAYLOAD_OBSERVED` (severity INFO).

**Important note on reading userspace structs:**

The uprobe uses `bpf_probe_read_user()` instead of `bpf_core_read()` because OpenSSL's `ssl_st` is a userspace library struct with no BTF/CO-RE information in `vmlinux.h`. Using `bpf_core_read()` would fail CO-RE relocation at program load time with "invalid CO-RE relocation" / "failed to resolve CO-RE relocation".

The offset of the `version` field within `ssl_st` was empirically determined by scanning offsets 0-80 on the target platform. On ARM 32-bit (johnblue), the version field is at offset 36. On other architectures (e.g. x86_64 where pointers are 8 bytes), the offset will differ. If detection fails on a new platform, enable the `bpf_printk` diagnostic scanning code in the uprobe to locate the correct offset.

### XDP Hook: Wire-Level TLS Inspection (AUXILIARY)

> **IMPORTANT:** XDP comes in two modes:
> - **Native XDP** (driver-level `ndo_bpf`): Requires NIC driver support. The ASpeed
>   AST2600 ftgmac100 driver has zero XDP support — verified by `ip link show eth0`
>   showing no `xdp` or `prog/xdp` line.
> - **Generic XDP / SKB mode** (`XDP_FLAGS_SKB_MODE`): A software fallback that hooks
>   into `netif_receive_skb()`. Works with any NIC, including virtio-net in QEMU
>   TAP+BRIDGE mode.
>
> The daemon now tries **native XDP first**, then falls back to **generic (SKB) XDP**
> automatically. This means XDP works in QEMU TAP+BRIDGE mode with virtio-net-pci.
> On SLIRP (default) or real ftgmac100 hardware, both attempts fail gracefully and
> the daemon continues with uprobe only.
> See [Platform Limitations](#platform-limitations) below.

**What is inspected:**

1. **Ethernet + IP + TCP headers** — filters to IPv4, TCP-only traffic on port 443 (source or destination).
2. **TLS ClientHello record** — identifies packets whose first byte is `0x16` (TLS Handshake ContentType).
3. **TLS version field** — extracted from the ClientHello fixed portion at offset 5+4 (after the record header and handshake header). The version bytes `[major, minor]` are compared against `0x0303` (TLS 1.2):
   - `< 0x0303` → `HG_EVENT_TLS_VERSION_VIOLATION` (severity `CRITICAL`)
   - `>= 0x0303` → `HG_EVENT_TLS_HANDSHAKE_METADATA` (severity `INFO`)
4. **Plaintext HTTP on port 443** — detects unencrypted HTTP method verbs (`GET`, `POST`, `PUT`, `DELETE`, `HEAD`) appearing on the wire.

**Filtering actions:**

- The XDP program calls `blocklist_check(ip->saddr)` before any inspection. If the source IP is in the blocklist, the packet is dropped (`XDP_DROP`).
- For TLS version violations, the XDP program now returns `XDP_DROP` to proactively block the connection.
- All other events are returned as `XDP_PASS`.

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
          │        → BlockTcpAction: SOCK_DESTROY current TCP connection
          └── no  → log only, no blocklist action
```

The blocklist map (`src_blocklist`) is a `BPF_MAP_TYPE_HASH` with a maximum of 1024 entries. Each entry maps a source IP (network byte order) to an absolute expiry timestamp in nanoseconds.

## Platform Limitations

### XDP Support Summary

| Platform | NIC | Native XDP | Generic XDP (SKB mode) | Current Status |
|----------|-----|------------|------------------------|----------------|
| x86 native host (supported NIC) | e.g. ixgbe, mlx5, virtio-net | ✅ Yes | ✅ Yes | ✅ XDP works natively |
| QEMU johnblue TAP+BRIDGE | virtio-net-pci (via `-device virtio-net-pci`) | ✅ Yes | ✅ Yes | ✅ XDP works (generic SKB mode via `bpf_xdp_attach` fallback) |
| QEMU johnblue SLIRP (default) | ftgmac100 (emulated, slirp backend) | ❌ No | ❌ No (slirp has no real netdev) | ❌ XDP not possible |
| Real ASpeed AST2600 HW | ftgmac100 | ❌ No (no ndo_bpf) | ❌ No (ftgmac100 lacks generic XDP support) | ❌ XDP not possible |

### XDP Not Available on ASpeed AST2600 (ftgmac100)

The XDP hook code remains in https_guard.bpf.c for platforms with NIC-level XDP support,
but it does NOT function on the ASpeed AST2600 ftgmac100 NIC (the typical OpenBMC BMC
network controller). This has been verified:

```
root@johnblue:~# ip link show eth0
2: eth0: ... mtu 1500 qdisc pfifo_fast qlen 1000
    link/ether ...
```
(No `xdp` or `prog/xdp` line — XDP is not loaded.)

The daemon handles this correctly by treating XDP as an optional, auxiliary attachment.
If the XDP attach fails, it logs a warning and continues with the uprobe only:

```
https_guard: XDP program not found; running uprobe only
https_guard: enforcement active via uprobe(SSL_write)
```

### Enabling XDP in QEMU (TAP+BRIDGE + virtio-net-pci)

To get XDP working in QEMU, you **must** use TAP+BRIDGE networking with the virtio-net-pci
device. The default SLIRP mode does NOT expose a real NIC to the guest.

The daemon's XDP attach logic in `https_guard_program.cpp` now implements a two-step fallback:
1. Try **native XDP** (`XDP_FLAGS_UPDATE_IF_NOEXIST`) — works on real NICs with ndo_bpf.
2. On failure, try **generic XDP / SKB mode** (`XDP_FLAGS_SKB_MODE`) — works on virtio-net.

This means when you launch QEMU with the TAP+BRIDGE configuration described in
[johnblue.conf](../../conf/machine/johnblue.conf), XDP will attach successfully in
generic SKB mode.

**Verification inside the guest:**
```bash
# Check daemon logs for XDP attach status
journalctl -u https-guard-daemon -l | grep "XDP attached"
# Expected: "https_guard: XDP attached in generic (SKB) mode"

# Verify XDP is loaded on the interface
ip link show eth0 | grep -i xdp
# Expected: "xdp/generic" or "xdp" in the output
```

**Kernel configuration requirement:**
The kernel must have `CONFIG_NET_XDP_XMIT=y` for generic XDP. This is already enabled
by the `bpf-kernel-config.cfg` fragment applied via `linux-aspeed_%.bbappend`. Build
and verify with:
```bash
bitbake virtual/kernel -c menuconfig  # Search for CONFIG_NET_XDP_XMIT
```

### Uprobe-Only Enforcement

When XDP is not available (SLIRP mode or real ftgmac100 hardware), enforcement works
entirely through the uprobe+SOCK_DESTROY path:

Since XDP is not available, TLS security enforcement works as follows:

1. The uprobe on SSL_write() fires when OpenSSL sends encrypted data.
2. The negotiated TLS version is read from ssl->version.
3. An event is submitted to the ring buffer with the process PID.
4. The userspace daemon reads /proc/<pid>/net/tcp to find the TCP socket 4-tuple.
5. SOCK_DESTROY is issued via NETLINK_INET_DIAG to kill the TCP connection.
6. The source IP is logged for follow-up.

### Cannot Test TLS < 1.2 with curl + OpenSSL 3.x

OpenSSL 3.x has removed support for TLS 1.0 and TLS 1.1 at compile time. The
`--tlsv1.0` and `--tlsv1.1` flags are silently ignored — curl always negotiates
TLS 1.3 regardless of the flag. This is visible in curl verbose output:

```
curl -4 --tlsv1.0 -v -ku root:0penBmc https://localhost/redfish/v1
...
* TLSv1.3 (OUT), TLS handshake, Client hello (1):
* SSL connection using TLSv1.3 / TLS_AES_256_GCM_SHA384 / ...
```

The negotiated TLS version read by the uprobe will always be 0x0304 (TLS 1.3)
for all curl connections on this platform.

---

## Event Data Model (`https_guard/events.h`)

The header is dual-purposed: it is included both by the BPF C program (compiled with `clang -target bpf`) and by the C++ daemon. When compiled for BPF, it provides its own minimal integer types; when compiled for C++, it uses `<stdint.h>`.

### Event Types (`enum hg_event_type`)

| Value | Name | Source | Meaning |
|-------|------|--------|---------|
| 1 | `HG_EVENT_TLS_VERSION_VIOLATION` | XDP or Uprobe | Client offered TLS version < 1.2 (could be 1.0 or 1.1) |
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
src_ip_v4    (uint32)    — Source IPv4 address (network byte order) — 0 for uprobe events
dst_ip_v4    (uint32)    — Destination IPv4 address (network byte order) — 0 for uprobe events
src_port     (uint16)    — Source TCP port (host byte order) — 0 for uprobe events
dst_port     (uint16)    — Destination TCP port (host byte order) — 0 for uprobe events
tls_version  (uint16)    — TLS version code (e.g. 0x0301 = 1.0, 0x0304 = 1.3)
tls_record_type (uint16) — TLS record ContentType (reserved for future use)
process      (char[16])  — Comm name of the process (from bpf_get_current_comm)
source_ip    (char[32])  — Dotted-decimal string of source IP (filled by XDP only)
sni          (char[64])  — SNI hostname extracted from TLS ClientHello (XDP only)
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

3. **Load and verify** the BPF object via `libbpf`.

4. **Create `HttpGuardProgram`** — passing the BPF object path, the `ActionLoop` reference, OpenSSL library path, network interface index, a default blocklist TTL of 5 minutes, and the configured output path. The program:
   - Attaches the uprobe to `SSL_write` in the specified OpenSSL shared library (PRIMARY).
   - Tries to attach the XDP program to the network interface (AUXILIARY, non-fatal if it fails).
   - Adopts the blocklist BPF map (`src_blocklist`) so the daemon can populate it with offending source IPs.

5. **Open ring buffer consumer** — `ring_buffer__new()` maps the `events` BPF map and registers the `on_event` callback.

6. **Poll loop** — `ring_buffer__poll()` is called in a 200ms interval loop until SIGINT or SIGTERM is received.

### Event Processing (`ringBufferHandler`)

The callback classifies incoming ring buffer events and dispatches countermeasures:

1. **Size validation** — drops undersized (< `sizeof(hg_event)`) records.
2. **Event type dispatch**:
   - `HG_EVENT_TLS_VERSION_VIOLATION` → critical event, marked actionable.
   - `HG_EVENT_HTTP_PAYLOAD_OBSERVED`, `HG_EVENT_HTTP_ANOMALY_DETECTED`, or `HG_EVENT_TLS_HANDSHAKE_METADATA` → runs pattern detection; if suspicious, marked actionable. Non-suspicious events are logged as informational (not silently dropped).
3. **Enforcement actions**:
   - **LogAction** — always pushed (all events are logged, including non-suspicious ones).
   - **XDP path** (src_ip_v4 != 0): BlockTcpAction + BlocklistAddAction with direct 4-tuple.
   - **Uprobe path** (src_ip_v4 == 0): reads /proc/<pid>/net/tcp via ProcPeerResolver to find socket 4-tuple, then issues BlockTcpAction + BlocklistAddAction.

---

## Pattern Detector (`https_guard/pattern_detector.hpp`)

The user-space anomaly detection engine applies a set of **static signature rules** to plaintext payload snippets.

### Rule Set

| Rule | Description |
|------|-------------|
| `../..` | Directory traversal |
| `union select` | SQL injection |
| `or 1=1` | SQL tautology |
| `drop table` | SQL DDL injection |
| `/etc/passwd` | File inclusion |
| `%2e%2e%2f` | URL-encoded path traversal |
| `cmd.exe` | Windows command execution |
| `wget http` | Remote payload download |

---

## ProcPeerResolver — PID-to-Socket Correlation (`https_guard/proc_peer_resolver.hpp`)

This utility parses `/proc/<pid>/net/tcp` to extract TCP socket 4-tuples from a process PID. It is used by the userspace daemon to correlate uprobe events (which only contain a PID, not socket info) with actual TCP connections, enabling SOCK_DESTROY enforcement.

### Key Methods

| Method | Description |
|--------|-------------|
| `getTcpSockets(pid_t pid)` | Returns vector of `TcpSocketEntry` with src_ip, dst_ip, src_port, dst_port |
| `parseProcNetEntry(field, ip, port)` | Parses hex format "AABBCCDD:PPPP" → IP + port |

### Format

The `/proc/net/tcp` hex format stores IP bytes in reverse order:
- `"0100007F:01BB"` → IP=127.0.0.1, Port=443

---

## ActionLoop — Async Event Dispatcher (`actions/core/ActionLoop.hpp`)

The `ActionLoop` is a singleton that decouples eBPF event callback processing from downstream I/O. It wraps a Boost.Asio `io_context` running on a dedicated background thread.

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
              │
              └── co_spawn BlockTcpAction::execute_async()
                   └── SOCK_DESTROY via NETLINK_INET_DIAG
```

---

## BlockTcpAction — TCP Connection Teardown (`actions/tcp/BlockTcpAction.hpp`)

`BlockTcpAction` kills a specific TCP socket tuple using the kernel's `tcp_drop` facility (`NETLINK_INET_DIAG` + `SOCK_DESTROY`). It targets the **current active connection** by its exact 4-tuple.

### Architecture

| Class | Role |
|-------|------|
| `TcpDestroyer` | RAII wrapper: opens NETLINK_INET_DIAG socket, sends SOCK_DESTROY, closes fd |
| `BlockTcpAction` | IAction adapter that constructs TcpDestroyer and runs it asynchronously |

---

## OpenBMC Recipe (`https-guard-openbmc.bb`)

### SRC_URI

The recipe sources include all source files under `files/`:
- Shell wrappers, systemd unit files, config file
- CMake build definition
- All C++ source and header files under `https_guard/`, `actions/`, and `ebpf/`.

### Build Steps

1. `do_configure[depends]` — depends on `virtual/kernel:do_compile` for vmlinux.
2. `do_configure:prepend` — locates target kernel vmlinux for CO-RE header generation. No libssl BTF header is generated (userspace shared libraries do not have BTF debug info).
3. `do_compile` — CMake build handles both the C++ daemon and (optionally) the BPF object.
4. `do_install` — installs shell wrappers, compiled daemon binary, action_runner, BPF object, systemd units, and config file.

### PACKAGECONFIG Flags

**Service selection:**

| Flag | Daemon | Generator | Bridge |
|------|--------|-----------|--------|
| `simulation` (default) | ✗ | ✓ | ✓ |
| `daemon` | ✓ | ✗ | ✓ |
| `both` | ✓ | ✓ | ✓ |

---

## Event Flow Summary

### Service / Shell-Script / Binary Mapping

| Service | Executable | Binary launched | Role |
|---------|-----------|----------------|------|
| `https-guard-daemon.service` | `/usr/sbin/https-guard-daemon` | `https-guardd` (C++ compiled) | Real-time eBPF event capture, TLS version detection, anomaly classification, PID→socket lookup, SOCK_DESTROY, blocklist enforcement |
| `https-guard-event-bridge.service` | `/usr/sbin/https-guard-event-bridge` | — (pure shell) | Tails the event log, dispatches events to D-Bus / journal / Redfish log |
| `simulated-event-generator.service` | `/usr/sbin/simulated-event-generator` | — (pure shell) | Generates synthetic events for QEMU / simulation testing |

### Complete Event Pipeline

```
         Kernel space                              User space
         ===========                              ==========

Wire: TLS ClientHello on TCP/443          Process: SSL_write(buf, num)
  │                                               │
  ▼                                               ▼
eBPF XDP hook (AUXILIARY)                  eBPF Uprobe hook (PRIMARY)
  │  (NOT on ASpeed ftgmac100)                   │  (ssl->version from OpenSSL)
  │                                              │  (payload snippet)
  │                                              │
  └─────────────┬────────────────────────────────┘
                │  shared `events` ring buffer (BPF_MAP_TYPE_RINGBUF)
                ▼
   ┌───────────────────────────────────────────────────────────┐
   │  C++ daemon: https-guardd                                 │
   │  ┌─────────────────────────────────────────────────────┐  │
   │  │ ring_buffer__poll() loop                            │  │
   │  │   → on_event() callback                             │  │
   │  │     → pattern_detector.hpp (anomaly rules)          │  │
   │  │     → Classify event                                │  │
   │  │     → For uprobe events: ProcPeerResolver(pid)      │  │
   │  │       reads /proc/<pid>/net/tcp → socket 4-tuple    │  │
   │  │     └── pushAction(LogAction)                       │  │
   │  │     └── pushAction(BlockTcpAction)                  │  │
   │  │     └── pushAction(BlocklistAddAction)              │  │
   │  └──────────────────────┬──────────────────────────────┘  │
   │                         │ ActionLoop background thread    │
   │  ┌──────────────────────▼─────────────────────────────┐   │
   │  │ ActionLoop (Boost.Asio io_context)                 │   │
   │  │  ┌─────────────────────────────────────────────┐   │   │
   │  │  │ LogAction → async_write(JSON line)          │   │   │
   │  │  ├─────────────────────────────────────────────┤   │   │
   │  │  │ BlockTcpAction → SOCK_DESTROY via Netlink   │   │   │
   │  │  ├─────────────────────────────────────────────┤   │   │
   │  │  │ BlocklistAddAction → BPF map update         │   │   │
   │  │  └─────────────────────────────────────────────┘   │   │
   │  └────────────────────────────────────────────────────┘   │
   └──────────────────────┬────────────────────────────────────┘
                          │  /var/log/https_guard_events.log
                          ▼
                   Bridge → EventService subscribers
```

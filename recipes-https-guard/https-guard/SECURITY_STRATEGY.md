# Security Strategy: Asynchronous Active Response

This document describes the two fundamental strategies for implementing security enforcement with eBPF, and explains why HTTPS-Guard adopts the **Asynchronous Active Response** approach, with Uprobe as the primary detection path on BMC platforms.

---

## Strategy 1: Synchronous Inline Enforcement ("The Immediate Return")

In a synchronous inline model, the eBPF program itself **decides and enforces** a security policy within the kernel hook, returning a verdict before the operation completes. No event is sent to userspace for the decision path — the decision must be made in nanoseconds.

### How it works

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

### Characteristics

| Aspect | Property |
|--------|----------|
| Decision time | Sub-microsecond (single eBPF instruction) |
| Blocking capability | Yes — `XDP_DROP`, `bpf_override_return`, etc. |
| Policy complexity | Low — limited by eBPF verifier (max instructions, loops, helpers) |
| Userspace involvement | Only at policy pre-load time |
| Use case | DDoS filtering, IP blocklisting, simple allow/deny rules |

### Limitations

- The eBPF verifier restricts program complexity — you cannot run regex, parse deeply nested protocols, or maintain complex state across connections without significant effort.
- Multi-stage attack detection (e.g. "a probe followed by an exploit 5 seconds later") is impractical because the eBPF program must decide on a single packet/event in isolation.
- Map-based policies must be pre-computed; dynamic learning (e.g. "this IP is now suspicious") requires a userspace feedback loop anyway.

---

## Strategy 2: Asynchronous Active Response ("The Fast Action Pipeline")

In an asynchronous model, the eBPF hook **defers** the decision to userspace. It emits an observation event via a ring buffer (or perf buffer) and immediately returns a non-blocking verdict (`XDP_PASS` / `0`). The userspace daemon, running in its own process context, receives the event milliseconds later, classifies it, and executes a countermeasure.

### How it works

```
                            ┌──────────────────────────────────────┐
  eBPF hook                │  eBPF hook                           │
  observes event           │  (Uprobe / XDP)                      │
      │                    │                                      │
      │  cannot decide     │  1. Reserve ring buffer entry        │
      │  (too complex)     │  2. Fill event fields                │
      ▼                    │  3. bpf_ringbuf_submit()             │
  ────┴─────────           │  4. return XDP_PASS / 0              │
  Return PASS              └──────────────────┬───────────────────┘
  immediately                                  │
                                               │  asynchronous
                                               ▼
                            ┌──────────────────────────────────────┐
                            │  Userspace daemon                    │
                            │                                      │
                            │  ring_buffer__poll() loop            │
                            │    → on_event() callback             │
                            │      → pattern_detector (complex     │
                            │        rules, regex, state machine)  │
                            │      → classifier                   │
                            │      → countermeasure:              │
                            │          • SOCK_DESTROY TCP conn    │
                            │          • update eBPF blocklist    │
                            │          • kill process (optional)  │
                            │          • log / alert              │
                            └──────────────────────────────────────┘
```

### Characteristics

| Aspect | Property |
|--------|----------|
| Decision time | Milliseconds (userspace round-trip) |
| Blocking capability | Indirectly — the daemon can terminate TCP connections via SOCK_DESTROY, update eBPF maps to block future events, or send signals to processes |
| Policy complexity | Unlimited — C++ code with full standard library, regex, machine learning, etc. |
| Userspace involvement | Every event is classified by userspace |
| Use case | Intrusion detection, anomaly scoring, multi-vector attack correlation |

### Advantages over synchronous enforcement

1. **Complex threat detection** — Userspace can run full pattern matching (e.g. SQL injection signatures, path traversal), maintain cross-connection state, and correlate events from multiple eBPF hooks (uprobe + XDP in our case).

2. **No eBPF verifier pressure** — The kernel hook is kept minimal; the heavy work is done in C++ where there are no instruction limits or helper restrictions.

3. **Dynamic countermeasures** — The daemon can learn over time: if a source IP triggers multiple anomalies, the daemon can write a block entry into an eBPF map, and future packets from that IP will be dropped **synchronously** by the XDP program (a hybrid approach). The initial detection remains asynchronous.

4. **Fail-safe by default** — If the daemon crashes, the eBPF hook still returns `XDP_PASS` / `0`, so the system continues operating. The kernel path never blocks userspace recovery.

---

## Why HTTPS-Guard uses Strategy 2

### Evidence in the source code

| Location | Evidence |
|----------|----------|
| `https_guard/https_guard.bpf.c:171-220` | Uprobe `SSL_write`: reads ssl->version via `bpf_probe_read_user()`, submits event, returns 0 — always observational |
| `https_guard/https_guard.bpf.c:377-378` | XDP `TLS version violation`: `if (evt_type == HG_EVENT_TLS_VERSION_VIOLATION) return XDP_DROP` — proactive XDP enforcement |
| `https_guard/https_guard.bpf.c:270-271` | `blocklist_check(ip->saddr)` — hybrid enforcement: active blocklist entries trigger `XDP_DROP` before any inspection |
| `actions/blocklist/blocklist.bpf.h:22-36` | `blocklist_check()` inline function — performs `XDP_DROP` for active blocklist entries; prunes expired entries via `bpf_map_delete_elem()` |
| `https_guard/https_guard_program.cpp:36-55` | `https_guard_ssl_write` uprobe attached first (PRIMARY); XDP attached second (optional) |
| `https_guard/https_guard_program.cpp:95` | `"enforcement active via uprobe(SSL_write)"` — logs which enforcement paths are active |
| `https_guard/https_guard_program.cpp:161-224` | Event handler: sends BlockTcpAction + BlocklistAddAction for actionable events |
| `https_guard/https_guard_program.cpp:183-187` | For uprobe events: calls `ProcPeerResolver::getTcpSockets(pid)` to read `/proc/<pid>/net/tcp` |
| `https_guard/https_guard_program.cpp:201-206` | Issues `BlockTcpAction` with resolved socket 4-tuple → SOCK_DESTROY |
| `https_guard/https_guard_program.cpp:210-215` | Issues `BlocklistAddAction` with resolved source IP |
| `https_guard/main.cpp:71` | `kDefaultBlocklistTtl = 5 minutes` — configurable blocklist TTL |
| `actions/blocklist/Blocklist.cpp:46-61` | `Blocklist::add()` — computes expiry and writes via `bpf_map_update_elem()` into the kernel BPF map |
| `actions/tcp/TcpDestroyer.cpp:69-182` | `TcpDestroyer::execute()` — sends `SOCK_DESTROY` via `NETLINK_INET_DIAG` to tear down the exact TCP 4-tuple |
| `actions/tcp/BlockTcpAction.cpp:29-57` | `BlockTcpAction::execute_async()` — constructs `TcpDestroyer` and offloads blocking call via `std::async` |
| `https_guard/proc_peer_resolver.hpp` | Parses `/proc/<pid>/net/tcp` to extract socket 4-tuples for uprobe-originated events |
| `https_guard/pattern_detector.hpp` | Complex string matching (SQL injection, path traversal) — impossible under eBPF verifier limits |
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

**On BMC platforms without XDP (e.g., ASpeed AST2600 ftgmac100):**
- Only the uprobe program loads successfully.
- XDP attachment fails gracefully (logged, non-fatal).
- The daemon runs in uprobe-only mode.
- TLS version violations are detected reactively: the uprobe fires after `SSL_write()`,
  the daemon reads `/proc/<pid>/net/tcp` to find the socket, and issues SOCK_DESTROY
  to kill the TCP connection. The source IP is logged for follow-up.
- This has been verified: `ip link show eth0` shows no `xdp` or `prog/xdp` line.

### How Uprobe-Only Enforcement Works

When the XDP program is not available (as on ASpeed AST2600), the enforcement flow is:

```
Process calls SSL_write(ssl, buf, num)
       │
       ▼
  Uprobe fires on SSL_write
       │
       ├── Reads ssl->version (uint16_t at offset 0 of ssl_st)
       │     using bpf_probe_read_user()
       │
       ├── If version < 0x0303 (TLS 1.2):
       │     → HG_EVENT_TLS_VERSION_VIOLATION
       │     → Severity: CRITICAL
       │
       └── Submits event to ring buffer (with PID only, no socket info)
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
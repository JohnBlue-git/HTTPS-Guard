# Security Strategy: Asynchronous Active Response

This document describes the two fundamental strategies for implementing security enforcement with eBPF, and explains why HTTPS-Guard adopts the **Asynchronous Active Response** approach.

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
  observes event           │  (XDP / uprobe)                      │
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
                           │      → classifier                    │
                           │      → countermeasure:               │
                           │          • update eBPF blocklist map │
                           │          • terminate connection      │
                           │          • log / alert               │
                           └──────────────────────────────────────┘
```

### Characteristics

| Aspect | Property |
|--------|----------|
| Decision time | Milliseconds (userspace round-trip) |
| Blocking capability | Indirectly — the daemon can update eBPF maps to block future matching events, or call out to external tools |
| Policy complexity | Unlimited — C++ code with full standard library, regex, machine learning, etc. |
| Userspace involvement | Every event is classified by userspace |
| Use case | Intrusion detection, anomaly scoring, multi-vector attack correlation |

### Advantages over synchronous enforcement

1. **Complex threat detection** — Userspace can run full pattern matching (e.g. SQL injection signatures, path traversal), maintain cross-connection state, and correlate events from multiple eBPF hooks (XDP + uprobe in our case).

2. **No eBPF verifier pressure** — The kernel hook is kept minimal; the heavy work is done in C++ where there are no instruction limits or helper restrictions.

3. **Dynamic countermeasures** — The daemon can learn over time: if a source IP triggers multiple anomalies, the daemon can write a block entry into an eBPF map, and future packets from that IP will be dropped **synchronously** by the XDP program (a hybrid approach). The initial detection remains asynchronous.

4. **Fail-safe by default** — If the daemon crashes, the eBPF hook still returns `XDP_PASS` / `0`, so the system continues operating. The kernel path never blocks userspace recovery.

---

## Why HTTPS-Guard uses Strategy 2

### Evidence in the source code

| Location | Evidence |
|----------|----------|
| `https_guard/https_guard.bpf.c:334-335` | `blocklist_check(ip->saddr)` — hybrid enforcement: active blocklist entries trigger `XDP_DROP` before any inspection |
| `https_guard/https_guard.bpf.c:428` | `return XDP_PASS;  /* Do not drop – only observe & report. */` — applied only after blocklist check passes |
| `https_guard/https_guard.bpf.c:452-456` | Plaintext HTTP anomaly detection: `bpf_ringbuf_submit()` then `XDP_PASS` — detection without dropping |
| `https_guard/https_guard.bpf.c:386-427` | TLS ClientHello inspection: event is `bpf_ringbuf_submit()`'d, then `XDP_PASS` — detection without dropping |
| `https_guard/https_guard.bpf.c:469-500` | Uprobe `SSL_write`: event is submitted, returns `0` — no override, no block |
| `actions/blocklist.bpf.h:22-36` | `blocklist_check()` inline function — performs `XDP_DROP` for active blocklist entries; prunes expired entries via `bpf_map_delete_elem()` |
| `https_guard/https_guard_program.cpp:48-55` | `Blocklist::instance().adopt()` — daemon adopts the blocklist BPF map fd during program attachment |
| `https_guard/https_guard_program.cpp:118-135` | `pushAction(BlocklistAddAction)` + `pushAction(BlockTcpAction)` — actionable events write the source IP into the blocklist map **and** kill the current TCP 4-tuple |
| `https_guard/main.cpp:71` | `kDefaultBlocklistTtl = 5 minutes` — configurable blocklist TTL |
| `actions/Blocklist.cpp:46-61` | `Blocklist::add()` — computes expiry and writes via `bpf_map_update_elem()` into the kernel BPF map |
| `actions/BlockTcpAction.cpp:55-182` | `BlockTcpAction::execute_async()` — sends `SOCK_DESTROY` via `NETLINK_INET_DIAG` to tear down the exact TCP 4-tuple |
| `https_guard/pattern_detector.hpp` | Complex string matching (SQL injection, path traversal) — impossible under eBPF verifier limits |
| `https-guard-event-bridge.sh` | Full shell-level dispatch to D-Bus, journal, or filesystem — decisions made entirely in userspace |

### The pipeline is hybrid — asynchronous detection with synchronous enforcement

HTTPS-Guard's eBPF programs implement a **two-tier** strategy:

**Tier 1 — Synchronous enforcement (Strategy 1):** Before any packet inspection, the XDP hook calls `blocklist_check(ip->saddr)` which queries the shared BPF blocklist map. If the source IP has a non-expired entry, the packet is immediately dropped (`XDP_DROP`) with zero userspace round-trip. Expired entries are deleted opportunistically within the same BPF helper.

**Tier 2 — Asynchronous detection (Strategy 2):** If the packet is not blocklisted, the XDP program proceeds with TLS ClientHello and HTTP anomaly inspection. Events are submitted via `bpf_ringbuf_submit()` and the hook returns `XDP_PASS`. The uprobe hook on `SSL_write` always returns `0` (pass).

```
Packet arrives on port 443
       │
       ▼
  ┌────────────────────────────────┐
  │ Tier 1: blocklist_check()      │  ← Synchronous enforcement
  │  ├── IP active  → XDP_DROP     │
  │  ├── IP expired → delete, PASS │
  │  └── IP absent  → XDP_PASS     │
  └──────────┬─────────────────────┘
             │ (if PASS)
             ▼
  ┌────────────────────────────────┐
  │ Tier 2: TLS / HTTP inspection  │  ← Asynchronous detection
  │  ├── ClientHello → ring buffer │
  │  ├── HTTP anomaly → ring buf   │
  │  └── XDP_PASS (always)         │
  └──────────┬─────────────────────┘
             │
             ▼
  ┌────────────────────────────────┐
  │ Userspace daemon               │
  │  → classify event              │
  │  → if actionable:              │
  │    → BlocklistAddAction(src_ip)│
  │    → writes expiry into BPF map│  ← Feeds Tier 1
  └────────────────────────────────┘
```

All classification (severity assignment, anomaly rule matching, message formatting) happens in userspace C++ code (`main.cpp` → `https_guard_program.cpp` → inline headers `pattern_detector.hpp` and `redfish_event_message.hpp`). The dispatch to Redfish EventService is deferred further to a separate shell bridge process (`https-guard-event-bridge.sh`).

### Hybrid Extension — Implemented (Two-Action Response)

The architecture now implements a **fully operational** hybrid extension with **two simultaneous countermeasures**:

```
  ┌──────────────────────────────────┐
  │  Daemon detects attack           │
  │  (TLS version violation or       │
  │   confirmed attack signature)    │
  │  from IP 10.0.0.5                │
  │                                  │
  │  → BlocklistAddAction(10.0.0.5,  │
  │      5min, reason)               │
  │  → Blocklist::add() writes       │
  │    expiry into BPF map           │
  │                                  │
  │  → BlockTcpAction(10.0.0.5,      │
  │      dst_ip, port, dst_port,     │
  │      reason)                     │
  │  → SOCK_DESTROY via              │
  │    NETLINK_INET_DIAG             │
  └──────┬────────────┬──────────────┘
         │            │
         ▼            ▼
  ┌────────────┐  ┌──────────────────────┐
  │ Next pkt   │  │ Current TCP conn     │
  │ from IP    │  │ matching 4-tuple     │
  │ 10.0.0.5   │  │ is torn down by      │
  │            │  │ kernel (SOCK_DESTROY)│
  │ XDP hook   │  │ Process gets         │
  │ calls      │  │ EPIPE/ECONNRESET     │
  │ blocklist  │  │ on next I/O          │
  │ _check()   │  └──────────────────────┘
  │            │
  │ → active   │
  │   entry    │
  │ → XDP_DROP │
  └────────────┘
```

The initial detection is asynchronous (Strategy 2), but the follow-up enforcement is synchronous (Strategy 1). The eBPF map (`src_blocklist`, a `BPF_MAP_TYPE_HASH`) serves as the bridge between the two strategies. This pattern — **"detect in userspace, enforce in kernel"** — is widely used in production systems like Cilium and Falco.

**Key implementation details:**

| Component | File | Role |
|-----------|------|------|
| BPF blocklist map | `actions/blocklist.bpf.h` | `BPF_MAP_TYPE_HASH` storing `src_ip → expiry_ns`; max 1024 entries |
| BPF `blocklist_check()` | `actions/blocklist.bpf.h:22-36` | Inline helper returning `XDP_DROP` for active entries, pruning expired ones |
| XDP hook integration | `https_guard/https_guard.bpf.c:334-335` | Calls `blocklist_check(ip->saddr)` as first processing step |
| Userspace Blocklist singleton | `actions/Blocklist.hpp`, `actions/Blocklist.cpp` | Wraps BPF map fd; provides `add()`, `contains()`, `adopt()`, `formatIp()` |
| Countermeasure action (blocklist) | `actions/BlocklistAction.hpp`, `actions/BlocklistAction.cpp` | `IAction` implementation that calls `Blocklist::add()` |
| Countermeasure action (TCP teardown) | `actions/BlockTcpAction.hpp`, `actions/BlockTcpAction.cpp` | `IAction` implementation that sends `SOCK_DESTROY` via `NETLINK_INET_DIAG` |
| Action dispatch | `https_guard/https_guard_program.cpp:64-145` | `ringBufferHandler()` classifies events as actionable and pushes both `BlocklistAddAction` and `BlockTcpAction` |
| Default TTL | `https_guard/main.cpp:18` | `kDefaultBlocklistTtl = 5 minutes` |

### Summary

| | Synchronous (Strategy 1) | Asynchronous (Strategy 2) |
|---|---|---|
| **Decision location** | eBPF kernel hook | Userspace daemon |
| **Latency to action** | Microseconds | Milliseconds |
| **Policy complexity** | Limited (verifier) | Unlimited (C++/Python/Go) |
| **HTTPS-Guard choice** | ✅ (blocklist enforcement) | ✅ (primary detection pipeline) |
| **Extension** | Blocklist map populated by daemon after event classification | Main detection + classification + dispatch |

---

*HTTPS-Guard implements a hybrid security model: asynchronous anomaly detection with synchronous blocklist enforcement. The eBPF programs observe and report TLS handshake metadata and HTTP anomalies (returning `XDP_PASS`), but also enforce active blocklist entries by dropping packets at the XDP layer (`XDP_DROP`). The userspace daemon classifies events, and for actionable threats (TLS version violations, confirmed attack signatures), writes the source IP into the BPF blocklist map with a configurable TTL (default: 5 minutes). This creates a closed-loop detection-to-enforcement pipeline without requiring any structural changes to the architecture.*

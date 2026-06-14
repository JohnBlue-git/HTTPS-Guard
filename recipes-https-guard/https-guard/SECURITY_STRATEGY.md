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
| `https_guard/https_guard.bpf.c:377` | `return XDP_PASS;  /* Do not drop – only observe & report. */` |
| `https_guard/https_guard.bpf.c:405` | `return XDP_PASS;` — even HTTP anomalies are not dropped at the XDP layer |
| `https_guard/https_guard.bpf.c:337-376` | TLS ClientHello inspection: event is `bpf_ringbuf_submit()`'d, then `XDP_PASS` |
| `https_guard/https_guard.bpf.c:429-448` | Uprobe `SSL_write`: event is submitted, returns `0` — no override, no block |
| `https_guard/main.cpp:196-201` | `ring_buffer__poll()` loop — the daemon consumes events **after** the kernel has already returned |
| `https_guard/pattern_detector.hpp` | Complex string matching (SQL injection, path traversal) — impossible under eBPF verifier limits |
| `https-guard-event-bridge.sh` | Full shell-level dispatch to D-Bus, journal, or filesystem — decisions made entirely in userspace |

### The pipeline is purely observational

HTTPS-Guard's eBPF programs **never** block, drop, or modify packets. Every hook:

1. Reserves a ring buffer entry
2. Fills in event data (TLS version, SNI, process info, payload snippet)
3. Submits the event via `bpf_ringbuf_submit()`
4. Returns `XDP_PASS` (XDP) or `0` (uprobe)

All classification (severity assignment, anomaly rule matching, message formatting) happens in userspace C++ code (`main.cpp` → inline headers `pattern_detector.hpp` and `redfish_event_message.hpp`). Even the dispatch to Redfish EventService is deferred further to a separate shell bridge process (`https-guard-event-bridge.sh`).

### Future hybrid extension

The architecture **supports** a hybrid extension without structural changes:

```
  ┌──────────────────────────────────┐
  │  Daemon detects repeated attacks │
  │  from IP 10.0.0.5                │
  │                                  │
  │  → writes IP 10.0.0.5 to         │
  │    eBPF "blocklist" map          │
  └──────────────┬───────────────────┘
                 │
                 ▼
  ┌──────────────────────────────────┐
  │  Next packet from 10.0.0.5       │
  │                                  │
  │  XDP hook queries blocklist map  │
  │  → match → XDP_DROP              │
  └──────────────────────────────────┘
```

The initial detection remains asynchronous (Strategy 2), but the follow-up enforcement becomes synchronous (Strategy 1). The eBPF map serves as the bridge between the two strategies. This pattern is commonly referred to as **"detect in userspace, enforce in kernel"** and is widely used in production systems like Cilium and Falco.

### Summary

| | Synchronous (Strategy 1) | Asynchronous (Strategy 2) |
|---|---|---|
| **Decision location** | eBPF kernel hook | Userspace daemon |
| **Latency to action** | Microseconds | Milliseconds |
| **Policy complexity** | Limited (verifier) | Unlimited (C++/Python/Go) |
| **HTTPS-Guard choice** | ❌ | ✅ |
| **Future extension** | Could add eBPF blocklist maps for repeat offenders | Primary detection pipeline |

---

*HTTPS-Guard is designed as a pure observational security agent. It detects and reports anomalies but does not currently enforce any inline blocking. The `XDP_DROP` path, eBPF blocklist maps, and automated countermeasures are reserved for a future iteration.*

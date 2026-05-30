# HTTPS-Guard Architecture

## Mission

HTTPS-Guard delivers a Detect -> Deny -> Dispatch pipeline:

1. Detect and deny in kernel space with eBPF.
2. Translate and enrich anomalies in user space.
3. Dispatch events as Redfish EventService-compatible payloads.

## Data Flow

```mermaid
flowchart TD
    A[Intrusive HTTPS Request] --> B[eBPF XDP/uprobes]
    B -->|XDP_DROP| C[Deny in kernel]
    B -->|ring buffer metadata| D[C++ daemon]
    D --> E[Redfish event JSON]
    E --> F[/var/log/redfish/https_guard_events.log]
    F --> G[Redfish EventService watcher]
    G --> H[HTTPS push to subscribers]
```

## Components

- ebpf/https_guard.bpf.c
  - XDP path: drops TLS 1.0/1.1 ClientHello (hard deny).
  - Uprobe path: inspects SSL_write plaintext snippets for suspicious patterns.
  - Emits normalized hg_event records to ring buffer map events.

- src/main.cpp
  - Loads BPF object and reads ring buffer events.
  - Applies user-space anomaly rules for HTTP payloads.
  - Formats Redfish-compatible JSON and appends to output log path.

- config/security_message_registry/OemSecurityEvent.1.0.0.json
  - OEM registry with strongly typed message IDs and argument schema.

## Why this design

- eBPF keeps enforcement at line-rate and close to the attack surface.
- User-space daemon keeps policy updates and payload shaping flexible.
- Redfish integration leverages existing BMC EventService fan-out instead of building a custom notification stack.

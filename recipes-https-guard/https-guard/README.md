# Source Code Reference: recipes-https-guard/https-guard/files/

This directory contains the complete source code of the **HTTPS-Guard** agent — an eBPF-based network security observability tool for OpenBMC. It implements a **Detect → Translate → Dispatch** pipeline using kernel-space XDP/uprobe programs, a user-space C++ daemon, a shell-based event bridge, and Redfish EventService integration.

> For a top-level project overview, build instructions, and deployment guidance, see the root [`README.md`](../../README.md).

---

## Table of Contents

- [Directory Layout](#directory-layout)
- [eBPF Programs (`https_guard/https_guard.bpf.c`)](#ebpf-programs-https_guardhttps_guardbpfc)
  - [XDP Hook: Wire-Level TLS Inspection](#xdp-hook-wire-level-tls-inspection)
  - [Uprobe Hook: Plaintext Payload Capture](#uprobe-hook-plaintext-payload-capture)
- [Event Data Model (`https_guard/events.h`)](#event-data-model-https_guardeventsh)
- [C++ Daemon (`https_guard/main.cpp`)](#c-daemon-https_guardmaincpp)
- [Pattern Detector (`https_guard/pattern_detector.hpp`)](#pattern-detector-https_guardpattern_detectorhpp)
- [Redfish Formatter (`https_guard/redfish_formatter.hpp`)](#redfish-formatter-https_guardredfish_formatterhpp)
- [String Utilities (`https_guard/string_utils.hpp`)](#string-utilities-https_guardstring_utilshpp)
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
│   ├── https_guard.bpf.c                              # eBPF programs (XDP + uprobe)
│   ├── https_guard_program.hpp                        # BPF object loader / ring-buffer adapter
│   ├── https_guard_program.cpp                        # BPF lifecycle implementation
│   ├── main.cpp                                      # C++ daemon entry point
│   ├── pattern_detector.hpp                          # User-space HTTP anomaly rules (inline)
│   ├── redfish_formatter.hpp                         # Redfish Event JSON serialization (inline)
│   └── string_utils.hpp                              # TLS version helpers (inline)
├── actions/
│   ├── main.cpp                                      # ActionLoop smoke-test / demo entry point
│   ├── ActionLoop.hpp                                # Boost.Asio-based event dispatcher interface
│   ├── ActionLoop.cpp                                # Boost.Asio-based event dispatcher implementation
│   ├── LogAction.hpp                                 # Event logging action interface
│   └── LogAction.cpp                                 # Event logging action implementation
```

---

## eBPF Programs (`https_guard/https_guard.bpf.c`)

The single BPF C file compiles to one BPF object that contains **two independent hook sections**, both writing to the same shared `events` ring buffer map:

| Section | Type | Hook Point | Purpose |
|---------|------|------------|---------|
| `SEC("xdp")` — `https_guard_xdp` | XDP | Network driver (RX path) | Inspects TLS ClientHello on port 443; detects TLS version violations and plaintext HTTP on the HTTPS port |
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

- The XDP program **observes and reports** (`XDP_PASS`) — it does **not** currently drop packets in production. The `XDP_DROP` action was considered during design but the current implementation uses `XDP_PASS` for all packets. Events are emitted to the ring buffer for the user-space daemon to decide on further action.
- TLS version violations are flagged via events, but the actual blocking is intended to be enforced by the daemon or downstream (e.g., by terminating the connection or updating firewall rules).

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

The daemon's `main()` function orchestrates the full eBPF lifecycle:

### Initialization Flow

1. **Parse CLI arguments** (4 positional):
   - `argv[1]` — Network interface (default: `eth0`).
   - `argv[2]` — OpenSSL shared library path (default: `/usr/lib/x86_64-linux-gnu/libssl.so.3`).
   - `argv[3]` — Output log path (default: `/var/log/redfish/https_guard_events.log`).
   - `argv[4]` — BPF object file path (default: `./build/https_guard.bpf.o`).

2. **Load and verify** the BPF object via `libbpf`:
   - `bpf_object__open_file()` — parses the ELF BPF object.
   - `bpf_object__load()` — loads programs into the kernel and creates maps.

3. **Attach programs**:
   - XDP program `https_guard_xdp` → `bpf_program__attach_xdp()` on the specified interface.
   - Uprobe program `https_guard_ssl_write` → `bpf_program__attach_uprobe()` on `SSL_write` from the specified OpenSSL shared library.
  - `HttpGuardProgram` owns the loaded BPF object and forwards ring-buffer events into `ActionLoop`.

4. **Open ring buffer consumer** — `ring_buffer__new()` maps the `events` BPF map and registers the `on_event` callback.

5. **Poll loop** — `ring_buffer__poll()` is called in a 200ms interval loop until SIGINT or SIGTERM is received.

### Event Processing (`on_event` callback)

The callback classifies incoming ring buffer events:

1. **Size validation** — drops undersized (< `sizeof(hg_event)`) records.
2. **Event type dispatch**:
   - `HG_EVENT_TLS_VERSION_VIOLATION` →
     - Sets severity to `"Critical"`.
     - Uses message ID `OemSecurityEvent.1.0.0.HttpsTlsVersionViolation`.
     - Composes a human-readable message including process name, PID, and TLS version string.
   - `HG_EVENT_HTTP_PAYLOAD_OBSERVED` or `HG_EVENT_HTTP_ANOMALY_DETECTED` →
     - Runs user-space anomaly detection via `is_http_payload_suspicious()`.
     - If the payload matches a rule (or was already flagged by the kernel as an anomaly), the event is promoted to `"Warning"`.
     - Uses message ID `OemSecurityEvent.1.0.0.HttpsPayloadAnomalyDetected`.
     - Includes the matched rule name in the message.
   - All other event types are silently dropped.

3. **Formatter** — calls `format_redfish_event()` to produce a JSON line.
4. **Log** — appends the JSON line to the output path and prints to stdout.

### Cleanup

On signal, the poll loop exits, the ring buffer is freed, BPF links are destroyed, and the BPF object is closed.

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

## Redfish Formatter (`https_guard/redfish_formatter.hpp`)

Converts an `hg_event` + classification result into a Redfish Event JSON line using the [nlohmann/json](https://github.com/nlohmann/json) library for safe, standards-compliant serialization. The library handles all string escaping and UTF-8 encoding automatically. The implementation is **inline** in the header, so no separate `.cpp` file is needed.

### Output Format

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
| `Severity` | `"OK"`, `"Warning"`, or `"Critical"` (mapped from hg_severity) |
| `MessageId` | `OemSecurityEvent.1.0.0.HttpsTlsVersionViolation` or `OemSecurityEvent.1.0.0.HttpsPayloadAnomalyDetected` |
| `Message` | Human-readable string containing process, PID, TLS version, or matched rule |
| `EventTimestamp` | Current UTC time in ISO 8601 format (`YYYY-MM-DDTHH:MM:SSZ`) |

---

## String Utilities (`https_guard/string_utils.hpp`)

### `tls_version_to_string()`

Maps TLS version codes to human-readable names (defined inline in the header):

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
- **Target**: `https_guardd` — compiles `https_guard/main.cpp`, `https_guard/https_guard_program.cpp`, `actions/ActionLoop.cpp`, `actions/LogAction.cpp`, and `ebpf/bpf_program.cpp`.
- **Secondary target**: `action_runner` — compiles `actions/main.cpp` plus `actions/ActionLoop.cpp` for exercising the dispatcher loop in isolation.
- **Include paths**: `https_guard/`, `actions/`, `ebpf/`, libbpf headers, nlohmann_json headers, and Boost headers.
- **Libraries**: `libbpf` + `nlohmann_json::nlohmann_json`.

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

1. `do_compile:append` — attempts to cross-compile `https_guard.bpf.c` using clang (from `clang-native`).
2. `do_install` — installs shell wrappers, the compiled daemon binary, the BPF object, systemd unit files, and the processed config file.

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

---

## Event Flow Summary

### Service / Shell-Script / Binary Mapping

Each systemd unit file (`*.service`) invokes a shell wrapper script installed on the target image. The wrapper in turn may invoke the compiled C++ binary. The table below shows the complete mapping from recipe sources to the installed image paths:

| Recipe source (`.service`) | Install path (executable) | Source script | Binary launched | Role |
|----------------------------|---------------------------|---------------|-----------------|------|
| `https-guard-daemon.service` | `/usr/sbin/https-guard-daemon` | `https-guard-daemon.sh` | `https-guardd` (C++ compiled) | Real-time eBPF event capture, anomaly detection, JSON logging |
| `https-guard-event-bridge.service` | `/usr/sbin/https-guard-event-bridge` | `https-guard-event-bridge.sh` | — (pure shell) | Tails the event log, dispatches events to D-Bus / journal / Redfish log |
| `simulated-event-generator.service` | `/usr/sbin/simulated-event-generator` | `simulated-event-generator.sh` | — (pure shell) | Generates synthetic events for QEMU / simulation testing |

**Important:** The shell scripts are installed **without** the `.sh` extension. For example, the source file `https-guard-event-bridge.sh` is installed as `/usr/sbin/https-guard-event-bridge` on the target image — the `.sh` suffix is stripped by the recipe's `do_install` step (see `install -m 0755 ${S}/https-guard-event-bridge.sh ${D}${sbindir}/https-guard-event-bridge`).

### Why is the bridge a shell script and not direct C++ code?

The `https-guard-event-bridge.sh` script exists as a separate process **decoupled** from the C++ daemon for several reasons:

1. **Avoid direct D-Bus / sd_journal / filesystem calls from the hot path** — The C++ daemon's `on_event()` callback runs inside the `ring_buffer__poll()` loop. Calling D-Bus (`busctl`/`sd_bus`), `sd_journal_send()`, or appending to `/var/log/redfish` directly from the daemon's event callback would block the ring buffer consumer, risking dropped eBPF events under load. Instead, the daemon writes a single JSON line to a log file (a fast, non-blocking `fstream::operator<<`), and the bridge script tails that file as a **separate process**.

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
  │  (TLS version, SNI, HTTP anomaly)             │  (payload snippet)
  │                                               │
  └─────────────┬───────────────────────────────┘
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
   │  │     → redfish_formatter.hpp (inline JSON)          │  │
   │  │     → append_line() to log file                    │  │
   │  └────────────────────────────────────────────────────┘  │
   └──────────────────────┬───────────────────────────────────┘
                          │  writes JSON lines
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
   │  │       busctl call ... Create ...            ───┐   │  │
   │  │     journal)                                     │   │  │
   │  │       systemd-cat -t https-guard-event ...       │   │  │
   │  │       emit_redfish_log "$ts" "$msg"       ───────┤   │  │
   │  │     both)                                         │   │  │
   │  │       busctl call ... Create ...            ─────┤   │  │
   │  │       systemd-cat -t https-guard-event ...       │   │  │
   │  │   esac                                            │   │  │
   │  │ done                                              │   │  │
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
   ┌──────────────┐      │   ┌─────────────────────────────┐
   │ bmcweb       │      │   │ bmcweb                       │
   │ D-Bus        │      │   │ FilesystemLogWatcher         │
   │ monitor      │      │   │ (inotify on /var/log/redfish)│
   └──────┬───────┘      │   └──────────────┬──────────────┘
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
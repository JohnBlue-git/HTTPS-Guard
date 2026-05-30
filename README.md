# HTTPS-Guard

HTTPS-Guard is a Network Security Observability Agent that implements a Detect -> Deny -> Dispatch security pipeline:

- Detect and deny in kernel space with eBPF.
- Translate and classify in user space with a C++ daemon.
- Dispatch as Redfish Event payloads for EventService subscribers.

## What is implemented in this repository

- eBPF XDP program:
	- inspects TLS ClientHello on port 443.
	- drops TLS 1.0 and TLS 1.1 attempts immediately with XDP_DROP.
	- emits telemetry to a ring buffer map.

- eBPF uprobe program:
	- hooks OpenSSL SSL_write.
	- captures plaintext snippets before encryption.
	- emits payload-observed and anomaly-detected events.

- C++ daemon:
	- loads and attaches BPF programs.
	- consumes ring buffer events.
	- applies HTTP payload anomaly pattern checks.
	- writes Redfish Event JSON lines to /var/log/redfish/https_guard_events.log.

- Redfish assets:
	- OEM message registry in config/security_message_registry/OemSecurityEvent.1.0.0.json.
	- event example payload in config/redfish_event_example.json.

## Architecture

```mermaid
flowchart TD
		A[Intrusive HTTPS Request] --> B[eBPF XDP and uprobe layer]
		B --> C[XDP_DROP for severe TLS policy violation]
		B --> D[Ring buffer event stream]
		D --> E[C++ HTTPS-Guard daemon]
		E --> F[Redfish Event JSON line]
		F --> G[/var/log/redfish/https_guard_events.log]
		G --> H[Redfish EventService watcher]
		H --> I[HTTPS push to subscribed clients]
```

## Repository layout

- ebpf/https_guard.bpf.c: Kernel-space detection and deny logic.
- include/https_guard/events.h: Shared event schema.
- src/main.cpp: Daemon runtime and BPF attachment.
- src/pattern_detector.cpp: Request anomaly signature checks.
- src/redfish_formatter.cpp: Redfish event payload generation.
- config/security_message_registry/OemSecurityEvent.1.0.0.json: OEM message registry.
- docs/architecture.md: Design and data flow details.

## Prerequisites

- Linux kernel with eBPF/XDP support.
- clang/llvm, cmake, pkg-config.
- libbpf development package.
- root privileges to attach XDP and uprobes.

Ubuntu example dependencies:

```bash
sudo apt-get update
sudo apt-get install -y clang llvm cmake pkg-config libbpf-dev linux-headers-$(uname -r)
```

## Build

Build BPF object:

```bash
chmod +x scripts/build_ebpf.sh
./scripts/build_ebpf.sh
```

Build daemon:

```bash
cmake -S . -B build
cmake --build build -j
```

## Run

Usage:

```bash
sudo ./build/https_guardd <network_interface> <openssl_lib_path> <output_log_path>
```

Example:

```bash
sudo ./build/https_guardd eth0 /usr/lib/x86_64-linux-gnu/libssl.so.3 /var/log/redfish/https_guard_events.log
```

The daemon writes one Redfish Event JSON record per line. This file path is intentionally chosen so an EventService log watcher can ingest and dispatch asynchronously to subscribers.

## Notes on production hardening

- Replace static signatures with configurable rule packs.
- Add JA3/JA4 fingerprint generation in user space.
- Integrate with journald and OpenBMC dbus log pipelines.
- Add unit tests for detector and payload formatter.
- Add integration tests with replayed PCAP and synthetic SSL_write traffic.

## OpenBMC QEMU Integration (simple path)

This repository now includes a ready-to-use OpenBMC layer for QEMU simulation:

- openbmc/meta-https-guard
- scripts/openbmc_qemu_setup.sh
- docs/openbmc-qemu-integration.md

What it gives you quickly:

- repo init + repo sync bootstrap on a stable branch (default scarthgap)
- layer injection and image package append
- two runtime services in QEMU image
	- HTTPS-Guard signal generator (simulated eBPF signal source)
	- HTTPS-Guard event bridge (DBus signal + Journal emission)

Run:

```bash
chmod +x scripts/openbmc_qemu_setup.sh
scripts/openbmc_qemu_setup.sh ~/openbmc
```

Then boot QEMU and verify:

```bash
cd ~/openbmc/build/qemuarm
runqemu nographic slirp
systemctl status https-guard-event-generator.service
systemctl status https-guard-event-bridge.service
```

For detailed steps, see docs/openbmc-qemu-integration.md.

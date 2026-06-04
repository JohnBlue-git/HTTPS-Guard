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

### Mission

HTTPS-Guard delivers a Detect -> Deny -> Dispatch pipeline:

1. Detect and deny in kernel space with eBPF.
2. Translate and enrich anomalies in user space.
3. Dispatch events as Redfish EventService-compatible payloads.

### Why this design

- eBPF keeps enforcement at line-rate and close to the attack surface.
- User-space daemon keeps policy updates and payload shaping flexible.
- Redfish integration leverages existing BMC EventService fan-out instead of building a custom notification stack.

### Data Flow

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

### Repository layout

- `conf/`: Yocto layer configuration for HTTPS-Guard.
- `manifest/`: repo manifest for syncing OpenBMC and HTTPS-Guard.
- `recipes-https-guard/https-guard/`: HTTPS-Guard OpenBMC recipe and deployment files.
- `recipes-bmcweb/bmcweb/`: bmcweb package append for OpenBMC integration.
- `recipes-phosphor/images/`: image append to install HTTPS-Guard into `obmc-phosphor-image`.
- `docs/architecture.md`: Design and data flow details.

### Recipe recipes-https-guard Components

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

## Build

Prerequisites

- Linux kernel with eBPF/XDP support.
- clang/llvm, cmake, pkg-config.
- libbpf development package.
- root privileges to attach XDP and uprobes.

Ubuntu example dependencies:

```bash
sudo apt-get update
sudo apt-get install -y clang llvm cmake pkg-config libbpf-dev linux-headers-$(uname -r)
```

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

## OpenBMC Build

This repository includes a ready-to-use OpenBMC manifest and Yocto layer (`meta-https-guard`) that integrates HTTPS-Guard into an OpenBMC image.

> **Note:** Adding `meta-https-guard` to the build is handled automatically by
> `meta-https-guard/conf/templates/default/bblayers.conf.sample`, which is picked up
> by the `setup` script when you initialise the build environment. No manual
> `BBLAYERS` edits are needed.

### Setup and build

1. Create and enter a working directory:

```bash
mkdir <work_dir>
cd <work_dir>
```

2. Initialise the repo manifest:

```bash
repo init -u https://github.com/JohnBlue-git/HTTPS-Guard.git -m manifest/main.xml
```

3. Sync all repositories (replace `<cpucore>` with your CPU thread count, e.g. `$(nproc)`):

```bash
repo sync -j$(nproc)
```

4. Create a tracking branch across all projects:

```bash
repo start master --all
```

5. Set up the OpenBMC build environment:

```bash
. setup johnblue
```

6. Build the image:

```bash
# build image
bitbake obmc-phosphor-image

# run qemu
runqemu johnblue slirp nographic
```

### Verify services (QEMU or real hardware)

```bash
systemctl status https-guard-event-generator.service
journalctl -u https-guard-event-generator -f

systemctl status https-guard-event-bridge.service
journalctl -u https-guard-event-bridge -f
```

### Validate logging and Redfish

```bash
busctl tree xyz.openbmc_project.Logging

curl -k https://<bmc-ip>/redfish/v1/EventService
curl -k https://<bmc-ip>/redfish/v1/EventService/Subscriptions
```

Create a Redfish HTTPS push subscription:

```bash
curl -k -X POST https://<bmc-ip>/redfish/v1/EventService/Subscriptions \
	-H "Content-Type: application/json" \
	-d '{
		"Destination": "https://<listener-ip>:8443/events",
		"Protocol": "Redfish",
		"SubscriptionType": "RedfishEvent",
		"Context": "https-guard-demo"
	}'
```

Listen to Redfish events over Server-Sent Events (SSE):

```bash
curl -k -N \
	-H "Accept: text/event-stream" \
	https://<bmc-ip>/redfish/v1/EventService/SSE
```

If BMC authentication is enabled, add `-u <user>:<password>` to the `curl` commands above. Use the HTTPS push subscription when you want the BMC to POST events to another service. Use SSE when you want to watch the event stream directly from a terminal without creating a subscription destination.

For architecture and data-flow details, see `docs/architecture.md`.

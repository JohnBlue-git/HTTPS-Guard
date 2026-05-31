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

- `conf/`: Yocto layer configuration for HTTPS-Guard.
- `manifest/`: repo manifest for syncing OpenBMC and HTTPS-Guard.
- `recipes-https-guard/https-guard/`: HTTPS-Guard OpenBMC recipe and deployment files.
- `recipes-bmcweb/bmcweb/`: bmcweb package append for OpenBMC integration.
- `recipes-phosphor/images/`: image append to install HTTPS-Guard into `obmc-phosphor-image`.
- `docs/architecture.md`: Design and data flow details.

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

## OpenBMC QEMU Integration

This repository now includes a ready-to-use OpenBMC manifest and Yocto layer for QEMU simulation.

### Configure OpenBMC build

1. Create and enter the OpenBMC working directory:

```bash
mkdir -p ~/openbmc
cd ~/openbmc
```

2. Initialize repo using the local manifest:

```bash
repo init -u /path/to/HTTPS-Guard/manifest/main.xml
```

3. Sync the repositories:

```bash
repo sync -j$(nproc)
```

4. Set up the OpenBMC build environment:

```bash
source ./setup qemuarm
```

5. Enable the HTTPS-Guard layer and package in your auto.conf:

```bash
cat >> build/qemuarm/conf/auto.conf <<'EOF'
BBLAYERS:append = " ${TOPDIR}/.."
IMAGE_INSTALL:append = " https-guard-openbmc"
DISTRO_FEATURES:append = " systemd"
EOF
```

### Build the image

```bash
bitbake obmc-phosphor-image
```

### Run QEMU

```bash
cd ~/openbmc/build/qemuarm
runqemu nographic slirp
```

### Verify services in QEMU

```bash
systemctl status https-guard-event-generator.service
systemctl status https-guard-event-bridge.service
```

### Validate logging

```bash
journalctl -u https-guard-event-bridge -f
busctl tree xyz.openbmc_project.Logging
```

### Redfish validation

```bash
curl -k https://<bmc-ip>/redfish/v1/EventService
```

## Usage Instructions

1. Create an OpenBMC working directory outside this repository:

```bash
mkdir -p ~/openbmc
cd ~/openbmc
```

2. Initialize repo with this repository's manifest:

```bash
repo init -u /path/to/HTTPS-Guard/manifest/main.xml
```

3. Sync the repositories:

```bash
repo sync -j$(nproc)
```

4. Set up the OpenBMC build environment:

```bash
source ./setup qemuarm
```

5. Append the HTTPS-Guard layer and package to auto.conf:

```bash
cat >> build/qemuarm/conf/auto.conf <<'EOF'
BBLAYERS:append = " ${TOPDIR}/.."
IMAGE_INSTALL:append = " https-guard-openbmc"
DISTRO_FEATURES:append = " systemd"
EOF
```

6. Build the image:

```bash
bitbake obmc-phosphor-image
```

7. Start QEMU:

```bash
cd ~/openbmc/build/qemuarm
runqemu nographic slirp
```

8. Check the services:

```bash
systemctl status https-guard-event-generator.service
systemctl status https-guard-event-bridge.service
```

9. Check logs and Redfish:

```bash
journalctl -u https-guard-event-bridge -f
busctl tree xyz.openbmc_project.Logging
curl -k https://<bmc-ip>/redfish/v1/EventService
```

For more details, see docs/openbmc-qemu-integration.md.

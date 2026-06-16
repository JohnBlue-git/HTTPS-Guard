# HTTPS-Guard

HTTPS-Guard is a Network Security Observability Agent that implements a Detect -> Translate -> Dispatch security pipeline:

- Detect in kernel space with eBPF.
- Translate and classify in user space with a C++ daemon.
- Dispatch through the event bridge as Redfish Event payloads for EventService subscribers.

## What is implemented in this repository

- eBPF XDP program:
	- inspects TLS ClientHello on port 443.
	- observes TLS 1.0 and TLS 1.1 attempts and emits events to a ring buffer map (XDP_PASS, does not currently drop).
	- emits TLS handshake metadata (SNI, version) for allowed TLS connections.
	- detects plaintext HTTP verbs on port 443 (anomaly signal).

- eBPF uprobe program:
	- hooks OpenSSL SSL_write.
	- captures plaintext snippets before encryption.
	- emits payload-observed events for user-space anomaly classification.

- C++ daemon:
	- loads and attaches BPF programs.
	- consumes ring buffer events.
	- applies HTTP payload anomaly pattern checks (SQLi, path traversal, etc.).
  - writes Redfish Event JSON lines to /var/log/https_guard_events.log.

- Event bridge:
  - tails the daemon output log.
  - forwards events to D-Bus, journald, or /var/log/redfish depending on PACKAGECONFIG.

- Simulation service:
  - emits synthetic events for QEMU and slirp-based testing.

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

```
                    +----------------------------+
                    | A: Intrusive HTTPS request |
                    +----------------------------+
                   /                             \
                  /                               \
                 v                                 v
+-----------------------+                       +----------------------+
| B: eBPF XDP hook      |                       | C: eBPF SSL_write    |
|                       |                       |     uprobe           |
+-----------------------+                       +----------------------+
| (TLS version, SNI,    |                       | (payload snippet)    |
|  HTTP anomaly events) |                       |                      |
+-------+---------------+                       +---------+------------|
          |        shared `events` ring buffer            |
          +------------------------+----------------------+
                                   |
                                   v
                        +-----------------------+
                        | E: C++ daemon         |
                        | (translate + classify)|
                        +-----------------------+
                                   |
                                   | Redfish event JSON lines
                                   v
                   +--------------------------------+
                   | F: /var/log/                   |
                   |     https_guard_events.log     |
                   +--------------------------------+
                                   |
                                   v
                  +--------------------------------+
                  | G: https-guard-event-bridge    |
                  +--------------------------------+
                   /                              \
                  /                                \
                 v                                  v
+-----------------------+                       +---------------------+
| H: /var/log/redfish   |                       | I: OpenBMC logging  |
| (plain-textevent log) |                       | (DBus + journald)   |
+-----------------------+                       +---------------------+
          |                                               |
          v                                               v
+-----------------------+                       +-------------------------------+
| J: bmcweb             |                       | K: bmcweb                     |
| FilesystemLog-Watcher |                       | D-Bus monitor (Logging.Entry) |
+-----------------------+                       +-------------------------------+
          |                                               |
          +-------------------+---------------------------+
                              |
                              v
                +----------------------------+
                | L: Redfish EventService    |
                +----------------------------+
                              |
                              v
                +----------------------------+
                | M: SSE and HTTPS push      |
                |     subscribers            |
                +----------------------------+
```

**Double-delivery prevention:** When the bridge uses D-Bus path (modes `dbus` or `both`), bmcweb's D-Bus monitor already dispatches to EventService subscribers. The filesystem log (`/var/log/redfish`) is **not** written in these modes to avoid duplicate delivery. The filesystem log is only written in `journal` mode, where FilesystemLogWatcher handles delivery.

Edge labels:

- A -> B : TLS ClientHello on port 443
- A -> C : OpenSSL SSL_write invocation
- B -> E : ring buffer event (TLS version violation / handshake metadata / HTTP anomaly)
- C -> E : ring buffer event (payload observed)
- E -> F : Redfish event JSON lines appended
- F -> G : tail /var/log/https_guard_events.log
- G -> H : plain-text event log line (journal-only mode)
- G -> I : DBus + journald emission (dbus / both mode)
- H -> J : bmcweb watches /var/log/redfish
- I -> K : bmcweb monitors D-Bus Logging.Entry
- J, K -> L : Redfish Log Entry created
- L -> M : SSE and HTTPS push to subscribers

### Repository layout

- `conf/`: Yocto layer configuration for HTTPS-Guard.
- `manifest/`: repo manifest for syncing OpenBMC and HTTPS-Guard.
- `recipes-https-guard/https-guard/`: HTTPS-Guard OpenBMC recipe and deployment files.
- `recipes-kernel/linux/`: Kernel config fragment for eBPF/XDP support.
- `recipes-bmcweb/bmcweb/`: bmcweb package append for OpenBMC integration.
- `recipes-phosphor/images/`: image append to install HTTPS-Guard into `obmc-phosphor-image`.
- `scripts/`: Helper scripts (QEMU TAP setup, etc.).
- `docs/architecture.md`: Design and data flow details.

### Recipe recipes-https-guard Components

- https_guard/https_guard.bpf.c
  - XDP path: inspects TLS 1.0/1.1 ClientHello on port 443 and emits events (observes, does not currently drop).
  - XDP path: extracts SNI from TLS extensions, detects plaintext HTTP on port 443 as anomaly.
  - Uprobe path: hooks SSL_write to capture plaintext snippets before encryption for user-space analysis.
  - Emits normalized hg_event records to ring buffer map events.

- https_guard/main.cpp
  - Loads BPF object and reads ring buffer events.
  - Applies user-space anomaly rules for HTTP payloads.
  - Formats Redfish-compatible JSON and appends to output log path.
  - Accepts 4 CLI arguments: interface, ssl_lib_path, output_path, bpf_object_path.

- config/security_message_registry/OemSecurityEvent.1.0.0.json
  - OEM registry with strongly typed message IDs and argument schema.

## Build (native / standalone)

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

## Run (native)

Usage:

```bash
sudo ./build/https_guardd <network_interface> <openssl_lib_path> <output_log_path> [bpf_object_path]
```

The 4th argument (bpf_object_path) is optional. Defaults to `./build/https_guard.bpf.o`.

Example:

```bash
sudo ./build/https_guardd eth0 /usr/lib/x86_64-linux-gnu/libssl.so.3 /var/log/https_guard_events.log
```

The daemon writes one Redfish Event JSON record per line. This file path is intentionally chosen so an EventService log watcher can ingest and dispatch asynchronously to subscribers.

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
bitbake obmc-phosphor-image
```

### PACKAGECONFIG options

The recipe `recipes-https-guard/https-guard/https-guard-openbmc.bb` supports two categories of PACKAGECONFIG flags, combined freely:

#### Service selection (which systemd units are auto-enabled)

| PACKAGECONFIG | Enables | Disables | Use case |
|---|---|---|---|
| `simulation` (default) | event-generator + event-bridge | daemon | QEMU with slirp, no real eBPF |
| `daemon` | daemon + event-bridge | event-generator | Real eBPF with TAP/bridge network |
| `both` | daemon + event-generator + event-bridge | — | Debugging, comparing real vs simulated |

#### Event sink mode (how events reach Redfish EventService subscribers)

| PACKAGECONFIG | Config value | D-Bus | systemd-cat | /var/log/redfish | EventService delivery path |
|---|---|---|---|---|---|
| `event-both` (default) | `both` | ✓ | ✓ | ✗ | bmcweb D-Bus Logging.Entry monitor |
| `dbus-only` | `dbus` | ✓ | ✗ | ✗ | bmcweb D-Bus Logging.Entry monitor |
| `journal-only` | `journal` | ✗ | ✓ | ✓ | bmcweb FilesystemLogWatcher |

**Double-delivery prevention:** When D-Bus is used (`dbus` or `both` mode), bmcweb's D-Bus monitor already dispatches to all EventService subscribers. The filesystem log is **not** written to avoid duplicate delivery. The filesystem log is only written in `journal` mode.

#### Usage

Set PACKAGECONFIG in `conf/local.conf`:

```bash
# Simulation mode with journal-only sink (no D-Bus):
PACKAGECONFIG:pn-https-guard-openbmc = "simulation journal-only"

# Real daemon mode with D-Bus sink:
PACKAGECONFIG:pn-https-guard-openbmc = "daemon dbus-only"

# Both daemon and simulation (for debugging), with both sinks:
PACKAGECONFIG:pn-https-guard-openbmc = "both event-both"
```

Or override on the bitbake command line:

```bash
bitbake obmc-phosphor-image --extra-config 'PACKAGECONFIG:pn-https-guard-openbmc = "daemon dbus-only"'
```

## QEMU Setup

HTTPS-Guard supports two QEMU networking modes:

| Mode | XDP support | Networking | Use case |
|---|---|---|---|
| **SLIRP** (default) | No | user-mode (NAT) | Simulation-only testing |
| **TAP/bridge** | Yes (generic XDP) | Real virtio-net device | Real eBPF daemon |

### Mode A: SLIRP (simulation, no eBPF required)

This is the default. No special setup needed.

```bash
# Default PACKAGECONFIG is "simulation event-both"
bitbake obmc-phosphor-image
runqemu johnblue slirp nographic
```

Inside the guest, verify synthetic events are flowing:

```bash
systemctl status simulated-event-generator
journalctl -u simulated-event-generator -f

systemctl status https-guard-event-bridge
journalctl -u https-guard-event-bridge -f
```

### Mode B: TAP/bridge (real eBPF daemon)

Use this when you need the real `https-guardd` daemon with XDP and uprobes working inside the QEMU guest. This requires:

- A kernel with eBPF/XDP support (enabled by the config fragment).
- A TAP device and bridge on the host.
- A virtio-net NIC in the guest (supports generic XDP).

#### Step 1 — Host: create the TAP/bridge network

```bash
./scripts/qemu-setup-tap.sh destroy
./scripts/qemu-setup-tap.sh create
```

This creates bridge `br-httpsguard` and TAP `tap-httpsguard` with MAC `52:54:00:12:34:56`.
The script uses `sudo` internally for the network operations; do not run the whole
script with `sudo`, or the TAP device will be owned by `root` and QEMU will fail
to attach to it as your user.

#### Step 2 — Build the image with daemon mode

```bash
echo 'PACKAGECONFIG:pn-https-guard-openbmc = "daemon dbus-only"' >> conf/local.conf
bitbake obmc-phosphor-image
```

#### Step 3 — Launch QEMU with TAP networking

```bash
QB_NETWORK_OPTION='-netdev tap,id=net0,ifname=tap-httpsguard,script=no,downscript=no -device virtio-net-pci,netdev=net0,mac=52:54:00:12:34:56'
QB_NET=none runqemu johnblue nographic qemuparams="$QB_NETWORK_OPTION"
```

`QB_NET=none` is required here because `runqemu` otherwise adds its own default
network backend first, which would duplicate `net0` when the custom TAP device is
passed through `qemuparams`.

#### Step 4 — Inside the guest: verify and monitor

```bash
# Verify kernel BPF support is enabled
zcat /proc/config.gz | grep -E "CONFIG_BPF|CONFIG_XDP|CONFIG_UPROBE"

# Check daemon status
systemctl status https-guard-daemon
journalctl -u https-guard-daemon -f

# Verify bridge service is processing events
systemctl status https-guard-event-bridge
journalctl -u https-guard-event-bridge -f

# Check the event log
cat /var/log/https_guard_events.log
```

### Kernel eBPF/XDP configuration

The kernel recipe `linux-aspeed` is extended by `recipes-kernel/linux/linux-aspeed_%.bbappend`, which includes the config fragment `recipes-kernel/linux/bpf-kernel-config.cfg`. This enables all required kernel features:

- `CONFIG_BPF`, `CONFIG_BPF_SYSCALL`, `CONFIG_BPF_JIT`
- `CONFIG_NET_XDP`, `CONFIG_NET_XDP_XMIT` (generic XDP fallback for virtio)
- `CONFIG_UPROBE_EVENTS`, `CONFIG_UPROBES`, `CONFIG_KPROBES`
- `CONFIG_DEBUG_INFO_BTF` (BTF required by CO-RE eBPF)
- `CONFIG_BPF_EVENTS`, `CONFIG_FPROBE`
- And more (see the config fragment for the full list)

After building, verify the kernel includes these features:

```bash
bitbake virtual/kernel -c menuconfig
# Search for CONFIG_BPF, CONFIG_XDP, CONFIG_UPROBE
```

Or check the generated config:

```bash
grep -E "CONFIG_BPF|CONFIG_XDP|CONFIG_UPROBE" tmp/work/johnblue-poky-linux/linux-aspeed/*/build/.config
```

### Verify services (QEMU or real hardware)

```bash
# In simulation mode:
systemctl status simulated-event-generator.service
journalctl -u simulated-event-generator -f

# In daemon mode:
systemctl status https-guard-daemon.service
journalctl -u https-guard-daemon -f

# Always running:
systemctl status https-guard-event-bridge.service
journalctl -u https-guard-event-bridge -f
```

### Validate logging and Redfish

```bash
busctl tree xyz.openbmc_project.Logging

curl -k https://<bmc-ip>/redfish/v1/EventService
curl -k https://<bmc-ip>/redfish/v1/EventService/Subscriptions
```

## Notes on production hardening

- Replace static signatures with configurable rule packs.
- Add JA3/JA4 fingerprint generation in user space.
- Integrate with journald and OpenBMC dbus log pipelines.
- Add unit tests for detector and payload formatter.
- Add integration tests with replayed PCAP and synthetic SSL_write traffic.

### Certificates in bmcweb

bmcweb uses two PEM files inside the BMC to establish TLS connections, and
relies on two more directories to decide which certificates/CA chains to
trust. The four locations are summarised below:

| Path | Role | Direction | Purpose |
|------|------|-----------|---------|
| `/etc/ssl/certs/https/server.pem` | Server certificate (Identity Store) | BMC -> client | Presented by bmcweb to your browser/HTTPS client when you open the Redfish web UI. This is the certificate (and matching private key embedded as a combined PEM) that the BMC "shows" to you during the TLS handshake on port 4433. |
| `/etc/ssl/certs/https/client.pem` | Client certificate (Identity Store, optional) | BMC -> remote server | Used by bmcweb when it acts as a TLS **client**. This covers both ordinary outbound HTTPS calls from bmcweb and **mutual TLS (mTLS)** to a Redfish event subscriber — the BMC will present this certificate to the listener if the subscriber's destination is configured to request a client cert. |
| `/etc/ssl/certs/https/` (folder) | Identity Store | BMC -> peer | The directory containing the PEM files above. Together they are what the BMC shows to *you* (as a server) and to *remote services* (as a client) during TLS handshakes. |
| `/etc/ssl/certs/authority/` (folder) | Trust Store (Authority) | BMC <- remote server | The directory of CA / leaf certificates the BMC uses to decide whether a **remote** server (e.g. your event destination) is trusted. When the BMC POSTs an event to `https://<listener-ip>:8443/events`, it validates the listener's certificate chain against this directory. |

Conceptually:

- **Identity Store** (what the BMC shows to you): `/etc/ssl/certs/https/server.pem`
  and `/etc/ssl/certs/https/client.pem`.
- **Trust Store / Authority** (who the BMC trusts): `/etc/ssl/certs/authority/`.

If a remote certificate is not in the Trust Store, the BMC will refuse the
TLS connection unless the subscription is created with `VerifyCertificate:
false`. The section below walks through both flows.

### Subscribe to Redfish EventService (HTTPS push)

The BMC delivers events by POSTing JSON payloads to a destination URL that
you register through the Redfish `EventService/Subscriptions` endpoint. The
full flow is: prepare a local HTTPS receiver, install its certificate into
the BMC's Trust Store (optional but recommended), then create the
subscription.

#### Step 1 — Prepare an HTTPS receiver on the listener machine

On the machine whose IP you will use as `Destination` (replace
`192.168.11.76` with the actual IP that the BMC can reach), generate a
self-signed certificate whose CN/SAN matches that IP:

```bash
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout key.pem -out cert.pem -days 365 \
  -subj "/CN=<bmc-ip>" \
  -addext "subjectAltName = IP:192.168.11.76"
```

This produces two files: `cert.pem` (server certificate) and `key.pem`
(matching private key).

#### Step 2 — Run a minimal Python HTTPS listener

Save the following as `~/MyListener/listener.py`:

```python
# save as ~/MyListener/listener.py
from http.server import BaseHTTPRequestHandler, HTTPServer
import ssl

class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length)
        print(f"\n[EVENT RECEIVED] Path: {self.path}")
        print(body.decode('utf-8'))
        
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"Success")

# Configuration
server_address = ('0.0.0.0', 8443)
httpd = HTTPServer(server_address, Handler)

# SSL Setup
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
# Since we generated separate files in Step 1:
context.load_cert_chain(certfile="cert.pem", keyfile="key.pem")

httpd.socket = context.wrap_socket(httpd.socket, server_side=True)

print(f"Listener active on https://{server_address[0]}:{server_address[1]}/events")
httpd.serve_forever()
```

Start the listener in another terminal:

```bash
cd ~/MyListener
python3 listener.py
```

You should see `Listener active on https://0.0.0.0:8443/events`. The BMC
will POST Redfish event payloads to `https://<listener-ip>:8443/events`.

#### Step 3 — Add the listener's certificate to the BMC Trust Store

Before subscribing with certificate verification enabled, the BMC must
trust the listener's self-signed `cert.pem`. Upload it to
`/redfish/v1/Managers/bmc/Truststore/Certificates/`. The `sed` command
flattens the PEM file so that it can be passed inline as a JSON string:

```bash
curl -k -u root:0penBmc -X POST \
  https://192.168.11.76:4433/redfish/v1/Managers/bmc/Truststore/Certificates/ \
  -H "Content-Type: application/json" \
  -d "{\"CertificateString\": \"$(sed ':a;N;$!ba;s/\n/\\n/g' cert.pem)\", \"CertificateType\": \"PEM\"}" -v
```

After this call, `cert.pem` is known to the BMC and the TLS handshake
from the BMC to your listener will succeed even when `VerifyCertificate`
is left at its default (`true`).

#### Step 4 — Create the subscription

With Trust Store entry in place (certificate verification enabled):

```bash
curl -k -X POST https://<bmc-ip>:4433/redfish/v1/EventService/Subscriptions \
	-H "Content-Type: application/json" \
	-d '{
		"Destination": "https://<bmc-ip>:8443/events",
		"Protocol": "Redfish",
		"SubscriptionType": "RedfishEvent",
		"Context": "https-guard-demo"
	}'
```

Alternatively, if you do **not** want to install the listener certificate
into the Trust Store (for example, while doing a quick local test), you
can disable verification on a per-subscription basis by setting
`VerifyCertificate` to `false`:

```bash
curl -k -X POST https://<bmc-ip>/redfish/v1/EventService/Subscriptions \
	-H "Content-Type: application/json" \
	-d '{
		"Destination": "https://<listener-ip>:8443/events",
		"VerifyCertificate": false,
		"Protocol": "Redfish",
		"SubscriptionType": "RedfishEvent",
		"Context": "https-guard-demo"
	}'
```

Notes:

- `<bmc-ip>` is the BMC's address (default port `4433`).
- `<listener-ip>` is the IP that the BMC can reach to deliver events
  (the same IP you used as CN/SAN in Step 1).
- `Context` is an opaque string echoed back in every event payload; it is
  useful for filtering in your listener.
- If BMC authentication is enabled, add `-u <user>:<password>` to the
  `curl` commands above.
- Use the HTTPS push subscription when you want the BMC to POST events to
  another service. Use SSE when you want to watch the event stream
  directly from a terminal without creating a subscription destination.

Listen to Redfish events over Server-Sent Events (SSE):
- HTTP/2 incompatibility: The connection negotiated h2 via ALPN (confirmed in the log: ALPN selected protocol "h2"). SseSocketRule::handleUpgrade in bmcweb only has overloads for plain TCP and TLS-over-TCP (HTTP/1.1). There is no HTTP/2 overload — so even with the correct path, SSE would fail. SSE requires HTTP/1.1.
- Missing trailing slash: The route is registered as /redfish/v1/EventService/SSE/ (with /) but the curl request was /redfish/v1/EventService/SSE (without /). That's why the catch-all /redfish/<path> matched and returned 404.

```bash
curl --http1.1 -k -N -u root:0penBmc -H "Accept: text/event-stream" \
  "https://<bmc-ip>:4433/redfish/v1/EventService/SSE/"
```

If BMC authentication is enabled, add `-u <user>:<password>` to the `curl` commands above. Use the HTTPS push subscription when you want the BMC to POST events to another service. Use SSE when you want to watch the event stream directly from a terminal without creating a subscription destination.
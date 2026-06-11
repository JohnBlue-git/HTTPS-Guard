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
  - writes Redfish Event JSON lines to /var/log/https_guard_events.log.

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
                                 +--------------------------------+
                                 | A: Intrusive HTTPS request     |
                                 +--------------------------------+
                                  /                              \
                                 /                                \
                                v                                  v
+-----------------------------+                      +-------------------------------+
| B: eBPF XDP program         |                      | C: eBPF SSL_write uprobe      |
+-----------------------------+                      +-------------------------------+
   |              \                                          |
   |               \                                         |
   |                \                                        |
   v                 v                                       v
+-------------+   +-------------------+   +-------------------+
| D: XDP_DROP |   | E: C++ daemon     |<--+ ring buffer event |
| in kernel   |   |  (translate +     |   +-------------------+
| (TLS 1.0/   |   |   classify)       |
|  1.1)       |   +-------------------+
+-------------+            |
                           | Redfish event JSON lines
                           v
              +------------------------------+
              | F: /var/log/                |
              |     https_guard_events.log  |
              +------------------------------+
                           |
                           v
              +------------------------------+
              | G: https-guard-event-bridge  |
              +------------------------------+
                /                              \
               /                                \
              v                                  v
+-------------------------+         +----------------------------+
| H: /var/log/redfish     |         | I: OpenBMC logging         |
|     (plain-text event   |         |  (optional DBus +          |
|      log)               |         |   journald)                |
+-------------------------+         +----------------------------+
              |
              v
+------------------------------+
| J: bmcweb                    |
|     FilesystemLogWatcher     |
+------------------------------+
              |
              v
+------------------------------+
| K: Redfish EventService      |
+------------------------------+
              |
              v
+------------------------------+
| L: SSE and HTTPS push        |
|     subscribers              |
+------------------------------+
```

Edge labels:

- A -> B : TLS ClientHello on port 443
- A -> C : OpenSSL SSL_write invocation
- B -> D : TLS 1.0 or 1.1 ClientHello detected
- B -> E : ring buffer event (allowed TLS)
- C -> E : ring buffer event (payload observed / anomaly)
- E -> F : Redfish event JSON lines appended
- F -> G : tail /var/log/https_guard_events.log
- G -> H : plain-text event log line
- G -> I : optional DBus and journald emission
- H -> J : bmcweb watches /var/log/redfish
- J -> K : Redfish Log Entry created
- K -> L : SSE and HTTPS push to subscribers

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
sudo ./build/https_guardd eth0 /usr/lib/x86_64-linux-gnu/libssl.so.3 /var/log/https_guard_events.log
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

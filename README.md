# HTTPS-Guard for OpenBMC

HTTPS-Guard is an eBPF-based network security observability and enforcement tool for OpenBMC. It detects TLS version violations and HTTP anomalies in real-time, then takes automated countermeasures through a hybrid kernel/userspace architecture.

## Table of Contents

- [What is HTTPS-Guard?](#what-is-https-guard)
- [Architecture Overview](#architecture-overview)
- [Source Code Structure](#source-code-structure)
- [Building HTTPS-Guard](#building-https-guard)
- [QEMU Configuration](#qemu-configuration)
  - [Bridge Mode (Recommended for XDP)](#bridge-mode-recommended-for-xdp)
  - [SLIRP Mode (Default)](#slirp-mode-default)
  - [Port Forwarding Limitations](#port-forwarding-limitations)
- [Deployment](#deployment)
- [Monitoring Redfish Events](#monitoring-redfish-events)
- [Exercising the Detections](#exercising-the-detections)
  - [The trigger helper](#the-trigger-helper)
  - [Which rules enforce, and why that matters](#which-rules-enforce-and-why-that-matters)
  - [Verification status](#verification-status)
  - [Test-environment caveats](#test-environment-caveats)
- [Platform Support](#platform-support)
- [Troubleshooting](#troubleshooting)

## What is HTTPS-Guard?

HTTPS-Guard provides real-time network security monitoring for OpenBMC systems by:

1. **Detecting TLS version violations** - Identifies when clients attempt to use TLS 1.0 or 1.1 (insecure protocols)
2. **Monitoring HTTP payloads** - Captures plaintext HTTP traffic on port 443 for anomaly detection
3. **Automated enforcement** - Blocks malicious connections via TCP teardown and IP blocklisting
4. **Redfish integration** - Dispatches security events through OpenBMC's EventService

### Key Features

- **eBPF-based detection** - Uses uprobe (primary) and XDP (auxiliary) for kernel-level monitoring
- **Hybrid enforcement** - Synchronous XDP_DROP for known threats + asynchronous userspace classification
- **Pattern detection** - SQL injection, path traversal, and other attack signatures
- **Zero-configuration fallback** - Gracefully degrades on platforms without XDP support
- **Redfish EventService** - Native integration with OpenBMC event infrastructure

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                        Kernel Space                             │
│  ┌──────────────┐              ┌──────────────┐                 │
│  │   Uprobe     │              │     XDP      │                 │
│  │ SSL_write()  │              │  (optional)  │                 │
│  │              │              │              │                 │
│  │ • ssl->ver   │              │ • TLS check  │                 │
│  │ • payload    │              │ • HTTP check │                 │
│  │ • PID        │              │ • blocklist  │                 │
│  └──────┬───────┘              └──────┬───────┘                 │
│         │                             │                         │
│         └─────────────┬───────────────┘                         │
│                       │                                         │
│              ┌────────▼────────┐                                │
│              │  Ring Buffer    │                                │
│              │  (events map)   │                                │
│              └─────────────────┘                                │
└─────────────────────────────────────────────────────────────────┘
                          │
                          │ async
                          ▼
┌────────────────────────────────────────────────────────────────┐
│                       Userspace                                │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │              https-guardd daemon                         │  │
│  │  ┌────────────────────────────────────────────────────┐  │  │
│  │  │ poll thread: ring_buffer__poll()                   │  │  │
│  │  │   → find owning hook, its ringBufferHandler()      │  │  │
│  │  │     submits the record + its detection list        │  │  │
│  │  ├──────────────── thread boundary ───────────────────┤  │  │
│  │  │ DetectLoop (Boost.Asio io_context, 2 threads):     │  │  │
│  │  │   → walk the list, first verdict wins:             │  │  │
│  │  │     • TlsVersionDetector    (< TLS 1.2)            │  │  │
│  │  │     • PayloadAnomalyDetector (SQLi/traversal)      │  │  │
│  │  │     • CipherSuiteDetector   (weak suites, alert)   │  │  │
│  │  │     • SniDetector           (malformed, alert)     │  │  │
│  │  │     • CertAccessDetector    (HTTPS key opened)     │  │  │
│  │  │     • ConnRateDetector      (SYNs/window)          │  │  │
│  │  │     • SlowlorisDetector     (conns held open)      │  │  │
│  │  │     • RenegotiationDetector (handshakes/window)    │  │  │
│  │  │   → if actionable: resolve peer (lazily, uprobe)   │  │  │
│  │  │       • BlockTcpAction (SOCK_DESTROY, full tuple)  │  │  │
│  │  │       • BlocklistAddAction (BPF map update)        │  │  │
│  │  │   → LogAction (file write, always)                 │  │  │
│  │  ├────────────────────────────────────────────────────┤  │  │
│  │  │ every 2s: ConnRateSweeper reads the per-source     │  │  │
│  │  │   counter map and synthesises rate / Slowloris /   │  │  │
│  │  │   renegotiation events for the same pipeline       │  │  │
│  │  └────────────────────────────────────────────────────┘  │  │
│  └──────────────────────────────────────────────────────────┘  │
│                          │                                     │
│                          ▼                                     │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │         Event Bridge (shell script)                      │  │
│  │  Tails log → D-Bus Create / journal / Redfish log        │  │
│  └──────────────────────────────────────────────────────────┘  │
└────────────────────────────────────────────────────────────────┘
```

**Design Principle:** BPF is **OBSERVATIONAL** (data collection only), userspace is **INTELLIGENT** (classification, decision-making, enforcement).

> For an interactive, diagram-based walkthrough of this pipeline, see [DESIGN.html](DESIGN.html).

## Source Code Structure

### Layer layout

```
meta-https-guard/
├── conf/machine/johnblue.conf        # QEMU AST2600 machine definition (networking modes)
├── recipes-https-guard/https-guard/  # Main recipe + all C++/eBPF source
│   ├── https-guard-openbmc.bb        # BitBake recipe (build flags, install, PACKAGECONFIG)
│   └── files/                        # Source tree — see DESIGN.md for full details
├── recipes-kernel/linux/             # Kernel BPF/XDP config fragment
├── recipes-bmcweb/bmcweb/            # bmcweb OemSecurityEvent schema append
├── scripts/qemu-bridge/qemu-setup-tap.sh # Host bridge / TAP / NAT setup for QEMU testing
└── manifest/main.xml                 # Repo manifest
```

### Component roles

The source under `files/` is organized around the **Detect → Classify → Dispatch** pipeline, one top-level directory per stage:

| Component | Path | Role |
|-----------|------|------|
| **Detect** | `programs/` | Attaches BPF hooks and hands raw records over — no parsing, no rules. Three hooks derive from `BpfProgram`: `ssl_uprobe/` (uprobes on `SSL_write()` **and** `SSL_read()`, PRIMARY), `xdp_tls/` (ClientHello inspection, blocklist enforcement, and the per-source connection counters, AUXILIARY), and `lsm_cert_guard/` (BPF-LSM on the HTTPS key — cannot attach on ARM32, see [LIMITATIONS.md](LIMITATIONS.md)). Each hook splits into `ebpf/` and `src/`; `core/` holds `BpfProgram` and `HttpGuardProgram`, which owns the one object, ring buffer and poll loop |
| **Classify** | `detections/` | Eight detections, one directory each, every one holding its own event struct, its parse, its rule and its `DESIGN.md`: `tls_version/`, `payload_anomaly/`, `cipher_suite/`, `sni/`, `cert_access/`, `conn_rate/`, `slowloris/`, `renegotiation/`. Plus `core/` — the `IDetection` seam, `EventMeta`, and `DetectLoop`, which walks a submitted list and knows nothing about events. The three counting detections are stateful without any stateful rule: their state lives in a BPF map that `ConnRateSweeper` aggregates |
| **Dispatch** | `actions/` | Three async countermeasures run through `ActionLoop`: `log/` (file write), `tcp/` (SOCK_DESTROY via Netlink), `blocklist/` (BPF map update) |
| **Tests** | `tests/` | doctest-based unit tests for the `detections/` layer and the real parsers — no kernel/BPF/root/QEMU dependency |
| **Event bridge** | `service/https-guard-event-bridge.sh` | Shell script that tails the event log and forwards entries to D-Bus and/or the Redfish filesystem log |

**Which rules enforce:** the blocklist applies to a source address on *every* port, so an actionable false positive removes all access to the BMC for the blocklist TTL. TLS-version, payload-anomaly and the three counting rules enforce; cipher-suite, SNI and certificate-access alert only. The reasoning is in `detections/CLAUDE.md`, and it is worth reading before changing a rule's `actionable` flag.

> For build system internals, the raw event ABI, and the security-model rationale, see [DESIGN.md](DESIGN.md). One level down, every unit documents itself: `detections/<family>/DESIGN.md` per detection (why detect it, how, how to protect, what to hook), `actions/<kind>/DESIGN.md` per countermeasure, plus a layer document each for `programs/`, `detections/` and `actions/`. Known gaps and unverified claims: [LIMITATIONS.md](LIMITATIONS.md).

## Building HTTPS-Guard

### Prerequisites

```bash
# Ubuntu/Debian
sudo apt install git gcc g++ make file wget \
    gawk diffstat bzip2 cpio chrpath zstd lz4 bzip2 \
    python3 python3-pip

# Fedora
sudo dnf install git python3 gcc g++ gawk which bzip2 chrpath cpio \
    hostname file diffutils diffstat lz4 wget zstd rpcgen patch
```

### Build Steps

```bash
# 1. Clone OpenBMC with HTTPS-Guard layer
git clone https://github.com/openbmc/openbmc
cd openbmc

# 2. Add meta-https-guard to bblayers.conf
#    (The layer should already be present if you're in this repo)

# 3. Setup build environment for your target
. setup johnblue  # or your target machine

# 4. Build the image
bitbake obmc-phosphor-image

# Or build just HTTPS-Guard
bitbake https-guard-openbmc
```

### Configuring via local.conf

`https-guard-openbmc`'s behavior is controlled by `PACKAGECONFIG`, set per-recipe in your build's `conf/local.conf` (or a distro/machine conf). The default is:

```
PACKAGECONFIG:pn-https-guard-openbmc ?= "daemon event-both"
```

**Service selection** — which systemd services get built/enabled (pick one):

| Flag | Effect |
|------|--------|
| `daemon` **(default)** | Enables the real `https-guardd` (uprobe + optional XDP), disables the simulator. Requires a kernel with `CONFIG_BPF`/`CONFIG_UPROBE_EVENTS` (and `CONFIG_NET_XDP` for XDP — its absence is non-fatal, the daemon runs uprobe-only). Also turns the BPF object build on, which needs a target kernel built with `CONFIG_DEBUG_INFO_BTF`. |
| `simulation` | Enables `simulated-event-generator` instead, disables the real daemon. No kernel eBPF/XDP support and no BPF toolchain required — the fallback for a machine whose kernel lacks BTF. |
| `both` | Enables both, for comparing real vs. simulated events side by side. |

> The default is `daemon` because the daemon is the point of the layer: shipping
> the simulator by default meant a first boot looked like it was working while
> detecting nothing real. The trade is that the default build now requires a
> BTF-carrying kernel, where it previously skipped BPF entirely — see the flag
> table above for the fallback.

**Event delivery mode** — how events reach Redfish EventService subscribers (pick one):

| Flag | Effect |
|------|--------|
| `dbus-only` | Emits via D-Bus `xyz.openbmc_project.Logging.Create` only. |
| `journal-only` | Emits via `systemd-cat` + writes `/var/log/redfish` for bmcweb's `FilesystemLogWatcher`. |
| `event-both` (default) | Emits both D-Bus and journal, and also writes `/var/log/redfish` (required for the push to actually reach subscribers — see [Event Bridge Not Dispatching](#event-bridge-not-dispatching)). |

Example: build with the real daemon and journal-only delivery:

```
# conf/local.conf
MACHINE = "johnblue"
PACKAGECONFIG:pn-https-guard-openbmc = "daemon journal-only"
```

Then rebuild:

```bash
bitbake https-guard-openbmc
```

### Build Outputs

- **Daemon binary:** `tmp/deploy/images/<machine>/https-guard-openbmc/usr/sbin/https-guardd`
- **BPF object:** `tmp/deploy/images/<machine>/https-guard-openbmc/usr/share/https-guard/https_guard.bpf.o`
- **Systemd units:** Installed to `/usr/lib/systemd/system/`

## QEMU Configuration

### Bridge Mode (Recommended for XDP)

Bridge mode gives the guest a real TAP-backed Ethernet interface, which is required for XDP. SLIRP (the default) uses user-mode networking and cannot support XDP.

- **AST2600 (johnblue)**: Uses the machine's built-in `ftgmac100` NIC, backed by `tap-httpsguard`
- **x86_64/aarch64**: Uses `virtio-net-device`, backed by the same TAP

#### Step 1 — Host: create bridge and TAP (one-time)

The helper script creates `br-httpsguard` (`192.168.200.1/24`), attaches `tap-httpsguard`, enables IP forwarding, and sets up NAT masquerade so the guest can reach the internet.

```bash
cd /path/to/HTTPS-Guard
sudo ./meta-https-guard/scripts/qemu-bridge/qemu-setup-tap.sh destroy
sudo ./meta-https-guard/scripts/qemu-bridge/qemu-setup-tap.sh create
```

Expected output ends with:
```bash
[+] Done. Bridge br-httpsguard ready with TAP tap-httpsguard.
    Bridge IP: 192.168.200.1/24 (host side)
```

#### Step 2 — Host: launch QEMU in bridge mode

For AST2600, `-net nic,netdev=net0` creates the `nd_table[0]` entry that the machine's `ftgmac100` consumes as its network backend (it does **not** add a second NIC). `QB_NET=none` prevents runqemu from adding its default SLIRP `net0` which would conflict.

```bash
QB_NET=none runqemu johnblue nographic \
  qemuparams='-netdev tap,id=net0,ifname=tap-httpsguard,script=no,downscript=no -net nic,netdev=net0'
```

#### Step 3 — Guest: configure networking

Once the guest boots, assign a static IP to `eth0` (the ftgmac100 backed by the TAP):

```bash
# Run inside the QEMU guest as root
ip addr add 192.168.200.2/24 dev eth0
ip link set eth0 up
ip route add default via 192.168.200.1
echo 'nameserver 8.8.8.8' > /etc/resolv.conf
```

#### Step 4 — Host: verify connectivity

```bash
# Ping the guest
ping -c 3 192.168.200.2

# Test Redfish access
# (but the --tlsvX.X flag is ignored by curl — see the curl/OpenSSL 3.x caveat in DESIGN.md)
curl -ku root:0penBmc https://192.168.200.2/redfish/v1 --tlsv1.3
curl -ku root:0penBmc https://192.168.200.2/redfish/v1 --tlsv1.2
curl -ku root:0penBmc https://192.168.200.2/redfish/v1 --tlsv1.1
curl -ku root:0penBmc https://192.168.200.2/redfish/v1 --tlsv1.0
```

#### Step 5 — Guest: verify XDP is loaded

```bash
# Check the NIC for an attached XDP program
ip link show eth0 | grep -i xdp
# Expected line: "    prog/xdp  id <N>  name https_guard_xdp  ..."

# Check daemon logs
journalctl -u https-guard-daemon -l | grep -i xdp
# Expected: "https_guard: XDP attached in native mode"
#       or: "https_guard: XDP attached in generic (SKB) mode"
# If neither: daemon is running uprobe-only (kernel lacks CONFIG_XDP)
```

### SLIRP Mode (Default)

SLIRP is the default QEMU networking mode. It uses user-mode networking and does **not** expose a real NIC to the guest.

**Launch QEMU with SLIRP (default):**

```bash
runqemu johnblue nographic slirp
```

**Characteristics:**
- ✅ Easy to use, no host setup required
- ✅ Uprobe detection works perfectly
- ❌ No promiscuous mode
- ❌ Limited to user-mode networking

**XDP under SLIRP — verify on your own kernel build, don't assume:** this section previously stated XDP cannot attach under SLIRP (no real netdev). A live QEMU boot on this project's own build showed the opposite — `journalctl` logged `"https_guard: XDP attached in native mode"` even under plain SLIRP. Attach succeeding doesn't necessarily mean line-rate `XDP_DROP` enforcement is exercised the same way it would be against a real NIC (SLIRP's backend still isn't real hardware), and this wasn't independently confirmed either way — only that the daemon and OS agree the program is attached. Treat the SLIRP/XDP relationship as kernel-build-dependent until someone verifies the drop path specifically, not as a fixed platform limitation.

**Check what actually attached:**

```bash
journalctl -u https-guard-daemon -l | grep "enforcement active"
# "https_guard: enforcement active via N of M hook(s)" — N/M depends on
# what actually attached on your kernel; it is not hardcoded to any
# specific hook combination (see programs/core/src/HttpGuardProgram.cpp).
```

### Port Forwarding Limitations

**QEMU SLIRP port forwarding does NOT work with HTTPS-Guard XDP:**

```bash
# This does NOT enable XDP:
runqemu johnblue nographic \
  qemuparams="-redir tcp:8443::443"
```

**Why?** SLIRP uses a virtual network stack inside QEMU. The guest's `eth0` is backed by the `ftgmac100` emulated driver with a SLIRP backend, not a real network device. XDP requires either:
- Native XDP: NIC driver with `ndo_bpf` support
- Generic XDP: Real netdev with `netif_receive_skb()` hook

The reasoning above is why SLIRP is *documented* as providing neither — but see the [XDP under SLIRP](#slirp-mode-default) note above: an actual boot on this project's kernel showed the attach call itself succeeding under SLIRP regardless. Port forwarding is still a separate, unaffected problem either way (it doesn't change what backend `eth0` has), so bridge mode remains the recommended path for anything you want to depend on XDP actually running — see [Bridge Mode](#bridge-mode-recommended-for-xdp) above.

## Deployment

### Enable Services

```bash
# Inside QEMU/guest
systemctl enable https-guard-daemon
systemctl enable https-guard-event-bridge
systemctl start https-guard-daemon
systemctl start https-guard-event-bridge
```

### Verify Deployment

```bash
# Check daemon status
systemctl status https-guard-daemon

# View daemon logs
journalctl -u https-guard-daemon -f

# Check event log
tail -f /var/log/https_guard_events.log

# Verify eBPF programs loaded
bpftool prog list
# Expected: https_guard_ssl_write (uprobe) and optionally https_guard_xdp (xdp)

# Check ring buffer map
bpftool map list
# Expected: events (ringbuf)
```

### Configuration

Edit `/etc/default/https-guard` (installed from `https-guard.conf`):

```bash
# Event sink mode: dbus | journal | both
HTTPS_GUARD_EVENT_MODE=both

# Network interface for XDP attachment
HTTPS_GUARD_IFACE=eth0

# Path to OpenSSL shared library (uprobe attachment point)
HTTPS_GUARD_SSL_LIB=/usr/lib/libssl.so.3

# JSON event archive read by the event bridge
HTTPS_GUARD_EVENT_FILE=/var/log/https_guard_events.log

# Redfish log directory watched by bmcweb for EventService dispatch
HTTPS_GUARD_REDFISH_LOG=/var/log/redfish
```

## Monitoring Redfish Events

### Event Log Location

The daemon writes events to `HTTPS_GUARD_EVENT_FILE` (`/var/log/https_guard_events.log`) in JSON format. The event bridge tails this file and forwards entries to D-Bus / the Redfish log directory:

```json
{"@odata.type":"#Event.v1_7_0.Event","Name":"Platform Security Anomaly Event","Id":"1234567890","Events":[{"EventId":"evt-1234567890","Severity":"Critical","MessageId":"OemSecurityEvent.1.0.HttpsTlsVersionViolation","Message":"Security violation: Process 'curl' (PID 12043) attempted an HTTPS connection using an insecure TLS version (TLS 1.0). Packet was blocked.","EventTimestamp":"2024-01-15T10:30:45Z","OriginOfCondition":{"@odata.id":"/redfish/v1/Managers/BMC"}}]}
```

Note: `MessageId` uses exactly 4 dot-separated fields (`RegistryName.Major.Minor.MessageKey`) because bmcweb's `registries::getMessageComponents()` requires that shape to resolve severity/text — it does not accept a 3-part semver patch digit. The registry itself is compiled into bmcweb from
`recipes-bmcweb/bmcweb/files/0001-add-oem-security-event-message-registry.patch`
(mirrored for documentation at `/redfish/v1/Registries/OemSecurityEvent.1.0.0/`), so a Redfish EventService push for these MessageIds carries the real severity below rather than a generic borrowed one.

### Event Message IDs

All nine, and which detection rule emits each. "Enforces" means the verdict is
`actionable`, which triggers the blocklist and — where a full 4-tuple is known —
a TCP teardown. See [Which rules enforce, and why that matters](#which-rules-enforce-and-why-that-matters).

| Message ID (`OemSecurityEvent.1.0.` +) | Severity | Emitted by | Fed by | Enforces |
|---|---|---|---|---|
| `HttpsTlsVersionViolation` | Critical | `TlsVersionDetector` | uprobe + XDP | **yes** |
| `HttpsPayloadAnomalyDetected` | Warning | `PayloadAnomalyDetector` | uprobe + XDP | **yes** |
| `HttpsConnectionRateViolation` | Warning | `ConnRateDetector` | XDP counters | **yes** |
| `HttpsSlowlorisDetected` | Warning | `SlowlorisDetector` | XDP counters | **yes** |
| `HttpsTlsRenegotiationStorm` | Warning | `RenegotiationDetector` | XDP counters | **yes** |
| `HttpsWeakCipherSuiteDetected` | Warning | `CipherSuiteDetector` | XDP | no — alert only |
| `HttpsSniAnomalyDetected` | Warning | `SniDetector` | XDP | no — alert only |
| `HttpsCertificateAccessViolation` | Critical | `CertAccessDetector` | BPF-LSM | no |
| `HttpsTrafficObserved` | OK | none — inline fallback when no rule matches | any | no |

### Subscribe to Events via Redfish

bmcweb's EventService delivers events by POSTing them as HTTPS requests to a
subscriber-supplied `Destination` URL. `scripts/listener/` provides a minimal
HTTPS receiver (`listener.py`) for testing this end-to-end, backed by its own
`cert.pem` / `key.pem`.

#### Step 1 — Generate a certificate for the listener

```bash
cd meta-https-guard/scripts/listener

openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout key.pem -out cert.pem -days 365 \
  -subj "/CN=<listener_ip>" \
  -addext "subjectAltName=IP:<listener_ip>"
```

Use the IP address of the machine that will run `listener.py`, reachable from
the BMC guest — e.g. `192.168.200.1` (the host side of `br-httpsguard` in
bridge mode, see [Step 1](#step-1--host-create-bridge-and-tap-one-time)
above).

#### Step 2 — Trust the certificate on the BMC

The cert is self-signed, so bmcweb's outbound HTTPS client refuses it until
it's added to the BMC's Redfish TrustStore:

```bash
cd meta-https-guard/scripts/listener

jq -n --rawfile cert cert.pem '{CertificateString: $cert, CertificateType: "PEM"}' | \
  curl -k -u root:0penBmc -X POST \
    https://192.168.200.2/redfish/v1/Managers/bmc/Truststore/Certificates \
    -H "Content-Type: application/json" -d @-
```

#### Step 3 — Start the listener (this also subscribes it to the BMC)

On startup, `listener.py` auto-detects its own IP — a UDP `connect()` to
`BMC_HOST` that never actually sends a packet, it just resolves the outbound
route/interface the BMC would use to reach you — and POSTs a Redfish
`EventService/Subscriptions` request on your behalf, so no separate `curl`
subscribe call is needed. It loads `cert.pem`/`key.pem` from its own script
directory (not the caller's cwd), so it can be run from the repo root:

```bash
python3 meta-https-guard/scripts/listener/listener.py
# [SUBSCRIBE] https://<listener_ip>:8443/events -> HTTP 201
# Listener active on https://0.0.0.0:8443/events
```

Override the defaults (`BMC_HOST=192.168.200.2`, `BMC_USER=root`,
`BMC_PASS=0penBmc`, `LISTENER_PORT=8443`) via environment variables if
needed, e.g.:

```bash
LISTENER_IP=192.168.200.1 python3 meta-https-guard/scripts/listener/listener.py
```

`LISTENER_IP` only needs to be set explicitly if auto-detection picks the
wrong interface (e.g. multiple NICs on the host).

If subscribing fails (e.g. the cert from Step 2 isn't trusted yet, or the
BMC isn't reachable), `listener.py` logs `[SUBSCRIBE] failed: ...` but keeps
running — you can still subscribe manually once the issue is fixed:

```bash
# Note: this bmcweb's EventService.v1_5_0 schema rejects "EventTypes"
# (Base.1.19.PropertyUnknown) — it was dropped from the Redfish spec in
# favor of RegistryPrefixes/MessageIds, so it's omitted here.
curl -k -u root:0penBmc -X POST \
  https://192.168.200.2/redfish/v1/EventService/Subscriptions \
  -H "Content-Type: application/json" \
  -d '{
    "Destination": "https://<listener_ip>:8443/events",
    "Protocol": "Redfish"
  }'

# Query existing subscriptions
curl -k -u root:0penBmc \
  https://192.168.200.2/redfish/v1/EventService/Subscriptions
```

#### Step 4 — Trigger and verify

```bash
curl -ku root:0penBmc https://192.168.200.2/redfish/v1
```

`listener.py`'s terminal should print the pushed event:

```
[EVENT RECEIVED] Path: /events
{"@odata.type":"#Event.v1_7_0.Event","Name":"Platform Security Anomaly Event",...}
```

#### Alternative: SSE streaming (no listener needed)

```bash
# View events via SSE (bridge mode: guest IP direct)
curl -k -N --http1.0 -u root:0penBmc \
  -H "Accept: text/event-stream" \
  https://192.168.200.2/redfish/v1/EventService/SSE/

# View events via SSE (SLIRP mode: host-forwarded port)
curl -k -N --http1.0 -u root:0penBmc \
  -H "Accept: text/event-stream" \
  https://localhost:4433/redfish/v1/EventService/SSE/
```

### D-Bus Event Monitoring

```bash
# Monitor D-Bus for log events
busctl monitor xyz.openbmc_project.Logging

# Create a manual log entry (for testing)
busctl call xyz.openbmc_project.Logging /xyz/openbmc_project/logging/entry \
  xyz.openbmc_project.Logging.Entry Create \
  'says' '{"Severity": "xyz.openbmc_project.Logging.Entry.Critical", "Message": "Test event"}'
```

## Exercising the Detections

Nine event types, and how to make each one fire. Every recipe below was run
against a real QEMU boot; where one could **not** be driven to completion, that
is stated rather than left implied.

Two things to get right before any of this works:

1. **XDP-fed rules need traffic from outside the guest.** A packet the BMC
   sends to its own `127.0.0.1` never traverses XDP. Run those cases from the
   host, against the forwarded port.
2. **The uprobe-fed rules are the opposite** — they fire on *any* process on
   the box calling `SSL_write`/`SSL_read`, so `openssl s_client` to
   `127.0.0.1:443` from inside the guest works fine.

> ### Enforcing a rule against yourself will lock you out
>
> The blocklist is keyed on **source address across every port**, not just
> 443. If you trigger an enforcing rule from the machine you are administering
> the BMC from, you lose SSH and Redfish for the full blocklist TTL (300s by
> default). This is not hypothetical — it is what happens, every time, and it
> is measured below. Trigger enforcing rules from a *third* host, or accept the
> outage.

### Quick reference

| Rule → Message ID | How to trigger it | Enforces | Verified live? |
|---|---|---|---|
| `HttpsPayloadAnomalyDetected` | Send an attack signature through TLS (§ [Payload anomaly](#payload-anomaly)) | **yes** | ✅ yes |
| `HttpsTlsVersionViolation` | Crafted ClientHello with `legacy_version` < 0x0303 (§ [Legacy TLS](#legacy-tls-version)) | **yes** | ✅ yes, XDP path |
| `HttpsWeakCipherSuiteDetected` | Crafted ClientHello offering RC4/3DES/NULL (§ [Weak cipher suite](#weak-cipher-suite)) | no | ✅ yes |
| `HttpsSniAnomalyDetected` | Malformed SNI, or a mismatch against `HTTPS_GUARD_EXPECTED_SNI` (§ [SNI anomaly](#sni-anomaly)) | no | ✅ yes, both paths |
| `HttpsTrafficObserved` | Any clean HTTPS request — the no-rule-matched fallback | no | ✅ yes |
| `HttpsConnectionRateViolation` | More than `HTTPS_GUARD_RATE_THRESHOLD` connections per 10s (§ [Volumetric](#volumetric-rate-slowloris-renegotiation)) | **yes** | ⚠ mechanism only |
| `HttpsSlowlorisDetected` | Hold more than `HTTPS_GUARD_SLOWLORIS_THRESHOLD` connections open | **yes** | ⚠ lowered threshold |
| `HttpsTlsRenegotiationStorm` | More than `HTTPS_GUARD_RENEG_THRESHOLD` handshakes per 10s | **yes** | ⚠ lowered threshold |
| `HttpsCertificateAccessViolation` | Read the HTTPS private key as any process other than `bmcweb` | no | ❌ cannot attach on ARM32 |

`⚠` and `❌` are explained under [Verification status](#verification-status) —
they are limits of the test environment and the platform, not of the rules.

### The trigger helper

`scripts/trigger/trigger_detections.py` builds TLS ClientHellos by hand,
because the three ClientHello-fed rules **cannot be driven with a normal
client**: OpenSSL 3.x refuses to offer RC4 or TLS 1.0 at all, and
`curl --tlsv1.0` is silently ignored. It sends one record and closes, which is
all XDP needs — no handshake ever completes.

```bash
# From the HOST, not the guest.
scripts/trigger/trigger_detections.py --list

# SLIRP: use the forwarded HTTPS port that runqemu printed (often 4433/4434)
scripts/trigger/trigger_detections.py weak_rc4 --port 4434

# Bridge mode: go straight at the guest
scripts/trigger/trigger_detections.py weak_rc4 --host 192.168.100.2 --port 443
```

Wait for the daemon to finish attaching before sending anything — startup takes
~16s on QEMU, and a case sent before `enforcement active via N of M hook(s)`
appears in the journal is simply lost:

```bash
journalctl -u https-guard-daemon -f | grep -m1 "enforcement active"
```

### Payload anomaly

`PayloadAnomalyDetector` matches eight case-insensitive substrings in the
plaintext passing through `SSL_write`/`SSL_read`: `../..`, `union select`,
`or 1=1`, `drop table`, `/etc/passwd`, `%2e%2e%2f`, `cmd.exe`, `wget http`.

Run inside the guest. The `sleep` matters: enforcement tears down a *live*
socket, so a request that has already closed gives nothing to act on.

```bash
(printf 'GET /etc/passwd HTTP/1.1\r\nHost: localhost\r\n\r\n'; sleep 30) \
  | openssl s_client -connect 127.0.0.1:443 -quiet -ign_eof
```

```
https_guard: uprobe event received: process='openssl' (PID 521), direction=write, tls_version=772
BlocklistAddAction: blocklisted 127.0.0.1 for 300s reason=Attack signature ... rule '/etc/passwd'
BlockTcpAction: destroyed TCP connection 127.0.0.1:42570 -> 127.0.0.1:443
```

`openssl` exits **103** (connection aborted) — that is the client observing its
own teardown, and is the real confirmation. A "SOCK_DESTROY succeeded" log line
alone would not be.

**Signatures past the first 127 bytes are not seen.** The BPF side copies at
most 127 bytes per call, so put the signature in the request path or an early
header, not a late one.

Expect a *second* event from the same request: the `SSL_read` uprobe sees
bmcweb receiving the same bytes. That one usually declines to enforce
("no connection could be attributed") — see
[Attribution](LIMITATIONS.md#attribution-and-enforcement).

### Legacy TLS version

**Enforcing.** This will blocklist the sender.

```bash
scripts/trigger/trigger_detections.py legacy_tls10 --port 4434
```

```
xdp event received: tls_version=769, is_violation=1, cipher_suites=1/1, sni='bmc.example.com'
pushing LogAction for severity=Critical
BlocklistAddAction: blocklisted 10.0.2.2 for 300s reason=... insecure TLS version (TLS 1.0)
BlockTcpAction: destroyed TCP connection 10.0.2.15:443 -> 10.0.2.2:59690
```

Measured: SSH from that host died **immediately** and came back after **271s**
of a 300s TTL. Nothing needs doing to recover — wait it out.

The **uprobe** path for this rule cannot be driven on this image at all: it
reads the *negotiated* version out of the `SSL` object, and OpenSSL 3.x will
not negotiate below TLS 1.2. Only the XDP path is reachable.

`legacy_version` is also **not** proof of the negotiated version — a TLS 1.3
client sets it to 0x0303 and signals the real version in an extension this hook
does not parse. It catches genuinely old clients, which have no such fallback.

### Weak cipher suite

Alert-only, so this is safe to run against your own host.

```bash
scripts/trigger/trigger_detections.py weak_rc4  --port 4434   # RC4 among modern suites
scripts/trigger/trigger_detections.py weak_3des --port 4434   # 3DES
scripts/trigger/trigger_detections.py weak_null --port 4434   # NULL encryption
scripts/trigger/trigger_detections.py clean     --port 4434   # control: expect HttpsTrafficObserved
```

The table covers NULL encryption, EXPORT-grade, RC4, single-DES, 3DES and
anonymous key exchange (22 code points, see
`detections/cipher_suite/weak_cipher_suites.hpp`). Capture is capped at 32
suites; the true offered count is reported separately (`cipher_suites=3/3`) so a
short list is distinguishable from a clipped one.

### SNI anomaly

Alert-only. Two independent paths, and **both are verified**.

Malformed SNI fires unconditionally — no configuration needed:

```bash
scripts/trigger/trigger_detections.py bad_sni       --port 4434   # unknown name_type
scripts/trigger/trigger_detections.py truncated_sni --port 4434   # declared length > record
```

Hostname mismatch fires **only** when an expected name is configured:

```bash
# on the BMC
sed -i 's/^HTTPS_GUARD_EXPECTED_SNI=$/HTTPS_GUARD_EXPECTED_SNI=bmc.example.com/' \
  /etc/default/https-guard
systemctl restart https-guard-daemon
# confirm it took: journalctl should say "expected SNI: bmc.example.com",
# not "(unset — mismatch checking disabled)"
```

```bash
scripts/trigger/trigger_detections.py other_sni --port 4434
```

```
Warning | HttpsSniAnomalyDetected | SNI anomaly from 10.0.2.2: SNI hostname
'attacker.example.net' does not match the expected 'bmc.example.com'.
```

A truncated hostname is flagged malformed rather than compared, so a clipped
name can never masquerade as a mismatch — or as a match.

### Volumetric: rate, Slowloris, renegotiation

**All three enforce.** All three read per-source counters that the XDP program
maintains, swept every 2s; none has a ring-buffer event of its own. The window
is fixed at **10s** at build time — only the thresholds are configurable:

```bash
HTTPS_GUARD_RATE_THRESHOLD=500       # SYNs per 10s per source     (0 = rule off)
HTTPS_GUARD_SLOWLORIS_THRESHOLD=100  # connections held open       (0 = rule off)
HTTPS_GUARD_RENEG_THRESHOLD=200      # ClientHellos per 10s        (0 = rule off)
```

Lower the relevant threshold in `/etc/default/https-guard` and restart, or you
will not reach it through QEMU (see below).

```bash
# connection rate — completed connections, not a SYN burst
python3 - <<'EOF'
import socket, time
for _ in range(150):
    try:
        socket.create_connection(("127.0.0.1", 4434), timeout=2).close()
    except OSError:
        pass
    time.sleep(0.02)
EOF
```

That produced `per-source counters: 1 source(s); busiest 151 attempts` — 150
connections plus the SSH session, which is a useful sanity check that the
counter is keyed the way you think it is.

For Slowloris, `trigger_detections.py slowloris` holds connections open — but
this is unreliable through a SLIRP hostfwd: an earlier run reached 5 held
connections (below), yet a re-measurement saw only ~1 of 3–8 arrive as
guest-side `open_conns`. SLIRP does not forward held host connections to the
guest consistently, so exercise this rule on a real netdev or a bridged/TAP
network for a dependable result. For a renegotiation storm,
`trigger_detections.py renegotiation` sends repeated handshake records on **one**
connection (a storm is many handshakes on a single connection, not one each);
bmcweb RSTs the stream after ~3 records, so set `HTTPS_GUARD_RENEG_THRESHOLD`
below that to see it fire.

**Reading the counter line is harder than it should be.** It goes to
`std::cout`, which journald makes block-buffered, so it arrives in ~4KB batches
minutes late. `systemctl restart https-guard-daemon` flushes it. Every other
diagnostic uses `std::cerr` and appears immediately — so the *absence* of a
recent counters line means nothing. Recorded in
[LIMITATIONS.md](LIMITATIONS.md#observability).

Note `process=` is meaningless for XDP-sourced events (`swapper/0`,
`systemd-journal`, whatever was on-CPU when the packet arrived) — XDP runs in
interrupt context with no owning process. Only uprobe events carry a real PID.

### Certificate access

`CertAccessDetector` fires when any process whose `/proc/<pid>/exe` is not one
of the allowed executables — `/usr/bin/bmcweb` (serves the certificate) or
`/usr/bin/phosphor-certificate-manager` (installs/replaces it via
Redfish/D-Bus, then restarts `bmcweb.service`) — opens
`/etc/ssl/certs/https/server.pem`:

```bash
cat /etc/ssl/certs/https/server.pem > /dev/null
```

**This cannot fire on the AST2600 target.** `BPF_PROG_TYPE_LSM` attach needs a
BPF trampoline, which ARM32 has never implemented, so the hook does not attach
at all — the journal says so plainly:

```
libbpf: prog 'https_guard_cert_open': failed to attach: -ENOTSUPP
https_guard: failed to attach LSM cert-access-guard (non-fatal): Unknown error 524
https_guard: enforcement active via 2 of 3 hook(s)
```

`2 of 3` is the expected healthy state on this platform, not a fault. Full
reasoning in [LIMITATIONS.md](LIMITATIONS.md#platform-the-certificate-guard-cannot-enforce-on-arm32).

### Which rules enforce, and why that matters

The distinction is deliberate, and getting it wrong has already caused an
outage during development:

- **`cipher_suite` and `sni` alert only.** They fire on a handshake bmcweb
  refuses anyway, so the offer itself does no damage. They were briefly made
  actionable and immediately locked an operator out of SSH; that incident is
  why they are not.
- **`conn_rate`, `slowloris` and `renegotiation` enforce**, because they
  describe *ongoing harm* — slots being occupied, asymmetric load being
  generated — and an alert that does not stop it is close to useless. That makes
  their thresholds safety-critical rather than tuning details.
- **`cert_access` does not enforce** because there is no connection to act on.

### Verification status

What has actually been driven end-to-end on hardware, versus what only unit
tests cover. The weaker claim is recorded as the weaker claim.

| | Status |
|---|---|
| `PayloadAnomalyDetector` | ✅ verified live, both enforcement halves |
| `TlsVersionDetector` | ✅ verified live via XDP. The uprobe path is unreachable on this image — OpenSSL 3.x will not negotiate below TLS 1.2 |
| `CipherSuiteDetector` | ✅ verified live |
| `SniDetector` | ✅ verified live — malformed *and* hostname-mismatch |
| `SlowlorisDetector` | ⚠ verified live once at a **lowered** threshold (5 connections against a limit of 3, SLIRP), not at the shipped default of 100. **Not reliably reproducible through a SLIRP hostfwd:** a re-measurement saw only ~1 of 3–8 held host connections arrive as guest-side `open_conns` — SLIRP does not forward held connections consistently. Exercise on a real netdev or bridged/TAP network for a dependable result |
| `ConnRateDetector` | ⚠ mechanism verified; the shipped default of 500/10s was never exceeded, because SLIRP will not propagate a fast enough burst (~456 in 6s was the ceiling) |
| `RenegotiationDetector` | ⚠ verified live at a **lowered** threshold (2–3 handshake records on one connection against a limit of 2; full enforcement and a measured 326s lockout). bmcweb RSTs the malformed record stream after ~3 records, so the shipped default of 200 is not reachable through SLIRP. Sending the records on *one* connection, not one connection each, is what makes it reachable at all |
| `CertAccessDetector` | ❌ unreachable on ARM32 — see above |

### Test-environment caveats

Every one of these cost real debugging time before being understood.

- **QEMU SLIRP terminates and re-originates TCP.** A rapid connect/close burst
  from the host does not arrive at the guest as SYNs. Use *completed*
  connections when exercising anything that counts them.
- **Holding as few as five connections through a SLIRP hostfwd saturates the
  forward and kills SSH on it.** So "SSH dropped" is *not* evidence that a
  source was blocklisted — the two are indistinguishable from outside. Read the
  journal, not the symptom. This was initially misdiagnosed the other way round.
- **Guest-originated loopback traffic never traverses XDP.** Wire-level cases
  must originate outside the guest.
- **Check which QEMU you are talking to.** A stale instance from an earlier
  session keeps its port, so `runqemu` silently bumps the new one (2222 → 2223,
  4433 → 4434) and SSH on 2222 answers from a hours-old image. Confirm the image
  timestamp in the `runqemu` command line, not just that SSH responds. This
  produced a confident and entirely wrong reading of a fresh build once.
- **The target image has no `bpftool`, and its BusyBox `ip` cannot detach XDP.**
  A leaked XDP attachment used to need a reboot; attachments are now
  `bpf_link`-owned and released by the kernel on process exit, including on
  `SIGKILL`. `bpftool` is not installed and cannot be cleanly built for this
  ARM32 target — the reasoning, and why it is not needed, is in
  [LIMITATIONS.md](LIMITATIONS.md#tooling-no-bpftool-on-the-target-and-it-will-not-build-for-arm32).
  The `bpftool` commands in the deployment and troubleshooting steps below are
  therefore host-side / bridged-debugging steps, not on-BMC commands.

## Platform Support

| Platform | NIC | Uprobe | XDP Native | XDP Generic | Status |
|----------|-----|--------|------------|-------------|--------|
| ASpeed AST2600 (johnblue) | ftgmac100 | ✅ | ✅* | ❌ | Full (bridge mode) |
| QEMU SLIRP | ftgmac100 (emulated) | ✅ | ❔** | ❌ | At least uprobe; verify XDP on your build |
| QEMU TAP+BRIDGE | virtio-net-* | ✅ | ✅ | ✅ | Full support |
| x86_64 (native) | ixgbe, mlx5, etc. | ✅ | ✅ | ✅ | Full support |

\*\* Documented as unsupported (SLIRP has no real netdev), but a live boot on this project's kernel logged a successful native-mode attach anyway — see the [XDP under SLIRP](#slirp-mode-default) note. Not reliable enough to plan around either way without checking your own kernel.

\* XDP on AST2600 requires bridge mode. Pass `-netdev tap,id=net0,ifname=tap-httpsguard,script=no,downscript=no -net nic,netdev=net0` to runqemu (not SLIRP).

### AST2600 Platform Notes

The ASpeed AST2600 SoC used in `johnblue` has **no PCI bus** and **no virtio-bus**, which means:

- ❌ `virtio-net-pci` cannot be used (requires PCI bus)
- ❌ `virtio-net-device` cannot be used (requires virtio-bus)
- ✅ Bridge mode works using the built-in ftgmac100 with `-netdev tap,id=net0,... -net nic,netdev=net0`
- ✅ Uprobe-based SSL_write detection works perfectly
- ✅ XDP is available in bridge mode

**Why no virtio?** The AST2600 is a BMC SoC with 4 built-in Ethernet controllers (ftgmac100). It has no PCIe controller, so QEMU's `-device virtio-net-*` options fail with error: `No 'virtio-bus' bus found`.

**Bridge mode on AST2600:** The ftgmac100 is integrated into the SoC and automatically created by the `ast2600-evb` machine. Use `-netdev tap,id=net0,ifname=tap-httpsguard,script=no,downscript=no -net nic,netdev=net0` — the `-net nic,netdev=net0` creates an nd_table[0] entry that the machine's ftgmac100 consumes as its backend. Do not use `-device ftgmac100` (it would try to place a second SoC-integrated device on the bus). This provides a real network interface for XDP support.

**SLIRP mode limitation:** In SLIRP mode (default), the ftgmac100 driver connects to a virtual network stack without a real netdev, so XDP is not available. Use bridge mode for XDP functionality.

## Troubleshooting

### XDP Not Loading

```bash
# Check kernel config
zcat /proc/config.gz | grep -E "CONFIG_NET_XDP|CONFIG_BPF"
# Required: CONFIG_NET_XDP=y, CONFIG_NET_XDP_XMIT=y, CONFIG_BPF=y

# Check interface capabilities
ip link show eth0
# Should show: xdp or xdp/generic if loaded

# Check daemon logs
journalctl -u https-guard-daemon -l | grep -i xdp
```

### Uprobe Not Firing

```bash
# Verify OpenSSL library path
ls -la /usr/lib/libssl.so.3

# Check if uprobe is registered
bpftool prog list | grep ssl_write

# Enable debug logging
journalctl -u https-guard-daemon -f
# Look for: "https_guard: uprobe hit pid=..."

# Test with openssl s_client
openssl s_client -connect localhost:443
```

### Build Failures

```bash
# Clean and rebuild
bitbake https-guard-openbmc -c clean
bitbake https-guard-openbmc

# Check for missing dependencies
bitbake -e https-guard-openbmc | grep ^DEPENDS

# Verify kernel vmlinux exists
ls -la tmp/work/*/linux-*/build/vmlinux
```

### Event Bridge Not Dispatching

```bash
# Check bridge service status
systemctl status https-guard-event-bridge

# Verify log file exists
ls -la /var/log/https_guard_events.log

# Test bridge manually
/usr/sbin/https-guard-event-bridge
# Should output: "Bridge started, monitoring /var/log/https_guard_events.log"
```

**No Redfish push arriving at a subscriber, even though the daemon/bridge logs show events:**
Verified on `johnblue`: this bmcweb build dispatches EventService push notifications
via its `filesystem_log_watcher` on `HTTPS_GUARD_REDFISH_LOG`
(`/var/log/redfish`), *not* via D-Bus `Logging.Create` entries. All event
modes (`dbus`/`journal`/`both`) now write to this file — if you're on an
older checkout where `dbus`/`both` skip it, events will never reach a
subscriber.

Also observed: this watcher delivers accumulated log content to a
subscriber as a batch **at subscribe time**, rather than reliably streaming
each new line the instant it's appended. If a subscription has been open
for a while and new events aren't showing up, try re-subscribing (or
restart `listener.py`, which re-subscribes on startup) to force a
catch-up flush.

## Development

For detailed source code documentation, event struct layouts, and the security strategy deep-dive, see [DESIGN.md](DESIGN.md), or [DESIGN.html](DESIGN.html) for a diagram-first version of the same material.

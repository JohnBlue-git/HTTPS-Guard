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
│  │  │ ring_buffer__poll()                                │  │  │
│  │  │   → find owning IHookModule, parseEvent()          │  │  │
│  │  │     → PID→socket (ProcPeerResolver, uprobe only)   │  │  │
│  │  │   → run detectors_[source] → Verdict               │  │  │
│  │  │     • TlsVersionDetector (< TLS 1.2)                │  │  │
│  │  │     • PayloadAnomalyDetector (SQLi/traversal)       │  │  │
│  │  │   → Enforcement actions (if actionable):           │  │  │
│  │  │       • LogAction (file write, always)             │  │  │
│  │  │       • BlockTcpAction (SOCK_DESTROY)              │  │  │
│  │  │       • BlocklistAddAction (BPF map update)        │  │  │
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
├── scripts/qemu-setup-tap.sh         # Host bridge / TAP / NAT setup for QEMU testing
└── manifest/main.xml                 # Repo manifest
```

### Component roles

The source under `files/` is organized around the **Detect → Classify → Dispatch** pipeline, one top-level directory per stage:

| Component | Path | Role |
|-----------|------|------|
| **Detect** | `programs/` | Attaches BPF hooks and parses their raw events. `ssl_uprobe/` (uprobe on `SSL_write()`, PRIMARY) and `xdp_tls/` (XDP ClientHello inspection + blocklist enforcement, AUXILIARY) each implement the `IHookModule` interface; `core/` holds the generic BPF lifecycle wrapper and the orchestrator (`HttpGuardProgram`) that dispatches between them |
| **Classify** | `detectors/` | Pure classification rules behind `IDetector`: `tls_version/` (TLS-version-violation check) and `payload_anomaly/` (SQLi/path-traversal signatures), run through a registry keyed by which hook produced the event |
| **Dispatch** | `actions/` | Three async countermeasures run through `ActionLoop`: `log/` (file write), `tcp/` (SOCK_DESTROY via Netlink), `blocklist/` (BPF map update) |
| **Tests** | `tests/` | doctest-based unit tests for the `detectors/` layer — no kernel/BPF/root/QEMU dependency |
| **Event bridge** | `service/https-guard-event-bridge.sh` | Shell script that tails the event log and forwards entries to D-Bus and/or the Redfish filesystem log |

> For per-file documentation, build system internals, event struct layouts, and security strategy deep-dives, see [DESIGN.md](DESIGN.md). Per-hook detection rationale and diagrams live in `programs/ssl_uprobe/DESIGN.md` and `programs/xdp_tls/DESIGN.md`.

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
PACKAGECONFIG:pn-https-guard-openbmc ?= "simulation event-both"
```

**Service selection** — which systemd services get built/enabled (pick one):

| Flag | Effect |
|------|--------|
| `simulation` (default) | Enables `simulated-event-generator`, disables the real eBPF daemon. No kernel eBPF/XDP or BPF toolchain required — good for a first QEMU boot. |
| `daemon` | Enables the real `https-guardd` (uprobe + optional XDP), disables the simulator. Requires a kernel with `CONFIG_BPF`/`CONFIG_UPROBE_EVENTS` (and `CONFIG_NET_XDP` for XDP). |
| `both` | Enables both, for comparing real vs. simulated events side by side. |

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
sudo ./meta-https-guard/scripts/qemu-setup-tap.sh destroy
sudo ./meta-https-guard/scripts/qemu-setup-tap.sh create
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
# specific hook combination (see programs/core/HttpGuardProgram.cpp).
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

| Message ID | Severity | Description |
|------------|----------|-------------|
| `OemSecurityEvent.1.0.HttpsTlsVersionViolation` | Critical | TLS version < 1.2 detected |
| `OemSecurityEvent.1.0.HttpsPayloadAnomalyDetected` | Warning | Attack signature in HTTP payload |
| `OemSecurityEvent.1.0.HttpsTrafficObserved` | OK | Normal HTTPS traffic observed |

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

# HTTPS-Guard for OpenBMC

HTTPS-Guard is an eBPF-based network security observability and enforcement tool for OpenBMC. It detects TLS version violations and HTTP anomalies in real-time, then takes automated countermeasures through a hybrid kernel/userspace architecture.

## Table of Contents

- [What is HTTPS-Guard?](#what-is-https-guard)
- [Architecture Overview](#architecture-overview)
- [Source Code Structure](#source-code-structure)
- [Building HTTPS-Guard](#building-https-guard)
- [QEMU Configuration](#qemu-configuration)
  - [Bridge Mode (Recommended for XDP)](#bridge-mode-recommended-for-xdp)
  - [SLIRP Mode (Default, Uprobe-Only)](#slirp-mode-default-uprobe-only)
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
│  │  │   → on_event()                                     │  │  │
│  │  │     → Classify event (event_type, severity)        │  │  │
│  │  │     → Anomaly detection (pattern_detector)         │  │  │
│  │  │     → PID→socket (ProcPeerResolver)                │  │  │
│  │  │     → Enforcement actions:                         │  │  │
│  │  │       • LogAction (file write)                     │  │  │
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

## Source Code Structure

### Layer layout

```
meta-https-guard/
├── conf/machine/johnblue.conf        # QEMU AST2600 machine definition (networking modes)
├── recipes-https-guard/https-guard/  # Main recipe + all C++/eBPF source
│   ├── https-guard-openbmc.bb        # BitBake recipe (build flags, install, PACKAGECONFIG)
│   └── files/                        # Source tree — see recipes README for full details
├── recipes-kernel/linux/             # Kernel BPF/XDP config fragment
├── recipes-bmcweb/bmcweb/            # bmcweb OemSecurityEvent schema append
├── scripts/qemu-setup-tap.sh         # Host bridge / TAP / NAT setup for QEMU testing
└── manifest/main.xml                 # Repo manifest
```

### Component roles

The source under `files/` is split into five components:

| Component | Path | Role |
|-----------|------|------|
| **eBPF programs** | `https_guard/https_guard.bpf.c` | Uprobe on `SSL_write()` captures TLS version + payload; XDP inspects ClientHello and enforces the blocklist |
| **C++ daemon** (`https-guardd`) | `https_guard/` | Loads the BPF object, polls the ring buffer, classifies events, resolves PID→socket, dispatches actions |
| **Enforcement actions** | `actions/` | Three async countermeasures: `LogAction` (file write), `BlockTcpAction` (SOCK_DESTROY via Netlink), `BlocklistAddAction` (BPF map update) |
| **BPF wrapper** | `ebpf/` | RAII wrapper for BPF program load / attach / detach lifecycle |
| **Event bridge** | `https-guard-event-bridge.sh` | Shell script that tails the event log and forwards entries to D-Bus and/or the Redfish filesystem log |

> For per-file documentation, build system internals, event struct layouts, and security strategy deep-dives, see [recipes-https-guard/https-guard/README.md](recipes-https-guard/https-guard/README.md).

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

### Build Outputs

- **Daemon binary:** `tmp/deploy/images/<machine>/https-guard-openbmc/usr/sbin/https-guardd`
- **BPF object:** `tmp/deploy/images/<machine>/https-guard-openbmc/usr/share/https-guard/https_guard.bpf.o`
- **Systemd units:** Installed to `/usr/lib/systemd/system/`

## QEMU Configuration

### Bridge Mode (Recommended for XDP)

Bridge mode exposes a real network interface to the guest, enabling XDP support. This works on all platforms:
- **AST2600 (johnblue)**: Uses built-in ftgmac100 (emulated hardware NIC)
- **x86_64/aarch64**: Uses virtio-net-device (paravirtualized, better performance)

**Key Point:** Bridge mode is a **host-side** configuration. The host doesn't care about the guest's architecture - it just passes Ethernet frames via a TAP device. The guest uses its native driver (ftgmac100 for AST2600, virtio-net for x86/ARM64).

**Setup on host (one-time):**

```bash
# Use the helper script
sudo ./meta-https-guard/scripts/qemu-setup-tap.sh destroy
sudo ./meta-https-guard/scripts/qemu-setup-tap.sh create
```

**For AST2600 (johnblue):**

The `ast2600-evb` machine's ftgmac100 NIC looks up `nd_table[0]` for its network backend. `-net nic,netdev=net0` creates that `nd_table` entry pointing at the TAP (it is NOT creating an extra NIC — the machine consumes the entry for its first ftgmac100, which appears as `eth0` in the guest).

```bash
QB_NET=none runqemu johnblue nographic \
  qemuparams='-netdev tap,id=net0,ifname=tap-httpsguard,script=no,downscript=no -net nic,netdev=net0'
```

**Verify XDP is working inside guest:**

```bash
# Check daemon logs
journalctl -u https-guard-daemon -l | grep "XDP attached"
# Expected: "https_guard: XDP attached in native mode"

# Verify XDP program loaded
ip link show eth0 | grep -i xdp
# Expected: "xdp" in output
```

**Test connectivity from host:**

```bash
# Ping the guest
ping -c 3 192.168.200.2

# Test HTTPS access
curl -k https://192.168.200.2/redfish/v1
```

### SLIRP Mode (Default, Uprobe-Only)

SLIRP is the default QEMU networking mode. It uses user-mode networking and does **not** expose a real NIC to the guest.

**Launch QEMU with SLIRP (default):**

```bash
runqemu johnblue nographic slirp
```

**Characteristics:**
- ✅ Easy to use, no host setup required
- ✅ Uprobe detection works perfectly
- ❌ No XDP support (no real netdev)
- ❌ No promiscuous mode
- ❌ Limited to user-mode networking

**Verify uprobe-only mode:**

```bash
journalctl -u https-guard-daemon -l | grep "enforcement active"
# Expected: "https_guard: enforcement active via uprobe(SSL_write)"
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

SLIRP provides neither. For XDP functionality on AST2600, use bridge mode with ftgmac100 as described in the [Bridge Mode](#bridge-mode-recommended-for-xdp) section above.

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
{"@odata.type":"#Event.v1_7_0.Event","Name":"Platform Security Anomaly Event","Id":"1234567890","Events":[{"EventId":"evt-1234567890","Severity":"Critical","MessageId":"OemSecurityEvent.1.0.0.HttpsTlsVersionViolation","Message":"Security violation: Process 'curl' (PID 12043) attempted insecure TLS version (TLS 1.0). Packet was blocked.","MessageArgs":["curl","12043","TLS 1.0"],"EventTimestamp":"2024-01-15T10:30:45Z","OriginOfCondition":{"@odata.id":"/redfish/v1/Managers/bmc"}}]}
```

### Event Message IDs

| Message ID | Severity | Description |
|------------|----------|-------------|
| `OemSecurityEvent.1.0.0.HttpsTlsVersionViolation` | Critical | TLS version < 1.2 detected |
| `OemSecurityEvent.1.0.0.HttpsPayloadAnomalyDetected` | Warning | Attack signature in HTTP payload |
| `OemSecurityEvent.1.0.0.HttpsTrafficObserved` | Informational | Normal HTTPS traffic observed |

### Subscribe to Events via Redfish

```bash
# Using curl to subscribe to events
curl -k -u root:0penBmc \
  -X POST https://localhost/redfish/v1/EventService/Subscriptions \
  -H "Content-Type: application/json" \
  -d '{
    "Destination": "http://client:8080/events",
    "Protocol": "Redfish",
    "EventTypes": ["Alert"]
  }'

# Query existing subscriptions
curl -k -u root:0penBmc \
  https://localhost/redfish/v1/EventService/Subscriptions

# View events via SSE (bridge mode: guest IP direct)
curl -k -N --https1.0 -u root:0penBmc \
  -H "Accept: text/event-stream" \
  https://192.168.200.2/redfish/v1/EventService/SSE/

# View events via SSE (SLIRP mode: host-forwarded port)
curl -k -N --https1.0 -u root:0penBmc \
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
| QEMU SLIRP | ftgmac100 (emulated) | ✅ | ❌ | ❌ | Uprobe-only |
| QEMU TAP+BRIDGE | virtio-net-* | ✅ | ✅ | ✅ | Full support |
| x86_64 (native) | ixgbe, mlx5, etc. | ✅ | ✅ | ✅ | Full support |

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

## Development

For detailed source code documentation, see:
- [recipes-https-guard/https-guard/README.md](recipes-https-guard/https-guard/README.md) - Complete code walkthrough
- [recipes-https-guard/https-guard/SECURITY_STRATEGY.md](recipes-https-guard/https-guard/SECURITY_STRATEGY.md) - Security model deep-dive

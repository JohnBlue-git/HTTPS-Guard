# HTTPS-Guard for OpenBMC

HTTPS-Guard is an eBPF-based network security observability and enforcement tool for OpenBMC. It detects TLS version violations and HTTP anomalies in real-time, then takes automated countermeasures through a hybrid kernel/userspace architecture.

## Table of Contents

- [What is HTTPS-Guard?](#what-is-https-guard)
- [Architecture Overview](#architecture-overview)
- [Directory Structure](#directory-structure)
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

## Directory Structure

```
meta-https-guard/
├── README.md                                    # This file
├── conf/
│   └── machine/
│       └── johnblue.conf                        # QEMU machine configuration
└── recipes-https-guard/
    └── https-guard/
        ├── README.md                            # Detailed source code documentation
        ├── SECURITY_STRATEGY.md                 # Security model deep-dive
        ├── https-guard-openbmc.bb               # BitBake recipe
        └── files/
            ├── CMakeLists.txt                   # Build system
            ├── https-guard.conf                 # Runtime configuration
            ├── https-guard-daemon.service       # systemd unit
            ├── https-guard-daemon.sh            # Daemon launcher
            ├── https-guard-event-bridge.service # Event bridge unit
            ├── https-guard-event-bridge.sh      # Redfish event dispatcher
            ├── simulated-event-generator.service
            ├── simulated-event-generator.sh
            ├── scripts/
            │   └── gen_ssl_offset.c             # Build-time offset detector
            ├── https_guard/
            │   ├── events.h                     # Shared event structs
            │   ├── https_guard.bpf.c            # eBPF programs
            │   ├── https_guard_program.hpp/cpp  # BPF loader + classifier
            │   ├── main.cpp                     # Daemon entry point
            │   ├── pattern_detector.hpp         # Anomaly rules
            │   ├── proc_peer_resolver.hpp       # PID→socket resolver
            │   ├── redfish_event_message.hpp    # Redfish formatting
            │   └── tls_version.hpp              # TLS version helpers
            ├── actions/
            │   ├── core/
            │   │   ├── ActionLoop.hpp/cpp       # Async dispatcher
            │   │   └── main.cpp                 # Test harness
            │   ├── blocklist/
            │   │   ├── blocklist.bpf.h          # BPF blocklist check
            │   │   ├── Blocklist.hpp/cpp        # BPF map wrapper
            │   │   ├── BlocklistAction.hpp/cpp  # Add IP to blocklist
            │   │   └── BlocklistAction.hpp/cpp
            │   ├── tcp/
            │   │   ├── BlockTcpAction.hpp/cpp   # TCP teardown
            │   │   └── TcpDestroyer.hpp/cpp     # Netlink SOCK_DESTROY
            │   └── log/
            │       ├── async_mutex.hpp          # Coroutine-safe I/O
            │       ├── LogAction.hpp/cpp        # File logger
            │       └── LogAction.hpp/cpp
            └── ebpf/
                ├── bpf_program.hpp/cpp          # BPF attachment wrapper
```

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

Bridge mode exposes a real network interface to the guest, enabling XDP support. This is required for XDP functionality.

**Setup on host (one-time):**

```bash
# Create TAP interface
sudo ip tuntap add dev tap-httpsguard mode tap user $(whoami)
sudo ip link set tap-httpsguard up

# Create bridge
sudo ip link add name br-httpsguard type bridge
sudo ip link set br-httpsguard up

# Attach TAP to bridge
sudo ip link set tap-httpsguard master br-httpsguard

# Optional: Attach host interface to bridge for external connectivity
# sudo ip link set eth0 master br-httpsguard
```

**Launch QEMU with bridge mode:**

```bash
# Set network options
export QB_NETWORK_OPTION='-netdev tap,id=net0,ifname=tap-httpsguard,script=no,downscript=no -device virtio-net-pci,netdev=net0,mac=52:54:00:12:34:56'

# Run QEMU
runqemu johnblue nographic qemuparams="$QB_NETWORK_OPTION"
```

**Verify XDP is working inside guest:**

```bash
# Check daemon logs
journalctl -u https-guard-daemon -l | grep "XDP attached"
# Expected: "https_guard: XDP attached in generic (SKB) mode"

# Verify XDP program loaded
ip link show eth0 | grep -i xdp
# Expected: "xdp/generic" or "xdp" in output
```

### SLIRP Mode (Default, Uprobe-Only)

SLIRP is the default QEMU networking mode. It uses user-mode networking and does **not** expose a real NIC to the guest.

**Launch QEMU with SLIRP (default):**

```bash
runqemu johnblue nographic
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

SLIRP provides neither.

**Workaround:** Use bridge mode (described above) for XDP functionality.

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

Edit `/etc/default/https-guard`:

```bash
# Event sink mode: dbus, journal, or both
HTTPS_GUARD_EVENT_MODE=both

# Network interface
HTTPS_GUARD_INTERFACE=eth0

# OpenSSL library path
HTTPS_GUARD_SSL_LIB=/usr/lib/libssl.so.3

# Output log path
HTTPS_GUARD_OUTPUT=/var/log/https_guard_events.log
```

## Monitoring Redfish Events

### Event Log Location

Events are written to `/var/log/redfish/https_guard_events.log` in JSON format:

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

# View events
curl -k -u root:0penBmc \
  https://localhost/redfish/v1/EventService/Events
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
| ASpeed AST2600 (johnblue) | ftgmac100 | ✅ | ❌ | ❌ | Uprobe-only |
| QEMU SLIRP | ftgmac100 (emulated) | ✅ | ❌ | ❌ | Uprobe-only |
| QEMU TAP+BRIDGE | virtio-net-pci | ✅ | ✅ | ✅ | Full support |
| x86_64 (native) | ixgbe, mlx5, etc. | ✅ | ✅ | ✅ | Full support |

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

## License

MIT License - See LICENSE file for details

## Contributing

Contributions welcome! Please submit pull requests or issues to the OpenBMC project.
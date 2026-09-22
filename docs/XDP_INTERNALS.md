# XDP Internals and Network Data Flow

XDP is an optional detection and enforcement path. `ssl_uprobe` remains the primary hook because it sees decrypted TLS and HTTP inside OpenSSL; XDP sees packets before the TCP and TLS stacks finish processing them.

## The traditional path

Without XDP, a received packet follows the normal network stack:

```text
NIC RX
  |
  v
netdev driver -> skb allocation -> GRO/IP/TCP -> socket receive queue
                                      |
                                      v
                              OpenSSL / bmcweb
                                      |
                                      v
                              SSL_read / SSL_write uprobe
                                      |
                                      v
                            HTTPS-Guard DetectLoop
```

The uprobe has protocol context, but it is after packet processing and only sees plaintext at the OpenSSL boundary.

## XDP modes

XDP runs at the earliest hook exposed by the selected mode. The program can return `XDP_DROP`, `XDP_PASS`, or another XDP action.

### Offloaded (hardware)

```text
NIC hardware parser
  |
  +-- XDP_DROP: packet never reaches the host
  |
  +-- XDP_PASS: packet is delivered to the host NIC path
```

The NIC executes the program. This is the lowest CPU-cost mode, but requires hardware and driver support for XDP offload. HTTPS-Guard does not assume it.

### Native (driver, or DRV mode)

```text
NIC RX -> driver ndo_bpf/XDP hook -> skb allocation -> kernel network stack
             |
             +-- XDP_DROP
             +-- XDP_PASS
```

Native XDP runs in the driver before the normal `skb` path. `ndo_bpf` is a `struct net_device_ops` driver callback used to configure BPF/XDP on a network device. It is not a syscall hook, uprobe, kprobe, or tracepoint. Kernel version alone cannot prove native support: the specific NIC driver must implement the callback and accept the requested XDP mode.

### Generic (SKB mode)

```text
NIC RX -> driver -> skb allocation -> generic XDP hook -> IP/TCP -> socket
                                      |
                                      +-- XDP_DROP
                                      +-- XDP_PASS
```

Generic XDP works without a native driver implementation, but it pays for the normal `skb` setup first. It is useful as a compatibility fallback and is slower than native mode.

Generic XDP is not guaranteed to be faster than TC. Both paths work with an
`skb` in software, and the result depends on where the kernel invokes each
hook, how much packet parsing the program performs, whether TC can use useful
`skb` metadata, and whether the TC path is hardware-offloaded. Benchmark the
actual program and interface when throughput or latency matters.

The daemon attempts the supported native path and then generic mode. The startup log records which mode attached. Failure of both is non-fatal because the uprobe path can still run.

## TC comparison

TC, or Linux traffic control, attaches BPF programs to a qdisc rather than to
the earliest receive point. With `cls_bpf` and ingress, the packet has already
become an `skb`:

```text
NIC RX -> driver -> skb allocation -> ingress qdisc / cls_bpf
                 |
          +------------+------------+
          |                         |
        TC_ACT_SHOT                TC_ACT_OK
        drop packet             continue to IP/TCP
                     |
                     v
                 socket / OpenSSL / bmcweb
```

TC can also run on egress, after the protocol stack has produced an `skb`:

```text
socket / TCP -> egress qdisc / cls_bpf -> driver -> NIC TX
           |
        +--------+--------+
        |                 |
      TC_ACT_SHOT        TC_ACT_OK
    drop packet       continue to wire
```

The ingress and egress hooks make TC useful for traffic shaping, packet
marking, redirecting, and policy that needs an `skb` or a later network-stack
context. `TC_ACT_SHOT` is the usual drop result. TC is not the same as native
XDP: it does not run before `skb` allocation, and it is configured through a
qdisc/classifier rather than through the NIC driver's XDP callback.

### XDP versus TC

| Property | XDP | TC `cls_bpf` |
|---|---|---|
| First receive point | Driver/native XDP can run before `skb` allocation; generic XDP runs after it | Ingress qdisc after `skb` allocation, or egress qdisc before transmission |
| Main return/action | `XDP_DROP`, `XDP_PASS`, redirect, or transmit | `TC_ACT_SHOT`, `TC_ACT_OK`, redirect, mark, or pipe |
| Driver dependency | Native and offloaded modes depend on NIC support; generic mode does not | Does not require native XDP support, but requires TC/qdisc support |
| Context | Small packet-level context such as `xdp_md`; direct packet bounds checks are required | `__sk_buff` context with metadata available after `skb` creation |
| Typical strength | Earliest possible drop, high packet-rate filtering, redirect | Shaping, marks, ingress/egress policy, and richer `skb` metadata |
| Cost | Native/offloaded mode avoids host `skb` work; generic mode pays for `skb` first and is not automatically cheaper than TC | Software TC pays for `skb` creation and qdisc/classifier work; hardware-offloaded TC can change the comparison |
| HTTPS-Guard role | Auxiliary ClientHello hints, counters, and synchronous blocklist enforcement | Not currently used by HTTPS-Guard |

The choice is not simply "XDP is newer than TC." Use native or offloaded XDP
when the decision can be made from packet bytes and the earliest possible drop
matters. Use TC when the policy needs `skb` metadata, ingress/egress placement,
qdisc integration, packet marks, or a driver that cannot provide native XDP.
Generic XDP and software TC should be treated as competing software paths,
not as a fixed speed ranking: a simple TC classifier can beat a generic-XDP
program that performs expensive parsing, while a minimal generic-XDP drop can
beat a TC path that pays substantial qdisc and classifier overhead. A TC
program can be a useful fallback for a new policy, but it does not provide the
same earliest-drop position as native XDP.

### Measure instead of assuming

As with `bpftool` (see [LIMITATIONS.md](LIMITATIONS.md#tooling-no-bpftool-on-the-target-and-it-will-not-build-for-arm32)),
do not assume `tc` or `ethtool` are on the BMC image either: this recipe's
only runtime dependency is `bash systemd`, and the target's shipped
networking tool is BusyBox's `ip`, not full iproute2. Check with
`command -v tc`/`command -v ethtool` first, or run the commands below from a
bridged/TAP host where they can be installed freely.

Compare the same policy in both paths on the same interface and kernel. Record
packet rate, CPU usage, drops, and latency while testing clean traffic and
traffic that actually matches the rule:

```sh
ip -s link show dev eth0
tc -s filter show dev eth0 ingress
sudo bpftool net list
pidstat -p "$(pidof https-guardd)" 1
```

For a useful comparison, keep the parser and rule equivalent, warm up both
paths, and repeat with different packet sizes. Do not compare native XDP with
software TC and call the result a generic-XDP comparison; the receive position
and amount of host work are different.

### Why HTTPS-Guard uses XDP instead of TC

`xdp_tls` needs to inspect the first packets of a connection and apply a
source-address blocklist before the packet proceeds through the host stack.
That makes XDP's early receive position and direct `XDP_DROP` result the right
fit. The daemon already has a generic-XDP fallback when native XDP is
unavailable, so adding TC would introduce another attachment and lifecycle
path without improving the primary enforcement decision.

TC remains relevant when a future rule needs socket or `skb` metadata, egress
filtering, packet marking, or traffic shaping. Such a rule should document
whether it attaches at ingress or egress, whether it needs `clsact`, and how
its qdisc ownership coexists with the system's existing network policy.

### Minimal TC capability check

On a disposable interface, confirm that the TC infrastructure exists without
assuming native XDP support:

```sh
tc qdisc show dev eth0
tc filter show dev eth0 ingress
tc filter show dev eth0 egress
sudo tc qdisc add dev eth0 clsact
sudo tc qdisc show dev eth0
sudo tc qdisc del dev eth0 clsact
```

Attaching a BPF classifier additionally requires a compatible object and
`CONFIG_NET_CLS_BPF`/`CONFIG_NET_ACT_BPF` support. `clsact` creation alone
proves only that the qdisc path is available; it does not prove that a
particular BPF program will load or attach.

## What this project can observe

`xdp_tls` parses the ClientHello and plaintext HTTP that is visible on port 443 at the wire. It feeds TLS-version, payload, cipher-suite, SNI, and rate-sweep detections. The shared XDP blocklist is checked synchronously before userspace classification; an actionable userspace verdict updates that map for later packets.

The XDP path cannot see decrypted HTTP after TLS encryption. That is why the uprobe and XDP detections overlap only for fields available at their respective boundaries.

## Checking SLIRP or another test backend

Do not infer XDP support from the QEMU networking label alone. Check the actual attach result:

```sh
journalctl -u https-guard-daemon | grep -iE 'xdp|attach|enforcement active'
cat /sys/class/net/eth0/ifindex
ip -details link show dev eth0
```

For this layer, the definitive test is to run the daemon and read whether `xdp_tls` attached in native or generic mode. A SLIRP backend is not a physical NIC and cannot provide hardware offload; a QEMU emulated netdev may nevertheless accept a native or generic XDP attach. Record the mode, not just "XDP enabled". See [LIMITATIONS.md](LIMITATIONS.md) for the current platform boundary and [DEBUGGING.md](DEBUGGING.md) for attach-stage diagnosis.

## Checking a driver for `ndo_bpf`

On the target, identify the interface and its driver:

```sh
netdev=eth0
readlink -f /sys/class/net/$netdev/device/driver
ethtool -i "$netdev"
```

Same caveat as above: don't assume `ethtool` is on the BMC image. `readlink -f
.../driver` needs no extra tool and works on-target either way.

On a host with the kernel source tree, inspect the driver’s `net_device_ops` initializer:

```sh
grep -RIn 'ndo_bpf' drivers/net drivers/net/ethernet
```

Then inspect the callback implementation and the driver’s XDP mode checks. A matching symbol in an unrelated driver is not evidence for the target device. The runtime attach result remains the final check, because a driver may implement `ndo_bpf` but reject a program, mode, or device state.

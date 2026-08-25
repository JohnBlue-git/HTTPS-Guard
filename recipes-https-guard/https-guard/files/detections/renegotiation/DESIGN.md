# TLS renegotiation storm

**Emits:** `OemSecurityEvent.1.0.HttpsTlsRenegotiationStorm` (Warning) ·
**Enforces:** yes.

## Why detect this

A TLS handshake is **asymmetrically expensive**: the server does key-exchange and
signature work far exceeding what the client spends asking for it. Driving
handshakes in a loop is therefore a cheap way to consume a BMC's very limited CPU
— the AST2600 is not a server-class part — without generating traffic volume that
looks like a flood.

That asymmetry is what separates this from
[`conn_rate`](../conn_rate/DESIGN.md). A source can stay well under any
connection-rate threshold while renegotiating continuously on connections it
already holds.

### Where the numbers come from

`programs/xdp_tls/ebpf/conn_rate.bpf.h` holds an `LRU_HASH` keyed on source
address, updated from two points in the XDP program:

```
inbound SYN (no ACK), BEFORE the port-443 filter
    ├─ syn_count   += 1      WINDOWED  → conn_rate
    └─ open_conns  += 1      LEVEL     → slowloris

FIN or RST
    └─ open_conns  -= 1      LEVEL     (floored at zero)

TLS handshake record (ContentType 0x16)
    └─ hello_count += 1      WINDOWED  → renegotiation
```

Three things there are deliberate:

- **LRU, not a plain hash.** A hash keyed on source address *is itself* a DoS vector: a spoofed-source flood fills it and inserts start failing. LRU bounds the memory and evicts the least recently seen source, which under a distributed flood is the entry least worth keeping.
- **SYNs are counted before the port filter.** A port scan targets ports other than 443 by definition, so counting after the filter would make the thing worth detecting invisible.
- **The BPF side draws no conclusion and drops nothing.** It only counts.

`ConnRateSweeper` reads the map every 2 seconds and synthesises one event per
detection per offending source. These detections therefore have **no
`IDetection`** and never reach `submit()` — there is no ring-buffer record for a
counter crossing a threshold.

### Why the threshold decision is in userspace

Counting has to be per-packet, so it belongs in BPF. The threshold does not, and
that split is the point.

A rate signal is far more false-positive-prone than a wire-format check. A
malformed ClientHello is malformed; "20 connections a second" might be a
monitoring system, a busy dashboard opening parallel requests, or several
administrators behind one NAT address. Deciding in BPF would mean a second
synchronous `XDP_DROP` path where a mistuned threshold drops legitimate traffic
at line rate with nothing in the loop to catch it — and making cipher-suite
detection actionable already locked an operator out of SSH once.

It also means the counters need no BPF→userspace event channel at all, which
avoided both bolting rate fields onto `xdp_event` and changing the hook interface
so one hook could emit several event kinds.

## How to detect

`hello_count` increments where the XDP program sees a TLS record with
`ContentType == 0x16` (handshake). **Windowed**, like the connection-rate count
and unlike Slowloris: handshake load is a rate, and a source that stops
renegotiating has stopped costing anything.

## How to protect

Actionable: blocklist the source, and Tier 1 drops the rest. No TCP teardown —
the verdict names an address, not a socket.

`HTTPS_GUARD_RENEG_THRESHOLD` defaults to 200 handshakes per 10s window. **0
disables the detection.**

## What to hook

`xdp_tls` maintains the counters; `ConnRateSweeper` polls them.

## Limits worth knowing

- **Verified live at a lowered threshold, not at the shipped default.** The trigger sends its `0x16` handshake records down *one* connection (a storm is many handshakes on a single connection, not one connection each), which is also what survives SLIRP's per-connection loss. bmcweb RSTs the malformed record stream after ~3 records, so one connection delivers ~3 countable records regardless of how many are sent — enough to cross a threshold of 2 (fires; full enforcement and a measured 326s lockout), never the shipped 200. Recipe and status in [README.md](../../../../../README.md#exercising-the-detections); the SLIRP ceiling in [LIMITATIONS.md](../../../../../LIMITATIONS.md).
- Attributed to an address, not a socket.
- Only the monitored interface is counted.

## How to trigger it

See [README.md § Exercising the Detections](../../../../../README.md#exercising-the-detections)
for the runnable recipe and this detection's live-verification status.

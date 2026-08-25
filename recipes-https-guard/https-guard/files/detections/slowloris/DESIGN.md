# Slowloris

**Emits:** `OemSecurityEvent.1.0.HttpsSlowlorisDetected` (Warning) ·
**Enforces:** yes.

## Why detect this

Slowloris exhausts a server's connection pool without volume: open many
connections, send a byte occasionally, never complete a request. Against a BMC —
with a small pool and no capacity to spare — it is unusually effective, and
unusually invisible, because every individual connection looks legitimate and the
traffic rate looks like nothing at all.

That last part is what makes it a separate detection from
[`conn_rate`](../conn_rate/DESIGN.md): a Slowloris attacker sits comfortably under
any connection-rate threshold.

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

## How to detect: a level, not a rate

This is the one counter that must **survive the window roll**, and that
distinction is the whole design.

A Slowloris attacker opens connections and then goes deliberately quiet. Against
a windowed counter that attacker looks *idle* — which is precisely the outcome
the attack is engineered to produce. So `open_conns` tracks a standing level:
SYNs minus FIN/RSTs, per source, carried across window boundaries.

**Floored at zero**, because closes can legitimately outnumber the SYNs this hook
observed — a connection predating the map entry, or a FIN *and* an RST for one
connection — and a negative level would read as innocent forever afterwards.

**Why not measure connection duration.** That would need per-connection state in
BPF and a notion of "too long" that depends on client behaviour. The standing
count needs neither, and makes duration implicit: connections that complete
promptly decrement the level, so a source only accumulates if it is *holding*
them.

**Re-reported only when the level climbs.** A source sitting on its connections
is still a problem, but logging it every 2s sweep would bury everything else.

## How to protect

Actionable: the source is blocklisted, and Tier 1 drops its subsequent packets.
No TCP teardown — the verdict names an address, not a socket, so there is no
4-tuple to destroy.

`HTTPS_GUARD_SLOWLORIS_THRESHOLD` defaults to 100 concurrent connections. **0
disables the detection.** Like the rate threshold this is safety-critical rather
than cosmetic, because the verdict enforces.

## What to hook

`xdp_tls` maintains the counters; `ConnRateSweeper` polls them. Nothing hooks
this detection directly.

## Limits worth knowing

- Attributed to an address, not a socket.
- Only the monitored interface is counted.
- **Verified live once at a lowered threshold** (5 connections against a limit of 3), never at the shipped default of 100. **Not reliably reproducible through a QEMU SLIRP hostfwd:** the original run reached 5 held connections, but a later re-measurement saw only ~1 of 3–8 held host connections arrive as guest-side `open_conns` — SLIRP does not forward held connections to the guest consistently, and how many arrive is environment/timing/version-dependent. Exercise this rule on a real netdev or a bridged/TAP network for a dependable result. See [README.md](../../../../../README.md#exercising-the-detections).

## How to trigger it

See [README.md § Exercising the Detections](../../../../../README.md#exercising-the-detections)
for the runnable recipe and this detection's live-verification status.

# Connection-rate violation

**Emits:** `OemSecurityEvent.1.0.HttpsConnectionRateViolation` (Warning) ·
**Enforces:** yes.

## Why detect this

A BMC has a small connection budget and a slow CPU. Volumetric abuse does not
need to be sophisticated to take the management interface away — and taking the
management interface away is often the *point*, because it removes the operator's
ability to see or fix whatever else is happening.

This also catches port scanning, which is why SYNs are counted before the
port-443 filter: a scan targets other ports by definition.

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

## How to protect

The verdict is actionable, so the source is blocklisted — and from then on Tier 1
drops its packets at line rate, which is the same two-tier flow a TLS-version
violation uses.

**No TCP teardown**, and that is not an omission: a rate violation is attributed
to an *address*, not a socket. There is no local endpoint and no ports, so asking
netlink to destroy a zero tuple produced a guaranteed `-ENOENT` and a misleading
failure line. `dispatchVerdict()` checks for a full 4-tuple first.

The cost of keeping the decision in userspace is that enforcement waits for the
next sweep rather than acting on the offending packet. For *sustained* abuse —
which is what this detects — that is immaterial: once the source is blocklisted,
the remainder is dropped in the kernel.

### Window and threshold

The window is **fixed at 10s at build time**
(`HTTPS_GUARD_CONN_RATE_WINDOW_SEC`) because it is structural: it decides how
much memory a burst can occupy and how the counter resets. Changing it needs a
rebuild — a real limitation, not an oversight.

The threshold is the policy knob (`HTTPS_GUARD_RATE_THRESHOLD`) because "abusive"
is deployment-dependent. The shipped default of **500 per 10s** was measured, not
guessed: idle 0, ordinary polling 20, aggressive parallel burst 60 — roughly 8x
headroom, while a real flood runs to thousands.

**0 disables the detection**, and 0 is the value when nothing is configured, so
this cannot start enforcing against real traffic on the strength of a default
nobody chose.

## What to hook

`xdp_tls` maintains the counters; nothing hooks *this* detection directly.
`ConnRateSweeper` polls the map from `DetectLoop`'s timer thread — see
[`detections/DESIGN.md`](../DESIGN.md) for why that timer is off the record
strand.

## Limits worth knowing

- **Only the monitored interface is counted.** Loopback never traverses XDP, so BMC-to-itself connections are invisible.
- **Clients behind one NAT address share the budget.** Several busy administrators can look like one abusive source.
- **Changing the window needs a rebuild.**

## How to trigger it

See [README.md § Exercising the Detections](../../../../../README.md#exercising-the-detections)
for the runnable recipe and this detection's live-verification status.

# Rate sweep: connection rate, Slowloris, renegotiation storm

**Emits:**
- `OemSecurityEvent.1.0.HttpsConnectionRateViolation` (Warning) — connection rate
- `OemSecurityEvent.1.0.HttpsSlowlorisDetected` (Warning) — Slowloris
- `OemSecurityEvent.1.0.HttpsTlsRenegotiationStorm` (Warning) — renegotiation storm

**Enforces:** yes, all three.

## Why one DESIGN.md for three rules

All three read the same `LRU_HASH`, counted by the same two points in
`xdp_tls`'s XDP program, aggregated by the one `ConnRateSweeper` (in
`core/engine/`, not in this directory — see "What runs this" below). They
differ only in *which field* of the counter each rule reads and how that field
behaves (a window that resets vs. a level that survives one), so their
rationale, their data source and their handshake diagram are identical. Where
they differ — the threshold, the enforcement note, the live-verification
status — gets its own subsection below.

Each rule is still its own type (`ConnRateEvent`/`ConnRateDetector`,
`SlowlorisEvent`/`SlowlorisDetector`, `RenegotiationEvent`/`RenegotiationDetector`)
and its own file: sharing a directory and a design doc is not sharing an event
type, and one rule cannot read another's counter by construction — see
`detections/CLAUDE.md`.

## Why detect these

A BMC has a small connection budget and a slow CPU. Volumetric abuse does not
need to be sophisticated to take the management interface away — and taking the
management interface away is often the *point*, because it removes the
operator's ability to see or fix whatever else is happening. Three different
shapes of abuse sit comfortably under each other's threshold, which is why
this is three rules and not one:

- **Connection rate** catches a flood or a port scan: many SYNs, fast. This also catches port scanning, which is why SYNs are counted before the port-443 filter — a scan targets other ports by definition.
- **Slowloris** catches the opposite shape: open many connections, then go quiet. A Slowloris attacker stays comfortably under any connection-rate threshold, and the traffic rate looks like nothing at all — every individual connection looks legitimate.
- **Renegotiation storm** exploits the asymmetry of the TLS handshake: the server does key-exchange and signature work far exceeding what the client spends asking for it, so a source can stay well under any connection-rate threshold while renegotiating continuously on connections it already holds.

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

### Where this sits in the handshake

```
Client                                                             bmcweb (server)
  │                                                                      │
  ├── TCP SYN ─────────────────────────────────────────────────────────▶│
  │◀──────────────────────────────────────────────────────── SYN-ACK ───┤
  ├── ACK ─────────────────────────────────────────────────────────────▶│
  │                    (TCP handshake complete; no TLS yet)              │
  │                                                                      │
  ├── ClientHello (0x16, unencrypted) ─────────────────────────────────▶│
  │      legacy_version · cipher_suites[] · extensions (incl. SNI)       │
  │◀── ServerHello, Certificate, ... (0x16) ────────────────────────────┤
  ├── Finished (0x16) ─────────────────────────────────────────────────▶│
  │◀── Finished (0x16) ─────────────────────────────────────────────────┤
  │              (TLS handshake complete; ssl->version now set)          │
  │                                                                      │
  ├── application data, e.g. an HTTP request ──────────────────────────▶│
  │◀── application data, e.g. an HTTP response ─────────────────────────┤
  │                                                                      │
  ├── TCP FIN or RST ──────────────────────────────────────────────────▶│
```

- **Connection rate** — the very first line: the inbound SYN, before the port-443 filter and before anything TLS-shaped exists on the connection at all. Counting any later point in this diagram would make a port scan invisible.
- **Slowloris** — not one point but the span between the SYN and the FIN/RST at the top and bottom of this diagram: `open_conns` increments at the first line and decrements at the last, regardless of how much or how little happens in between. A Slowloris connection is exactly the case where nothing in the middle ever happens at all.
- **Renegotiation storm** — every `0x16`-marked message in this diagram: the initial handshake's own messages, and any handshake-type record sent afterward on a connection that already completed one. `hello_count` does not distinguish an initial handshake from a repeated one; it counts the message type, not the connection's state, which is why the trigger recipe can drive this by resending `0x16` records rather than performing genuine renegotiations.

`ConnRateSweeper` reads the map every 2 seconds and evaluates all three rules
against each offending source. These detections therefore have **no
`IDetection`** and never reach `submit()` — there is no ring-buffer record for
a counter crossing a threshold.

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
avoided both bolting rate fields onto `xdp_event` and changing the hook
interface so one hook could emit several event kinds.

## How to detect, per rule

**Connection rate** is windowed, exactly like the handshake count and unlike
Slowloris: a burst of SYNs is a rate, and a source that stops connecting has
stopped costing anything.

**Renegotiation storm** is windowed the same way: `hello_count` increments
where the XDP program sees a TLS record with `ContentType == 0x16` (handshake).
Handshake load is a rate, and a source that stops renegotiating has stopped
costing anything.

**Slowloris is the one counter that must survive the window roll**, and that
distinction is its whole design. A Slowloris attacker opens connections and
then goes deliberately quiet. Against a windowed counter that attacker looks
*idle* — precisely the outcome the attack is engineered to produce. So
`open_conns` tracks a standing level: SYNs minus FIN/RSTs, per source, carried
across window boundaries.

- **Floored at zero**, because closes can legitimately outnumber the SYNs this hook observed — a connection predating the map entry, or a FIN *and* an RST for one connection — and a negative level would read as innocent forever afterwards.
- **Why not measure connection duration.** That would need per-connection state in BPF and a notion of "too long" that depends on client behaviour. The standing count needs neither, and makes duration implicit: connections that complete promptly decrement the level, so a source only accumulates if it is *holding* them.
- **Re-reported only when the level climbs.** A source sitting on its connections is still a problem, but logging it every 2s sweep would bury everything else. Connection-rate and renegotiation instead re-report once per *window*, since a windowed counter resets on its own.

## How to protect

All three are actionable: the source is blocklisted, and Tier 1 drops its
subsequent packets at line rate — the same two-tier flow a TLS-version
violation uses.

**No TCP teardown for any of the three**, and that is not an omission: each
verdict is attributed to an *address*, not a socket — there is no local
endpoint and no ports, so asking netlink to destroy a zero tuple produced a
guaranteed `-ENOENT` and a misleading "SOCK_DESTROY failed" line.
`dispatchVerdict()` checks for a full 4-tuple first, and none of these three
ever have one.

The cost of keeping the decision in userspace is that enforcement waits for
the next sweep rather than acting on the offending packet. For *sustained*
abuse — which is what all three of these detect — that is immaterial: once the
source is blocklisted, the remainder is dropped in the kernel.

**0 disables a rule**, independently per rule (`ConnRateSweeper::Thresholds`
carries one field each), and 0 is the value used when nothing is configured —
so none of the three can start enforcing against real traffic on the strength
of a default nobody chose.

### Window and threshold, per rule

| | Window | Default threshold | Config var |
|---|---|---|---|
| Connection rate | fixed 10s at build time (`HTTPS_GUARD_CONN_RATE_WINDOW_SEC`) | 500 per 10s | `HTTPS_GUARD_RATE_THRESHOLD` |
| Slowloris | none — a level, not a window | 100 concurrent connections | `HTTPS_GUARD_SLOWLORIS_THRESHOLD` |
| Renegotiation storm | same fixed 10s window | 200 handshakes per 10s | `HTTPS_GUARD_RENEG_THRESHOLD` |

The window is fixed at build time because it is structural: it decides how
much memory a burst can occupy and how the counter resets. Changing it needs a
rebuild — a real limitation, not an oversight. The threshold is the policy
knob because "abusive" is deployment-dependent. The connection-rate default
was measured, not guessed: idle 0, ordinary polling 20, aggressive parallel
burst 60 — roughly 8x headroom, while a real flood runs to thousands. Slowloris
and renegotiation-storm thresholds are safety-critical in the same way: too
low, and a legitimate client (a websocket-heavy dashboard holding many
connections; a monitoring system polling briskly) gets blocklisted.

## What runs this

`xdp_tls` maintains the counters. `ConnRateSweeper` — in `core/sweep/`, not
here — polls the map every 2 seconds from `DetectLoop`'s timer, evaluates
whichever of these three rules is over its threshold, and dispatches directly.
It lives under `core/` rather than in this directory because it is pipeline
machinery that drives three rules, the same relationship `core/engine/`'s
`DetectLoop` has to `IDetection` — not a fourth rule of its own. See
[`detections/DESIGN.md`](../DESIGN.md) for why its timer runs off the record
strand, and `core/sweep/ConnRateSweeper.hpp` for why `sweep()` is a coroutine
despite nothing in it awaiting anything yet.

Nothing hooks any of these three detections directly — there is no
`IDetection` implementation for any of them.

## Limits worth knowing

- **Only the monitored interface is counted.** Loopback never traverses XDP, so BMC-to-itself connections are invisible, for all three.
- **Clients behind one NAT address share the budget**, for all three.
- **Changing the window needs a rebuild**, for connection rate and renegotiation storm.
- **Attributed to an address, not a socket**, for all three — see "How to protect" above.
- **`SlowlorisDetector`** — verified live once at a **lowered** threshold (5 connections against a limit of 3), never at the shipped default of 100. **Not reliably reproducible through a QEMU SLIRP hostfwd:** the original run reached 5 held connections, but a later re-measurement saw only ~1 of 3–8 held host connections arrive as guest-side `open_conns` — SLIRP does not forward held connections to the guest consistently, and how many arrive is environment/timing/version-dependent. Exercise this rule on a real netdev or a bridged/TAP network for a dependable result.
- **`RenegotiationDetector`** — verified live at a **lowered** threshold, not at the shipped default. The trigger sends its `0x16` handshake records down *one* connection (a storm is many handshakes on a single connection, not one connection each), which is also what survives SLIRP's per-connection loss. bmcweb RSTs the malformed record stream after ~3 records, so one connection delivers ~3 countable records regardless of how many are sent — enough to cross a threshold of 2 (fires; full enforcement and a measured 326s lockout), never the shipped 200.

See [LIMITATIONS.md](../../../../../LIMITATIONS.md) for the SLIRP ceiling in full.

## How to trigger it

See [README.md § Exercising the Detections](../../../../../README.md#exercising-the-detections)
for the runnable recipes (`trigger_detections.py rate`, `slowloris`,
`renegotiation`) and each rule's live-verification status.

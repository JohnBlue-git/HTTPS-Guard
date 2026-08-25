# `BlocklistAddAction` — teaching the kernel to drop

**What it does:** writes a source address and an absolute expiry into a BPF map
that the XDP program reads on every packet.

**Why it is the most consequential action here:** it is the one that closes the
loop between asynchronous detection and synchronous defence — and the one whose
blast radius has caused a real outage.

## The feedback loop

```
   Tier 1 (synchronous, kernel, µs)          Tier 2 (asynchronous, userspace, ms)
   ────────────────────────────────          ────────────────────────────────────
   packet arrives
     └─ blocklist_check(saddr)
          ├─ hit, unexpired ──▶ XDP_DROP     a verdict says actionable
          │                                    └─ BlocklistAddAction
          └─ miss ──▶ inspect, submit  ...        └─ writes saddr + expiry ──┐
                                                                            │
          ◀───────────────────────────────────────────────────────────────────┘
          the NEXT packet from that source is dropped before it costs anything
```

Tier 1 can only drop what it already knows about. Tier 2 is the only path that
can teach it something new. Neither is sufficient alone, which is the whole
argument for the two-tier model — see the top-level `DESIGN.md`.

## The map

`src_ip_v4` (network byte order) → absolute expiry in nanoseconds, in a BPF hash
of `HTTPS_GUARD_BLOCKLIST_MAX_ENTRIES`. `blocklist_check()` does the lookup,
compares against `bpf_ktime_get_ns()`, and prunes stale entries opportunistically
as it goes — so expiry costs nothing extra and there is no sweeper for it.

Storing an **absolute expiry** rather than a TTL is what makes that possible: the
kernel side needs no notion of when the entry was written.

`Blocklist::adopt()` hands the map fd from `HttpGuardProgram` to this layer once
the object is loaded. If adoption fails the daemon says so and continues in pure
observational mode — non-fatal, because losing a countermeasure is better than
losing detection.

## The blast radius, which is the thing to understand

**The blocklist applies to a source address on every port, not just 443.** XDP
sits before the stack; it has no idea which service a packet was headed for. So
an actionable verdict against a false positive removes *all* access to the BMC —
SSH, IPMI, Redfish — for the blocklist TTL (300s by default).

That is not theoretical. Making cipher-suite detection actionable during
development blocklisted the peer address on a single crafted ClientHello and
instantly cut off the SSH session running the test. On a real BMC, one scanner
packet or one legacy tool behind a shared NAT address would lock out every
administrator sharing that address.

It is why the enforce/alert split exists, and why it is a property of each
detection rather than a global setting:

- `cipher_suite` and `sni` fire on a handshake bmcweb refuses anyway — the offer does no damage, so alerting is proportionate.
- `tls_version`, `payload_anomaly` and the three counter detections describe live or ongoing harm, so they enforce — which makes their thresholds safety-critical rather than tuning details.

## Always the peer, never us

`dispatchVerdict()` passes `meta.remote_ip_v4`, and the naming in `EventMeta` is
by **role** (`local_`/`remote_`) rather than by direction specifically to keep
that unambiguous. Under the old `src_`/`dst_` names the two hooks took opposite
frames of reference — the uprobe read `/proc`'s local address into `src_`, while
the XDP ingress hook put the packet's sender there — so uprobe-sourced events
blocklisted **the BMC's own address**.

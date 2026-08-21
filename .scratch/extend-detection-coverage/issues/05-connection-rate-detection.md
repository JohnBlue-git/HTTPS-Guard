# 05 — Connection-rate / SYN-flood / port-scan detection

**What to build:** Stateful, per-source-IP tracking of connection attempts over a time window, catching volumetric abuse (SYN floods, port scanning, general connection-rate abuse) that today's single-packet classification has no way to see. The natural fit is a BPF-side `LRU_HASH` map keyed on source IP with a packet/SYN counter, checked at the same point `blocklist_check()` already runs in `xdp_tls.bpf.h` — both are "is this source already a problem" checks at the same point in the packet path.

**Blocked by:** 01 — Extend the OEM security event message registry

**Status:** done

- [x] A BPF map tracks per-source-IP connection/packet counts over a rolling or fixed time window, sized to bound memory use under real abuse (an unbounded per-IP map is itself a DoS vector)
- [x] Crossing a threshold produces a Warning-or-Critical verdict using ticket 01's new message ID, and results in the same enforcement path other actionable verdicts use (BlockTcpAction/BlocklistAddAction) — a source confirmed abusive here should end up in the same blocklist `blocklist_check()` reads, same as a confirmed TLS-version violation does today
- [x] The threshold(s) are configurable (via `https-guard.conf` or an equivalent mechanism), not hardcoded, since "abusive rate" is deployment-dependent
- [x] Whether the threshold decision happens synchronously in BPF (like `is_violation`) or is deferred to a userspace detector reading the counters is this ticket's call — document which was chosen and why
- [x] Unit tests cover the counting/threshold logic in isolation against synthetic input, independent of whether the real counters live in a BPF map
- [x] Manually verified that legitimate traffic patterns (a normal Redfish client polling routinely) don't cross the chosen threshold

## Comments

### The decision this ticket asked me to make: BPF counts, userspace decides

Counting is per-packet so it must be in BPF (`conn_rate.bpf.h`, an
`LRU_HASH` keyed on source address — LRU rather than a plain hash because a
plain hash keyed on source *is itself* a DoS vector once a spoofed-source
flood fills it). The threshold decision is deliberately not in BPF:

- A rate signal is far more false-positive-prone than the wire-format checks
  this program already makes. Deciding in BPF means a second synchronous
  `XDP_DROP` path, so a mistuned threshold drops legitimate traffic at line
  rate with nothing in the loop to catch it. Making cipher-suite and SNI
  detection actionable already locked an operator out of SSH once.
- Keeping it in userspace means the counters need no BPF→userspace event
  channel at all: the daemon sweeps the map and synthesises a
  `ConnRateEvent`. That avoids bolting rate fields onto `xdp_event` (the god
  object ticket 15 just removed) or changing `IHookModule` so one hook can
  emit several event kinds.

Cost: enforcement waits for the next sweep (2s) instead of acting on the
offending packet. Immaterial for *sustained* abuse, which is what this
detects — once blocklisted, `blocklist_check()` drops the remainder at line
rate, reusing the existing two-tier flow rather than inventing a third.

SYNs are counted **before** the port-443 filter, since a port scan targets
other ports by definition and counting after that filter would make the
thing we want to detect invisible.

### Actionable, unlike cipher-suite and SNI — deliberately

Those fire on a handshake bmcweb refuses anyway: the offer does no damage, so
alerting is proportionate. A flood or scan is ongoing harm, so an alert that
does not stop it is close to useless. That makes the threshold
safety-critical rather than a tuning detail, which is why it is configurable
and why the default was measured rather than picked.

### The default, from measurement

| Scenario | Inbound connections / 10s |
|---|---|
| Idle | 0 |
| Ordinary Redfish polling (2 req/s) | 20 |
| Aggressive parallel dashboard burst | 60 |

Shipped default: **500 per 10s** — about 8x headroom over the heaviest
legitimate load observed, while a flood or scan runs to thousands. The config
file records these numbers and the NAT caveat (clients behind one address
share the budget).

### Two real bugs this ticket surfaced

**1. Sweep starvation under load — introduced here.** The first version swept
only when the event queue was empty after a timed wait. A flood generates
ring-buffer events, so the queue is never empty while one is in progress, and
the sweep would not run until traffic stopped — by which time the counting
window had rolled and the evidence was gone. Rate detection that switches
itself off under load is worse than none, because it looks present. Now swept
on a clock at the top of the loop regardless of queue state.

**2. Enforcement gate regression — introduced back in ticket 11.** The
actionable branch was gated on `evt.ensurePeerResolved() && remote_ip_v4 != 0`.
Any event that already knows its own address carries no resolver, so
`ensurePeerResolved()` returned false and enforcement was skipped entirely —
for **XDP events as well as rate events**. It hid because the only
enforcement verified live was a uprobe payload anomaly (which does have a
resolver), and the one actionable XDP rule needs a legacy-TLS client that was
never exercised end to end. Now resolves if possible and gates on whether an
address is actually present. Pinned by a regression test.

Also: `BlockTcpAction` is now skipped when there is no full 4-tuple. A rate
violation is attributed to an address, not a socket, so asking netlink to
destroy a zero tuple produced a guaranteed `-ENOENT` and a misleading
"SOCK_DESTROY failed" line.

### Verification

53/53 unit tests under ASan/UBSan, including the zero-threshold boundary
(0 means disabled, not "everything violates" — the most consequential
boundary in the class).

Live on QEMU:
- **No false positives:** the heaviest legitimate load, repeated, produced
  zero violations at the shipped default.
- **True positive, end to end:** with the threshold lowered to make it
  reachable in an emulated environment, 12 connections in one window produced
  `Connection-rate violation from 10.0.2.2: 12 connection attempts in 10s
  exceeds the configured threshold of 5`, a `blocklisted 10.0.2.2 for 300s`
  action, and `HttpsConnectionRateViolation` in the Redfish log — and it cut
  off the test's own SSH session, which recovered when the TTL expired. The
  lockout is the enforcement working.
- Uprobe teardown still works after the 4-tuple guard.

The observability line (`conn_rate: N source(s) tracked, busiest M
attempt(s)`) was added while debugging and kept: without it the only way to
choose a threshold is to guess and watch for lockouts. It is throttled to
once per 10s.

**Environment limit worth stating:** QEMU SLIRP will not propagate a rapid
connect/close burst to the guest, so the highest count reachable from the
host was ~456 in 6s — just under the shipped default. The true-positive test
therefore used a lowered threshold. On real hardware a flood exceeds 500
trivially; the mechanism is what was verified, not the specific number.

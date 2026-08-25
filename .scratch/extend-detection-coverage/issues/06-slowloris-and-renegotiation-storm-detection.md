# 06 — Slowloris and TLS-renegotiation-storm detection

**What to build:** Two detection rules that both need cross-event, time-windowed state — something no existing `IDetector` implementation does today: Slowloris (many connections held open, trickling data slowly enough to exhaust bmcweb's connection pool without ever completing a request) and TLS renegotiation storms (repeated ClientHellos from one source over a short window). Resolve the architecture question below *before* writing detection logic — it affects both rules identically, so it's this ticket's first deliverable, not a side effect of implementing either one.

**Blocked by:** 01 — Extend the OEM security event message registry

**Status:** done — both rules now verified live at lowered thresholds; slowloris only intermittently reproducible through SLIRP (see Verification)

- [x] **Resolve the stateful-detector question first.** Every existing `IDetector::evaluate` is `const` and touches nothing but the one `hg_event` it's given — that's what makes it trivially unit-testable and safe to run inline in the ring-buffer callback. Slowloris and renegotiation-storm detection both need to remember something *across* events (connection duration; ClientHello count per source over a window). Decide, and write down the reasoning: does `IDetector` grow a stateful variant (a non-`const evaluate`, or an internal mutable cache guarded appropriately for the daemon's threading model), or does a new, explicitly-stateful sibling interface exist alongside it so the existing contract's purity guarantee isn't quietly broken for every detector? Check the answer against `detectors/CLAUDE.md`'s stated intent for `IDetector` before committing to it.
- [x] Connection-duration tracking (for Slowloris) is implemented using whatever mechanism the resolved architecture calls for, keyed per-connection (source IP + port, at minimum)
- [x] ClientHello-per-source-IP-per-window tracking (for renegotiation storms) is implemented the same way
- [x] Crossing either threshold produces the corresponding Warning-or-Critical verdict from ticket 01's new message IDs, through the existing enforcement path
- [x] Both thresholds/windows are configurable, not hardcoded
- [x] Unit tests cover both rules' state-transition logic directly (e.g. "N ClientHellos within window W triggers, N-1 does not"), independent of whether the real state lives in a BPF map or in the userspace daemon
- [x] State doesn't grow unbounded under sustained attack — old/expired per-source entries get pruned, the same way `blocklist_check()` already prunes expired blocklist entries

## Architecture decision (this ticket's first deliverable)

**Neither option offered. `IDetector` stays pure and stateless; the state
lives outside it.**

The ticket framed this as a choice between growing `IDetector` a stateful
variant or adding an explicitly-stateful sibling interface. Both would give
up something the codebase depends on. `detections/core/IDetector.hpp` and
`detections/CLAUDE.md` both state the contract in the same terms — "pure,
synchronous classification rules… no I/O, no BPF/socket access" — and that
purity is what makes every detector unit-testable with a hand-built event and
safe to call from anywhere in the pipeline. Weakening it for two rules would
weaken it for all seven.

There is a third shape, and ticket 05 already proved it: **hold the state in a
BPF map, aggregate it in a sweeper, and synthesise an event carrying the
aggregate.** `ConnRateDetector` needs cross-event counting and yet has zero
mutable members — it reads `attemptCount()` and `threshold()` off the event it
is handed. The counting lives in an `LRU_HASH`; `ConnRateSweeper` reads it on
a timer and manufactures the event.

Both rules here fit that shape without modification:

| Rule | State needed | Where it lives |
|---|---|---|
| Renegotiation storm | ClientHellos per source per window | windowed counter in the same per-source map |
| Slowloris | connections held open per source | a *level* (incremented on SYN, decremented on FIN/RST), not a windowed count |

So this ticket adds counters to the existing per-source map and two more pure
detectors. No interface changes, no mutable detectors, no locking to reason
about, and the unit tests stay what the ticket asked for — "N within window W
triggers, N-1 does not" — expressed directly against a synthesised event.

The one wrinkle worth stating: the Slowloris counter is a level rather than a
rate, so it must *not* reset when the window rolls. That is the only reason
the per-source state struct now distinguishes windowed fields from
non-windowed ones.

## Implementation

Both rules are counters on the per-source map ticket 05 introduced, read by
the same sweeper, classified by two more **stateless** detectors. No
interface change, no mutable detector, no locking.

| Rule | Signal | Reset behaviour |
|---|---|---|
| Connection rate | inbound SYNs | windowed |
| Renegotiation storm | TLS handshake records | windowed |
| Slowloris | SYNs minus FIN/RST — connections held open | **level; survives the window roll** |

The Slowloris counter deliberately does not reset with the window: the attack
works by occupying slots and then going quiet, so a windowed count would show
an active attacker as idle. It is floored at zero, because closes can
legitimately outnumber observed SYNs (connections predating the entry, or a
FIN and an RST for the same connection) and a negative level would read as
innocent forever after.

Rather than track duration per connection as the ticket suggested, the
signal is the standing count of held-open connections per source. It needs no
per-connection state at all, and duration is implicit — connections that
complete promptly decrement the level, so only ones held open accumulate.

**Deviation worth noting:** the renegotiation counter increments on any TLS
handshake record (ContentType 0x16), not specifically a ClientHello.
Distinguishing message types would mean parsing before the packet's bounds
have been established, and a renegotiation storm is characterised by repeated
handshakes regardless of which side initiates.

All three rules share `HG_SOURCE_CONN_RATE` and rely on first-match-wins
being safe: the sweeper emits a different concrete event per rule, each
carrying only its own capability, so the other detectors see an event without
their capability and decline. A test pins that they do not poach each other's
events.

## Verification

59/59 unit tests under ASan/UBSan, including the boundaries the ticket asked
for — N triggers and N-1 does not, for both rules — plus zero-threshold-means-
disabled and the no-poaching property.

**Slowloris: verified end to end on QEMU.** Five connections held open
against a limit of three produced

```
BlocklistAddAction: blocklisted 10.0.2.2 for 300s reason=Possible Slowloris
from 10.0.2.2: 5 connections held open exceeds the configured limit of 3.
```

with `HttpsSlowlorisDetected` in the Redfish log. `BlockTcpAction` was
correctly skipped — a Slowloris verdict is attributed to an address, not a
single socket — so no misleading `SOCK_DESTROY failed` line was emitted.

**Update — slowloris not reliably reproducible through SLIRP.** A later
re-measurement in the same SLIRP setup could *not* reproduce the 5-held-open
result above: holding 3 connections gave `open_conns=1`, and holding 8 gave
`open_conns=0` with just 1 SYN reaching the guest. SLIRP does not forward held
host connections to the guest consistently, so how many arrive is
environment/timing/version-dependent. The original run happened, but treat
SLIRP slowloris as unreliable — a real netdev or bridged/TAP network is the
dependable way to exercise it.

**Renegotiation storm: verified live at a lowered threshold.** The original
attempt failed because it tried to drive handshakes by holding connections
open (which saturates the forward). The insight that fixed it: a renegotiation
storm is many handshakes on *one* connection, so the trigger now sends its
`0x16` records down a single kept-alive socket. bmcweb RSTs the malformed
stream after ~3 records, so one connection delivers ~3 countable records
regardless of `--count` — enough to cross a threshold of 2, which fired with
full enforcement and a measured 326s lockout (never the shipped 200). Still
unit-tested besides. The SLIRP ceiling is recorded in `LIMITATIONS.md`.

**Environment finding worth keeping:** holding as few as five connections
open through QEMU SLIRP hostfwd saturates the forward and breaks SSH on the
same forward. "SSH dropped" is therefore *not* usable as evidence of
blocklisting in this environment — it was initially misread that way here.
The journal is the reliable signal.

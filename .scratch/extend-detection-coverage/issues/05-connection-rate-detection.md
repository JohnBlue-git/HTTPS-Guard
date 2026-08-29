# 05 — Connection-rate / SYN-flood / port-scan detection

**What to build:** Stateful, per-source-IP tracking of connection attempts over a time window, catching volumetric abuse (SYN floods, port scanning, general connection-rate abuse) that today's single-packet classification has no way to see. The natural fit is a BPF-side `LRU_HASH` map keyed on source IP with a packet/SYN counter, checked at the same point `blocklist_check()` already runs in `xdp_tls.bpf.h` — both are "is this source already a problem" checks at the same point in the packet path.

**Blocked by:** 01 — Extend the OEM security event message registry

**Status:** ready-for-agent

- [ ] A BPF map tracks per-source-IP connection/packet counts over a rolling or fixed time window, sized to bound memory use under real abuse (an unbounded per-IP map is itself a DoS vector)
- [ ] Crossing a threshold produces a Warning-or-Critical verdict using ticket 01's new message ID, and results in the same enforcement path other actionable verdicts use (BlockTcpAction/BlocklistAddAction) — a source confirmed abusive here should end up in the same blocklist `blocklist_check()` reads, same as a confirmed TLS-version violation does today
- [ ] The threshold(s) are configurable (via `https-guard.conf` or an equivalent mechanism), not hardcoded, since "abusive rate" is deployment-dependent
- [ ] Whether the threshold decision happens synchronously in BPF (like `is_violation`) or is deferred to a userspace detector reading the counters is this ticket's call — document which was chosen and why
- [ ] Unit tests cover the counting/threshold logic in isolation against synthetic input, independent of whether the real counters live in a BPF map
- [ ] Manually verified that legitimate traffic patterns (a normal Redfish client polling routinely) don't cross the chosen threshold

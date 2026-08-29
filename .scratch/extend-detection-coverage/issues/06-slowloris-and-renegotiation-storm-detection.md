# 06 — Slowloris and TLS-renegotiation-storm detection

**What to build:** Two detection rules that both need cross-event, time-windowed state — something no existing `IDetector` implementation does today: Slowloris (many connections held open, trickling data slowly enough to exhaust bmcweb's connection pool without ever completing a request) and TLS renegotiation storms (repeated ClientHellos from one source over a short window). Resolve the architecture question below *before* writing detection logic — it affects both rules identically, so it's this ticket's first deliverable, not a side effect of implementing either one.

**Blocked by:** 01 — Extend the OEM security event message registry

**Status:** ready-for-agent

- [ ] **Resolve the stateful-detector question first.** Every existing `IDetector::evaluate` is `const` and touches nothing but the one `hg_event` it's given — that's what makes it trivially unit-testable and safe to run inline in the ring-buffer callback. Slowloris and renegotiation-storm detection both need to remember something *across* events (connection duration; ClientHello count per source over a window). Decide, and write down the reasoning: does `IDetector` grow a stateful variant (a non-`const evaluate`, or an internal mutable cache guarded appropriately for the daemon's threading model), or does a new, explicitly-stateful sibling interface exist alongside it so the existing contract's purity guarantee isn't quietly broken for every detector? Check the answer against `detectors/CLAUDE.md`'s stated intent for `IDetector` before committing to it.
- [ ] Connection-duration tracking (for Slowloris) is implemented using whatever mechanism the resolved architecture calls for, keyed per-connection (source IP + port, at minimum)
- [ ] ClientHello-per-source-IP-per-window tracking (for renegotiation storms) is implemented the same way
- [ ] Crossing either threshold produces the corresponding Warning-or-Critical verdict from ticket 01's new message IDs, through the existing enforcement path
- [ ] Both thresholds/windows are configurable, not hardcoded
- [ ] Unit tests cover both rules' state-transition logic directly (e.g. "N ClientHellos within window W triggers, N-1 does not"), independent of whether the real state lives in a BPF map or in the userspace daemon
- [ ] State doesn't grow unbounded under sustained attack — old/expired per-source entries get pruned, the same way `blocklist_check()` already prunes expired blocklist entries

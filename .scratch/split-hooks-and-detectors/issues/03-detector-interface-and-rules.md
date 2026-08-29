# 03 — Extract the detector interface and the two existing detection rules, with unit tests

**What to build:** Turn the TLS-version-violation check and the payload-pattern/anomaly check into standalone classes behind one common detector interface, run through a central per-event-source registry built in the daemon's entry point, replacing the inline classification currently in the ring-buffer handler. Preserve today's exact evaluation order and priority. Add unit tests for both rules.

**Blocked by:** 01 — Scaffold the new module layout and multi-layer build; 02 — Stand up a minimal unit-test framework and build target

**Status:** done

- [x] A common detector interface exists: given the daemon's common event representation, a detector may inspect it and, on a match, fill in its classification (severity, message, actionability) and report that it matched
- [x] The TLS-version-violation check and the payload-pattern/anomaly check are each implemented as standalone classes behind that interface, with no BPF/socket/action-dispatch knowledge inside them
- [x] A central registry maps each event source to its ordered list of applicable detectors, constructed in the daemon's entry point
- [x] The ring-buffer handler runs the registered detectors for an event's source, stopping at the first match, and falls back to today's "traffic observed" classification when none match — with today's exact priority (TLS-version check before payload-anomaly check) preserved
- [x] Unit tests cover both detectors: a clearly-violating input, a clearly-clean input, and the documented boundary condition (e.g. the exact TLS version threshold)
- [x] The daemon's end-to-end classification output is unchanged versus pre-refactor for the same inputs

## Comments

Built test-first (TDD, per /implement's instruction to use it at the pre-agreed seam): `IDetector::evaluate(hg_event&)`. Both detectors ended up with 2 boundary cases each rather than 1 — `TlsVersionDetector` covers both the threshold (0x0303 exactly) and the tls_version==0 sentinel (no data observed, not a violation), `PayloadAnomalyDetector` covers case-insensitivity and empty payload — since both were real edge cases already baked into the original logic that a refactor could easily get wrong. 9/9 test cases, 19/19 assertions pass, verified for real with g++ directly against the fetched doctest.h (no cmake in the implementing sandbox).

Also moved `hg_event.hpp` from `programs/core/` to `detectors/core/` (not called out in ticket 01) — it was about to create a circular dependency (`programs_lib` already links `detectors_lib`; detectors needing `hg_event.hpp` from `programs/core` would have required the reverse link too). `hg_event` is genuinely the classify-layer's central vocabulary type, so this is where it belongs.

Verified the XDP path's `is_violation` field and the unified `TlsVersionDetector` produce identical verdicts by tracing the BPF-side logic (both are only ever set together, both stay 0 together) — this was the main risk in unifying the two previously-separate classification branches, and it checks out.

**Correction (found by `/code-review`'s Spec-axis pass in ticket 04's commit):** the claim above was wrong for one case. `is_violation = (tls_ver < 0x0303) ? 1 : 0` in `xdp_tls.bpf.h` has no `tls_ver > 0` guard, so a genuinely-parsed wire `legacy_version` of `0x0000` sets `is_violation=1` — but `TlsVersionDetector`'s `tls_version == 0` early-exit (correct for the uprobe path, where 0 only ever means "unread") silently suppressed this for XDP, since `XdpTlsProgram::parseEvent` never carried `is_violation` into `hg_event` at all. Fixed by adding `hg_event.tls_violation_hint` (set by `XdpTlsProgram`, defaulted false elsewhere) and having `TlsVersionDetector` OR it into the check, plus a regression test for exactly this input. See the fix commit for detail.

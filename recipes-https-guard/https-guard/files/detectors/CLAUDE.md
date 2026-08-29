# detectors/ — Classify layer

Pure, synchronous classification rules. A detector answers one question — "does this already-parsed event match my rule?" — and nothing else: no I/O, no BPF/socket access, no enforcement, no knowledge of which hook produced the event. That's `../programs/` (parsing) and `../actions/` (dispatch) respectively.

## Layout

- **`core/`**
  - `IDetector.hpp` — `virtual std::optional<Verdict> evaluate(const hg_event& evt) const = 0;`. Takes `hg_event` by `const&` and never mutates it — a detector's whole output is the `Verdict` it returns (or `nullopt`).
  - `hg_event.hpp` — the common parsed-event representation both `programs/` and `actions/` also depend on. Deliberately has *no* classification fields (no severity/message/actionable) — those live only in `Verdict`. It lives here, not in `programs/`, specifically to avoid a circular library dependency (`programs_lib` already links `detectors_lib`).
  - `Verdict.hpp` — `{severity, message_id, message, actionable}`. What a detector decided, never what was observed.
- **`tls_version/`** — `TlsVersionDetector` (flags TLS < 1.2) + `tls_version.hpp` (the `TlsVersion` numeric→string helper it alone uses).
- **`payload_anomaly/`** — `PayloadAnomalyDetector` (SQLi / path-traversal / attack-signature substrings, case-insensitive).
- **`cert_access/`** — `CertAccessDetector` (flags `hg_event.cert_identity_mismatch`, set by `programs/lsm_cert_guard/`'s userspace-side `/proc/<pid>/exe` check — not actionable, since there's no TCP 4-tuple to blocklist for a local file access and any in-kernel enforcement already happened, or didn't, before this detector ever ran).

No `shared/` bucket — each subdirectory here is named after the one detector it owns, the same "one directory per concern" rule `programs/` follows for hooks. If a future rule genuinely needs to share logic with an existing one, that shared piece earns its own subdirectory under `core/` rather than reviving a generic `shared/`.

## The registry, and why `tls_violation_hint` exists

`HttpGuardProgram::DetectorRegistry` (defined in `programs/core/HttpGuardProgram.hpp`, built in `programs/core/main.cpp`) maps each `hg_event_source` to an *ordered* list of detectors — first match wins, no match falls back to an inline "OK, traffic observed" `Verdict` (not itself a detector; there's nothing to detect in that case).

`hg_event.tls_violation_hint` is the one field on the shared event that exists purely to prevent a specific class of bug: `xdp_tls`'s BPF side already computes a synchronous `is_violation` verdict from the wire (see its own `CLAUDE.md`), and that's a *stronger* signal than `TlsVersionDetector`'s own `tls_version` re-derivation can produce on its own — a genuinely-parsed `legacy_version` of `0x0000` is a real violation there, not "no data," which `tls_version == 0` alone would wrongly conclude. `SslUprobeProgram` never sets this hint (its BPF side makes no such determination), so `TlsVersionDetector`'s zero-check still applies there. This shipped as a real bug once (caught by `/code-review`, not by the implementer) — if you're writing a detector that spans hooks with different BPF-side classification power, look for whether you need an equivalent hint before assuming a single field means the same thing everywhere.

## Testing

`../tests/test_detectors.cpp` covers both existing detectors: a clearly-violating input, a clearly-clean input, and each rule's real boundary conditions (the exact TLS threshold, the `tls_violation_hint` override, case-insensitivity, empty input). This is the one seam in the whole project explicitly designed to be testable without a kernel, root, or QEMU — a new detector should get the same treatment before it's considered done.

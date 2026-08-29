# detections/ — Classify layer

Pure, synchronous classification rules. A detector answers one question — "does this already-parsed event match my rule?" — and nothing else: no I/O, no BPF/socket access, no enforcement, no knowledge of which hook produced the event. That's `../programs/` (parsing) and `../actions/` (dispatch) respectively.

## Layout

- **`core/`**
  - `IDetector.hpp` — `virtual std::optional<Verdict> evaluate(const hg_event& evt) const = 0;`. Takes `hg_event` by `const&` and never mutates it — a detector's whole output is the `Verdict` it returns (or `nullopt`).
  - `hg_event.hpp` — the common parsed-event representation both `programs/` and `actions/` also depend on. Deliberately has *no* classification fields (no severity/message/actionable) — those live only in `Verdict`. It lives here, not in `programs/`, specifically to avoid a circular library dependency (`programs_lib` already links `detections_lib`).
  - `Verdict.hpp` — `{severity, message_id, message, actionable}`. What a detector decided, never what was observed.
This directory holds the pipeline engine and **every** classification rule, one subdirectory per rule family — including rules that only one hook can currently feed. Placement deliberately does not depend on which hook supplies the data: making it depend on that meant reasoning about hypothetical future hooks every time a rule was added, and it is exactly the kind of rule that decays. Keeping them together also keeps this tree free of libbpf, so a detector cannot pick up a kernel dependency by proximity.

- **`core/DetectLoop.{hpp,cpp}`** — the worker that drives parse → classify → dispatch off libbpf's poll thread. Lives here rather than under `programs/` because it belongs to the detection concern, not to any hook; `IHookModule` and `hg_event_source.h` moved here with it to keep the dependency graph one-way (`actions_lib ← detections_lib ← programs_lib`).
- **`tls_version/`** — `TlsVersionDetector` (flags TLS < 1.2), registered for **both** uprobe and XDP — see the `tls_violation_hint` note below, which exists precisely because those two hooks differ in how much they can conclude on their own + `tls_version.hpp` (the `TlsVersion` numeric→string helper it alone uses).
- **`payload_anomaly/`** — `PayloadAnomalyDetector` (SQLi / path-traversal / attack-signature substrings, case-insensitive). Registered for **both** uprobe and XDP: the uprobe fills `payload_snippet` from `SSL_write`/`SSL_read`, and XDP fills it for plaintext-HTTP-on-443, the case where TLS never starts so no `SSL_write` ever happens.
- **`cipher_suite/`** — `CipherSuiteDetector` + `weak_cipher_suites.hpp` (offered NULL/EXPORT/RC4/3DES/anon suites). XDP only in practice, since nothing else parses a ClientHello. Alert-only — see its class comment for the lockout incident that settled that.
- **`sni/`** — `SniDetector` (malformed SNI always; hostname mismatch only when `HTTPS_GUARD_EXPECTED_SNI` is configured). XDP only in practice. Alert-only for the same reason.
- **`cert_access/`** — `CertAccessDetector` (an unrecognized process opened the HTTPS key). LSM only in practice.
- **`cert_access/`** — `CertAccessDetector` (flags `hg_event.cert_identity_mismatch`, set by `programs/lsm_cert_guard/`'s userspace-side `/proc/<pid>/exe` check — not actionable, since there's no TCP 4-tuple to blocklist for a local file access and any in-kernel enforcement already happened, or didn't, before this detector ever ran).

No `shared/` bucket — each subdirectory here is named after the one detector it owns, the same "one directory per concern" rule `programs/` follows for hooks. If a future rule genuinely needs to share logic with an existing one, that shared piece earns its own subdirectory under `core/` rather than reviving a generic `shared/`.

## The registry, and why `tls_violation_hint` exists

`HttpGuardProgram::DetectorRegistry` (defined in `programs/core/HttpGuardProgram.hpp`, built in `programs/core/main.cpp`) maps each `hg_event_source` to an *ordered* list of detectors — first match wins, no match falls back to an inline "OK, traffic observed" `Verdict` (not itself a detector; there's nothing to detect in that case).

`hg_event.tls_violation_hint` is the one field on the shared event that exists purely to prevent a specific class of bug: `xdp_tls`'s BPF side already computes a synchronous `is_violation` verdict from the wire (see its own `CLAUDE.md`), and that's a *stronger* signal than `TlsVersionDetector`'s own `tls_version` re-derivation can produce on its own — a genuinely-parsed `legacy_version` of `0x0000` is a real violation there, not "no data," which `tls_version == 0` alone would wrongly conclude. `SslUprobeProgram` never sets this hint (its BPF side makes no such determination), so `TlsVersionDetector`'s zero-check still applies there. This shipped as a real bug once (caught by `/code-review`, not by the implementer) — if you're writing a detector that spans hooks with different BPF-side classification power, look for whether you need an equivalent hint before assuming a single field means the same thing everywhere.

## Testing

`../tests/test_detectors.cpp` covers both existing detectors: a clearly-violating input, a clearly-clean input, and each rule's real boundary conditions (the exact TLS threshold, the `tls_violation_hint` override, case-insensitivity, empty input). This is the one seam in the whole project explicitly designed to be testable without a kernel, root, or QEMU — a new detector should get the same treatment before it's considered done.

# 01 — Extend the OEM security event message registry

**What to build:** Add new message IDs to `recipes-bmcweb/bmcweb/files/OemSecurityEvent.1.0.0.json` (and the corresponding entries in `0001-add-oem-security-event-message-registry.patch`) for every detector planned in this spec: certificate-access violation, weak/downgraded cipher suite, SNI anomaly, connection-rate violation, Slowloris, and TLS renegotiation storm. Follow the exact shape of the three existing entries (`HttpsTlsVersionViolation`, `HttpsPayloadAnomalyDetected`, `HttpsTrafficObserved`) — `Description`, `Message: "%1"`, `Severity`, `NumberOfArgs: 1`, `ParamTypes: ["string"]`, `Resolution`.

**Blocked by:** None — can start immediately

**Status:** ready-for-agent

- [x] A message ID exists for a certificate-access violation (BPF-LSM cert-access guard, ticket 03), severity Critical
- [x] A message ID exists for a weak/downgraded cipher suite (ticket 04), severity Warning or Critical (implementer's call, consistent with how `HttpsTlsVersionViolation` reasons about severity)
- [x] A message ID exists for an SNI anomaly (ticket 04), severity Warning
- [x] A message ID exists for a connection-rate/SYN-flood/port-scan violation (ticket 05), severity Warning or Critical
- [x] A message ID exists for Slowloris detection (ticket 06), severity Warning
- [x] A message ID exists for a TLS renegotiation storm (ticket 06), severity Warning or Critical
- [x] Every new entry follows the existing three entries' exact shape (fields, `NumberOfArgs`, `ParamTypes`)
- [x] The bmcweb patch file's registry content matches `OemSecurityEvent.1.0.0.json` exactly — no drift between the two copies
- [x] `MessageId` values keep the existing four-dot-separated-field shape (`OemSecurityEvent.1.0.HttpsXyz`) — bmcweb's `registries::getMessageComponents()` requires exactly that shape (see `README.md`'s note on this)

## Comments

Chose Warning for both cipher-suite and connection-rate/renegotiation entries: `xdp_tls` only ever sees a client's *offered* cipher suite (from the ClientHello), never the actually-negotiated one (no ServerHello visibility), so "offered weak" is an anomaly signal rather than a confirmed compromise the way a TLS-version violation is — consistent with `HttpsPayloadAnomalyDetected` already being Warning for the same "suspicious, not confirmed" reasoning. Same logic for rate/renegotiation: a threshold crossing is worth flagging and blocklisting, but isn't in itself proof of a successful attack.

`OemSecurityEvent.1.0.0.json` and the bmcweb patch's C++ mirror were kept in sync by construction — wrote the six new entries once, verified line-for-line they match between both files. Regenerated the patch's diff hunk from real `diff -u` output against actual file content rather than hand-editing the unified-diff line-count header (`@@ -0,0 +1,88 @@` → `@@ -0,0 +1,160 @@`) — verified by applying the patch against a synthetic stub repo with `git apply --check`, confirming it applies cleanly and produces a file with all 9 `MessageEntry` blocks (3 original + 6 new).

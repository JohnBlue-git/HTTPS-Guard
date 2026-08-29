# 04 — Cipher-suite and SNI detection in the XDP ClientHello parser

**What to build:** Extend `xdp_tls.bpf.h`'s existing ClientHello parsing (which already reads `legacy_version`) to also extract the cipher suite list and the `server_name` (SNI) extension, and add two new detectors that classify what it finds: a weak/downgraded cipher suite (NULL, EXPORT, RC4, 3DES, or similar), and an SNI that doesn't match the BMC's expected hostname (or is absent/malformed where expected).

**Blocked by:** 01 — Extend the OEM security event message registry

**Status:** ready-for-agent

- [ ] `xdp_event` (or a superseding struct) carries enough of the parsed ClientHello for both new detectors to classify without re-parsing: at minimum the offered cipher suite list and the SNI hostname, if present
- [ ] A `CipherSuiteDetector` (or equivalent) flags a known-weak cipher suite using ticket 01's new message ID
- [ ] An SNI detector flags a mismatched/unexpected hostname using ticket 01's new message ID — the definition of "expected" (a configured hostname, the BMC's own identity, or something else) is this ticket's call, consistent with how `HTTPS_GUARD_IFACE` etc. are already configured via `https-guard.conf`
- [ ] Both new detectors are registered in `main.cpp`'s `buildDetectorRegistry()` for `HG_SOURCE_XDP` only — this data doesn't exist for uprobe events
- [ ] Parsing correctness is tested against a handful of hand-built or captured ClientHello byte sequences (not just live traffic), the same way `TlsVersionDetector`'s threshold tests use synthetic input rather than requiring a live legacy TLS client
- [ ] No change to `TlsVersionDetector`'s existing behavior or to the `legacy_version` parsing already in place

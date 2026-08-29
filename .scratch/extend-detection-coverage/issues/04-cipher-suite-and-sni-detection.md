# 04 — Cipher-suite and SNI detection in the XDP ClientHello parser

**What to build:** Extend `xdp_tls.bpf.h`'s existing ClientHello parsing (which already reads `legacy_version`) to also extract the cipher suite list and the `server_name` (SNI) extension, and add two new detectors that classify what it finds: a weak/downgraded cipher suite (NULL, EXPORT, RC4, 3DES, or similar), and an SNI that doesn't match the BMC's expected hostname (or is absent/malformed where expected).

**Blocked by:** 01 — Extend the OEM security event message registry

**Status:** done

- [x] `xdp_event` (or a superseding struct) carries enough of the parsed ClientHello for both new detectors to classify without re-parsing: at minimum the offered cipher suite list and the SNI hostname, if present
- [x] A `CipherSuiteDetector` (or equivalent) flags a known-weak cipher suite using ticket 01's new message ID
- [x] An SNI detector flags a mismatched/unexpected hostname using ticket 01's new message ID — the definition of "expected" (a configured hostname, the BMC's own identity, or something else) is this ticket's call, consistent with how `HTTPS_GUARD_IFACE` etc. are already configured via `https-guard.conf`
- [x] Both new detectors are registered in `main.cpp`'s `buildDetectorRegistry()` for `HG_SOURCE_XDP` only — this data doesn't exist for uprobe events
- [x] Parsing correctness is tested against a handful of hand-built or captured ClientHello byte sequences (not just live traffic), the same way `TlsVersionDetector`'s threshold tests use synthetic input rather than requiring a live legacy TLS client
- [x] No change to `TlsVersionDetector`'s existing behavior or to the `legacy_version` parsing already in place

## Comments

### What "expected SNI" means here

Narrowed deliberately, because the obvious rule is a false-positive machine. A BMC answers to any DNS name that resolves to it, so comparing SNI against the BMC's own hostname would fire on every legitimate connection through a CNAME or site alias — and a noisy detector gets muted, which is worse than no detector. Absent SNI is also the *normal* case (a BMC reached by IP sends none), so that's never flagged. So:

- **Malformed SNI/ClientHello structure** — always flagged. No standard client emits one; it's a common fingerprint of scanners and hand-rolled probes.
- **Hostname mismatch** — opt-in only, via a new `HTTPS_GUARD_EXPECTED_SNI` in `https-guard.conf` (plumbed as an optional 5th daemon argument). Unset by default, in which case only the malformed check runs.

### Testing the real parser, not a copy of it

`parse_client_hello_detail()` was deliberately written using only pointer arithmetic and `uint*_t` — no BPF helpers — and split into its own `parse_client_hello.h`. That makes the *actual shipped parser* compile and run host-side, so `tests/test_client_hello_parsing.cpp` exercises the same code the kernel runs rather than a reimplementation that could drift from it. Same trick `parse_uprobe_event.hpp` already used for the uprobe side. 37/37 tests pass, built with `-Wall -Wextra -fsanitize=address,undefined` (zero warnings, no sanitizer findings across every truncation prefix of a valid ClientHello).

### Three real defects this ticket surfaced

**1. An SNI truncation bypass (in this ticket's own new code, caught before shipping).** The truncated-packet test loop found that a packet ending mid-hostname yielded `sni_present` with a *prefix* and no malformed flag. A crafted `bmc.evil.com` truncated to `bmc` would then have satisfied an expected-hostname check it has nothing to do with. Fixed by flagging whenever fewer bytes were captured than the name declared (`n < nlen`), which also subsumes the over-long case; direct regression test added.

**2. The BPF verifier rejected the first version of the parser** — found only by booting it, not by any amount of local review:
```
parse_client_hello.h:154: r0 = *(u8 *)(r5 +6)
invalid access to packet, off=31 size=1, R5(id=49,off=31,r=29)
```
clang had CSE'd the pointer arithmetic across the bounds check, so the read landed on a register whose validated range (29 bytes) was shorter than the offset read (31) — check and read had drifted onto different pointers. Fixed by routing every read through `hg_ch_u8`/`hg_ch_u16` helpers that recompute the pointer and validate exactly that byte immediately before dereferencing. Verbose, but it's what keeps the two from being separated; the reasoning (and the verifier message) is recorded in the header so the next person doesn't "simplify" it back.

**3. Making these detectors `actionable` was a self-inflicted DoS — proven by locking myself out.** Both detectors originally set `actionable = true`. The first live test with a crafted RC4 ClientHello produced exactly what that implies:
```
BlocklistAddAction: blocklisted 10.0.2.2 for 300s reason=Weak cipher suite offered ... TLS_RSA_WITH_RC4_128_SHA (0x0005) — RC4 stream cipher
```
`10.0.2.2` is the SLIRP host address — which is also where the SSH session running the test came from. The XDP blocklist drops **all** traffic from a source IP, not just port 443, so the test cut off its own management access; SSH recovered on its own ~105s later as the entry aged out (confirming the diagnosis rather than a crash). On a real BMC this means one scanner packet, or one legacy tool behind a shared NAT address, locks every administrator sharing that address out of *every* BMC service. Merely *offering* a weak suite in a handshake bmcweb then refuses does not justify that, so both detectors are now alert-only (`actionable = false`), with the reasoning recorded in both class comments and pinned by tests. Enforcement, if ever wanted, belongs behind an explicit opt-in.

### Two pre-existing defects found while verifying, filed separately

Neither introduced here, both out of scope, both filed rather than silently fixed or ignored:

- **Ticket 08** — `TcpDestroyer` passes host-byte-order ports into netlink's `idiag_sport`/`idiag_dport`, which need network order, so `SOCK_DESTROY` can never match a socket. TCP-kill enforcement has never actually worked, for either hook. This also corrects a wrong explanation previously recorded in ticket 02's comments (which blamed the connection having already closed); ticket 02 has been amended.
- **Ticket 09** — the XDP attachment outlives the daemon process (`bpf_xdp_attach` has no `bpf_link`, and the code pushes a `nullptr` placeholder), so restarting the daemon fails with "XDP program already attached" and it runs degraded at `1 of 3 hooks` — silently losing all wire-level detection, including everything this ticket adds, while still reporting itself healthy.

One small in-scope fix was made rather than filed: `XdpTlsProgram::parseEvent()` never copied `raw->source_ip` into `hg_event`, so every XDP verdict message read "an unidentified peer" despite the address being available. That directly degraded this ticket's new messages, in the same function this ticket already modifies.

### Live verification

Fresh QEMU boot, XDP attached in native mode. Real browser-style request first: a genuine `curl` to the SLIRP-forwarded port produced `cipher_suites=31/31, sni='bmc.example.com'` — the parser handles a real-world ClientHello, not just synthetic ones. Then four crafted ClientHellos sent over the wire, with the resulting Redfish event log showing exactly one entry per case and nothing spurious:

| Case sent | Parsed | Redfish MessageId |
|---|---|---|
| RC4 + 2 modern suites | `cipher_suites=3/3` | `HttpsWeakCipherSuiteDetected` — "TLS_RSA_WITH_RC4_128_SHA (0x0005) — RC4 stream cipher" |
| 3DES + 1 modern suite | `cipher_suites=2/2` | `HttpsWeakCipherSuiteDetected` — "TLS_RSA_WITH_3DES_EDE_CBC_SHA (0x000a) — 3DES / Sweet32" |
| modern suites only | `cipher_suites=3/3` | `HttpsTrafficObserved` (severity OK) — no false positive |
| SNI `name_type=7` (invalid) | `sni=''` | `HttpsSniAnomalyDetected` — "malformed or over-long SNI/ClientHello structure" |

And the point of the fix: **no `BlocklistAddAction` for any of them**, SSH reachable throughout.

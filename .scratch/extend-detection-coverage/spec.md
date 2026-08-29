# Extend detection coverage beyond TLS-version and payload-anomaly

Status: ready-for-agent

## Problem Statement

HTTPS-Guard's current detection is real but narrow: it flags a negotiated TLS version below 1.2, and a small set of attack-signature substrings in a payload snippet. Working through the two existing hooks in detail (writing their `DESIGN.md`s) surfaced concrete, specific gaps rather than vague "add more security" aspirations:

- The one uprobe hooked (`SSL_write`) observes what a process *sends*. Attacker-controlled input arrives in what a process *receives* (`SSL_read`) — today's payload-anomaly rules mostly only fire if a response happens to reflect bad input back, not on the request that actually carried it.
- Nothing verifies that the process opening the BMC's HTTPS certificate/key file is actually bmcweb. A uprobe's `comm` field is self-reported and trivially spoofable; there is no hook at all on certificate-file access.
- The `xdp_tls` hook already parses far enough into the ClientHello to read `legacy_version` — the cipher suite list and the SNI extension sit in the same record, unread, even though a downgraded cipher suite or a mismatched SNI are both real, wire-visible attack indicators.
- Volumetric and timing-based attacks (connection-rate abuse, SYN floods, port scanning, Slowloris, TLS renegotiation storms) have no detection at all — everything today is single-packet/single-call classification with no cross-event state.
- The Redfish message registry (`OemSecurityEvent.1.0.0.json`) only defines message IDs for the two existing detectors; every new detector above needs its own.

## Solution

Seven pieces of work, each independently valuable, most sharing one prerequisite (the message-registry extension, since four of the others each want their own new Redfish message ID and none of them should have to independently touch the same shared registry file):

1. Extend the OEM security event message registry with the message IDs the other six pieces need.
2. Mirror the existing `SSL_write` uprobe onto `SSL_read`, so the payload-anomaly rules see the request side, not just the response.
3. A BPF-LSM hook on certificate-file access, verifying process identity more robustly than a self-reported `comm`, rolled out shadow-mode-first given the blast radius of a synchronous deny bug.
4. Extend `xdp_tls`'s existing ClientHello parsing to also classify the cipher suite and SNI.
5. Stateful, per-source-IP connection-rate / SYN-flood / port-scan detection.
6. Stateful, cross-event Slowloris and TLS-renegotiation-storm detection.
7. Once the above land, a full documentation pass: regenerate `DESIGN.html`, add `DESIGN.md`/`CLAUDE.md` for the new hook(s) and detector(s), and reconcile every doc that currently describes "two hooks, two detectors" as the whole system.

This spec does not pin down every implementation detail as tightly as the `split-hooks-and-detectors` spec did — several of these (notably #5 and #6) surface real open architecture questions (see Implementation Decisions) that didn't exist until now, because nothing before this needed cross-event state or synchronous deny power. Each ticket names the question explicitly rather than assuming an answer.

## User Stories

1. As a BMC operator, I want an attacker's actual request content inspected, not just what the server sends back, so that a SQL-injection or path-traversal attempt in a request is caught even when the response doesn't echo it.
2. As a BMC operator, I want to know if a process other than bmcweb opens the HTTPS private key/certificate, so that key theft or a compromised local process impersonating bmcweb is detected (or blocked) rather than silently succeeding.
3. As a security reviewer, I want a downgraded or weak TLS cipher suite flagged the same way a downgraded TLS version already is, so that "technically TLS 1.2+" traffic that's still cryptographically weak doesn't go unnoticed.
4. As a security reviewer, I want an unexpected or mismatched SNI flagged, so that domain-fronting or requests aimed at the wrong virtual host are visible.
5. As a BMC operator, I want a flood of connection attempts or a port scan from one source detected and eventually blocklisted, so that volumetric abuse doesn't require a human watching logs in real time.
6. As a BMC operator, I want many slow, deliberately-incomplete connections (Slowloris) detected, so that a resource-exhaustion attack against bmcweb's connection pool is visible before it succeeds.
7. As a BMC operator, I want repeated TLS renegotiation from one source flagged, so that a renegotiation-based DoS attempt is caught.
8. As a HTTPS-Guard maintainer, I want each new detector's Redfish message ID to already exist before I write the detector, so that I'm not the one deciding registry content ad hoc mid-implementation.
9. As a HTTPS-Guard maintainer, I want the certificate-access guard to prove itself in observe-only mode before it can ever deny a real file open, so that a bug in new, unreviewed LSM code cannot itself take down bmcweb's ability to serve HTTPS at all.
10. As a HTTPS-Guard maintainer, I want the cipher-suite and SNI checks built as an extension of the existing ClientHello parsing rather than a new hook, so that the wire-level parsing logic isn't duplicated a second time.
11. As a HTTPS-Guard maintainer, I want the open question of "can a detector hold state across events" resolved explicitly and once, rather than each of the rate-based tickets inventing its own answer independently.
12. As a future contributor, I want the documentation to describe the system as it actually is once all of this lands, not as it was when only two hooks and two detectors existed.
13. As a HTTPS-Guard maintainer, I want each of these seven pieces to be its own ticket with its own acceptance criteria, so that landing one doesn't require the other six to also be finished.

## Implementation Decisions

- The message-registry extension is a prerequisite for every ticket that needs a new Redfish message ID (certificate-access guard, cipher-suite/SNI, connection-rate, Slowloris/renegotiation-storm) and is scoped to land first specifically so those four tickets don't each independently touch `OemSecurityEvent.1.0.0.json` and its bmcweb patch.
- The `SSL_read` mirror reuses the existing detectors and message IDs unchanged — a request-side payload is anomalous for exactly the same reasons a response-side one is — so it is not blocked by the registry extension.
- The certificate-access guard is explicitly staged: land it capable of denying access, but default it to an observe-only/shadow mode (log what it would have done, take no enforcement action) until it has been proven correct in the field, given that a false-positive deny would break bmcweb's own ability to serve HTTPS — a categorically larger blast radius than any existing enforcement action (killing one TCP connection, or dropping one packet class) causes today. Which of the two viable mechanisms (a BPF LSM hook capable of a synchronous deny, versus a kprobe-only detect-and-react-asynchronously fallback) to build the shadow mode on top of, and exactly which process-identity signals to check (binary path, cgroup, UID, some combination), are left to that ticket's implementer to decide against the target kernel's actual capabilities — this spec does not mandate one over the other.
- Cipher-suite and SNI detection extend `xdp_tls`'s existing ClientHello-parsing code path rather than introducing a new hook, since both fields live in the same TLS record `xdp_tls` already parses partway through for `legacy_version`.
- Connection-rate/SYN-flood/port-scan detection needs per-source-IP state over a time window, most naturally implemented as a BPF-side `LRU_HASH` map checked at the same point `blocklist_check()` already runs (both are "is this source already known-bad" checks) — but implementing it is deferred to that ticket rather than designed in detail here.
- Slowloris and TLS-renegotiation-storm detection both need cross-event, time-windowed aggregation that cannot be expressed as a pure function of one already-parsed event — the shape every existing `IDetector` implementation has. Whether that means `IDetector::evaluate` gains a non-`const` or otherwise stateful variant, or a new sibling interface is introduced for genuinely stateful rules, or existing hg_event/hook-module boundaries need to change to carry connection-duration/repeat-ClientHello information forward, is an open architecture question this spec deliberately does not resolve — the ticket for this work is expected to propose an answer and check it against the existing `IDetector` design's intent (pure, synchronous, no I/O) before writing code, not silently bend the interface.
- The documentation-rewrite ticket is blocked by all five detection-capability tickets, since it cannot accurately document hooks and detectors that don't exist yet, and a docs pass done before they land would likely be discarded or reworked once they do.

## Testing Decisions

- Every new detector should get the same treatment as `TlsVersionDetector`/`PayloadAnomalyDetector`: unit tests against synthetic `hg_event` (or whatever event/state representation a stateful detector ends up using) covering a clearly-violating input, a clearly-clean input, and its real boundary conditions — no kernel/BPF/root/QEMU dependency required to exercise the classification logic itself.
- The certificate-access guard additionally needs manual verification on real QEMU/hardware that shadow mode does not, itself, ever deny a legitimate bmcweb file open — this cannot be meaningfully unit-tested given it depends on real LSM hook behavior.
- Cipher-suite/SNI parsing correctness (byte-offset extraction from a ClientHello) should be tested against a handful of captured or hand-built ClientHello byte sequences, not just live traffic, the same way the existing TLS-version-threshold tests use synthetic input rather than requiring a live legacy TLS client.

## Out of Scope

- Any detection mechanism not named in this spec (this is not an open-ended "add all possible security hooks" effort).
- Making the certificate-access guard's enforcement (deny) mode the default — that's a follow-up decision made after shadow-mode field data exists, not part of this spec.
- Rewriting or extending the existing `TlsVersionDetector`/`PayloadAnomalyDetector` rules themselves.
- Any change to the `actions/` dispatch layer's existing three countermeasures.

## Further Notes

- This spec's tickets are less tightly pre-specified than `split-hooks-and-detectors`'s were, by design — this is genuinely new capability, not a structural refactor of already-understood behavior, and several open questions (stateful detectors, LSM rollout mechanics) are real enough that pinning down a wrong answer in the spec would cost more than letting each ticket's implementer resolve it against what they find when they get there.
- The SLIRP/XDP attach discrepancy noted in `programs/xdp_tls/DESIGN.md` (a live boot attached XDP successfully despite the platform being documented as unable to) is unrelated to this spec but worth the cipher-suite/SNI and connection-rate tickets' implementers knowing about, since both extend that same hook.

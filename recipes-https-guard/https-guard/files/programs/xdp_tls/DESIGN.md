# `xdp_tls` — XDP TLS/ClientHello inspection (AUXILIARY hook)

## Why detect this

`ssl_uprobe` sees a connection only after OpenSSL has already negotiated TLS and a process calls `SSL_write`. That's too late for three things this hook exists to catch instead:

**1. Repeat offenders, at line rate.** Once `ssl_uprobe` (or this hook itself) confirms a source is malicious, its IP gets written into a shared BPF map. Every *subsequent* packet from that source — including its very first `SYN`, long before any TLS handshake — should be dropped before it costs the system anything further. Only a hook on the wire can do that; a uprobe only fires once a userspace process is already deep into handling the connection.

**2. A TLS downgrade before the handshake even completes.** The ClientHello — the client's *first* message, unencrypted by definition — already announces roughly how old a client is willing to go. Dropping it here means the connection never gets a chance to finish negotiating, let alone reach bmcweb. Waiting for `ssl_uprobe` to see the result means the handshake already completed and a real (if short-lived) connection existed.

**3. Traffic that never becomes a valid TLS session at all.** Something sending plaintext HTTP straight at port 443 — a misconfigured client, a protocol-confusion probe, a scanner — will usually never trigger `SSL_write` in bmcweb at all, because the TLS handshake fails before any application code runs. A wire-level hook is the only place this is visible.

```
┌──────────────────────────────────────────────────────────────┐
│  What only the wire can see, that SSL_write can't            │
│                                                              │
│  • A source IP already known bad, on its very next SYN       │
│      → dropped before a socket is even allocated             │
│                                                              │
│  • A ClientHello proposing TLS 1.0/1.1                       │
│      → dropped before the handshake finishes — bmcweb never  │
│        sees this connection at all                           │
│                                                              │
│  • Plaintext "GET /..." bytes arriving on port 443           │
│      → the TLS handshake never even started; ssl_uprobe has  │
│        nothing to hook because no SSL_write happens for a    │
│        connection that never becomes a TLS session           │
└──────────────────────────────────────────────────────────────┘
```

## How to detect

**XDP** runs in the network driver's RX path — either natively (`ndo_bpf` support in the driver) or in generic/SKB mode (`netif_receive_skb()`, software fallback) — inspecting a packet before the kernel's normal networking stack has done almost anything with it. `HttpGuardProgram`/`XdpTlsProgram` tries native first, then generic, and simply doesn't attach if neither is available (see `programs/CLAUDE.md`) — this hook is auxiliary specifically so its absence never stops the daemon.

```
Wire
  │
  ▼
┌───────────────────────────────────────────────────────────────────┐
│  https_guard_xdp()  — SEC("xdp"), xdp_tls.bpf.h                   │
│                                                                   │
│  Ethernet ─▶ IPv4? ─▶ blocklist_check(saddr) ─▶ TCP, port 443?  │
│                              │                                    │
│                    hit & not expired                              │
│                              ▼                                    │
│                         XDP_DROP  ◄── Tier 1, before any          │
│                                       payload inspection at all   │
│                                                                   │
│  (miss / expired / absent) ──▶ inspect TCP payload's first byte  │
│         │                                                         │
│         ├─ 0x16 (TLS Handshake) ──▶ parse ClientHello (below)    │
│         │                                                         │
│         └─ looks like "GET "/"POST"/etc ──▶ plaintext-HTTP event  │
└───────────────────────────────────────────────────────────────────┘
```

**Parsing the ClientHello** — the record header (5 bytes: ContentType + legacy_record_version + length) is followed by the handshake header (4 bytes: HandshakeType + 3-byte length) before the `legacy_version` field this hook actually reads:

```
TCP payload, first bytes:
┌───────────────┬─────────┬────────┬────────────────┬──────────────────┬─────────────────┐
│ 0x16          │ 2-byte  │ 2-byte │ 0x01           │ 3-byte           │ 2-byte          │
│ (TLS Handshk) │ version │ length │ (Client Hello) │ handshake length │ legacy_version  │◄─ read here
└───────────────┴─────────┴────────┴────────────────┴──────────────────┴─────────────────┘
  byte0          bytes1-2    3-4          5              6-8            9-10
                                          └── cursor = payload + 5 + 4 ──┘
```

**A nuance worth knowing:** this reads the ClientHello's `legacy_version` field, not necessarily the version that ends up actually negotiated. A TLS-1.3-capable client always sets `legacy_version = 0x0303` (TLS 1.2) for backward compatibility and signals the real version via a `supported_versions` extension this hook doesn't parse. That's fine for this hook's actual purpose: a genuinely old client (only capable of TLS 1.0/1.1) has no `supported_versions` trick to fall back on — it presents its true maximum version in `legacy_version`, and that's exactly the case worth catching. A modern client that's merely *capable* of more than TLS 1.2 is correctly never flagged.

**Minimal classification — the one deliberate exception to "BPF is observational":**

```c
is_violation = (tls_ver < 0x0303) ? 1 : 0;
```

This line-rate decision is why `xdp_event` carries an `is_violation` field when `uprobe_event` doesn't — it's surfaced to userspace as `hg_event.tls_violation_hint` (see `detections/CLAUDE.md` for why that field exists and the bug it prevents). Everything else — message text, severity naming, whether to blocklist — is still decided entirely in userspace by `TlsVersionDetector`, same as the uprobe path.

## How to defend (enforcement)

```
ClientHello arrives, tls_ver < 0x0303
       │
       ├─── bpf_ringbuf_submit(evt)  ── event queued for userspace FIRST
       │                                (submitting invalidates the evt
       │                                 pointer, so the drop decision
       │                                 below uses a local variable,
       │                                 not evt->is_violation)
       │
       └─── return XDP_DROP  ── the packet is dropped NOW, synchronously.
             The handshake never completes; bmcweb never sees this
             connection.

                          │  (asynchronously, milliseconds later)
                          ▼
       Userspace: XdpTlsProgram::parseEvent() → hg_event
       (tls_violation_hint = true, local/remote addresses and ports already
        known — XDP sees the packet headers directly, unlike the
        uprobe path which needs ProcPeerResolver)
                          │
                          ▼
       TlsVersionDetector: hint is true → Verdict{Critical, actionable}
                          │
                          ▼
       BlockTcpAction (SOCK_DESTROY — likely redundant here since the
       handshake never completed, but harmless) + BlocklistAddAction
                          │
                          ▼
       Blocklist::add() writes this source IP into the SAME BPF map
       Tier 1's blocklist_check() reads
                          │
                          ▼
       This source's *next* packet — even a bare SYN, no ClientHello
       needed — is dropped by Tier 1 before reaching this parsing
       logic at all. This is the learning loop: Tier 2's confirmed
       verdict becomes Tier 1's future line-rate policy.
```

For a **plaintext-HTTP-on-443** event, `is_violation` is always 0 — there's no synchronous drop, only an observation submitted for userspace. This gives `PayloadAnomalyDetector` a real shot at attacker-supplied content, unlike the uprobe path's response-side `payload_snippet` (see `programs/ssl_uprobe/DESIGN.md`'s known limitations) — whatever's in this packet is genuinely what was sent to the BMC, not a reflected response.

## What's hooked, concretely

- **Hook point:** `SEC("xdp")` on the configured interface (`HTTPS_GUARD_IFACE`, default `eth0`), attached natively first, then generic/SKB mode, then skipped non-fatally.
- **BPF program:** `https_guard_xdp()` in `xdp_tls.bpf.h`.
- **Raw event struct:** `struct xdp_event` in `xdp_tls_event.h` — carries full socket 4-tuple and `is_violation`, unlike `uprobe_event`.
- **Shared state:** `blocklist_check()` / the `src_blocklist` BPF map, defined in `../../actions/blocklist/blocklist.bpf.h` and `#include`d here — this is the one dependency `programs/` has on `actions/`, because the blocklist map is genuinely an enforcement-layer concern shared across hooks, not owned by either.

## Known limitations

**Attach success under QEMU SLIRP is unverified as a hard rule.** This hook is documented (in `README.md`) as unable to attach under SLIRP networking (no real netdev, so neither native nor generic XDP should have anything to hook). A live boot on this project's own kernel showed the native attach call succeeding anyway. Whether the actual `XDP_DROP` enforcement path fires correctly in that state was not independently confirmed — treat it as needing verification on whatever kernel you're actually deploying to, not a fixed platform fact either way.

**Cipher-suite and SNI detection are alert-only, never enforced.** Both are extracted (see `ebpf/parse_client_hello.h`) and classified by `../../detections/cipher_suite/` and `../../detections/sni/`, but their verdicts are deliberately `actionable = false`. The blocklist this hook enforces is keyed on source IP and drops *every* port, not just 443 — so treating "offered RC4" or "unexpected SNI" as actionable means one scanner packet, or one legacy tool behind a shared NAT address, locks every administrator sharing that address out of SSH and everything else for the blocklist TTL. This was established empirically, not theoretically: the first live test of these detectors blocklisted the test's own SSH source and cut off the session. Offering a weak suite in a handshake bmcweb then refuses does not warrant that; enforcement, if ever wanted, belongs behind an explicit opt-in.

**SNI hostname mismatch is opt-in and off by default.** A BMC legitimately answers to any DNS name resolving to it, so mismatch-against-own-hostname would fire on every connection through a CNAME or site alias. Only a *configured* `HTTPS_GUARD_EXPECTED_SNI` enables mismatch checking; malformed-structure detection always runs. Absent SNI — the normal case for a BMC reached by IP — is never flagged.

**Captured ClientHello detail is capped.** At most `HG_MAX_CIPHER_SUITES` (32) suites and `HG_SNI_LEN - 1` (63) hostname bytes land in the event; `cipher_suites_offered` reports the true count so a detector can tell truncation from a genuinely short list, and a partially-captured hostname sets `sni_malformed` so it can't be compared as if complete (that specific gap was a real bypass — a truncated `bmc.evil.com` reading as `bmc` — caught by test before shipping).

**No rate-based detection.** Connection-rate abuse, SYN floods, and port scanning need per-source-IP state over a time window (an `LRU_HASH` map keyed on source IP, most naturally checked at the same point `blocklist_check()` already runs) — planned as a separate ticket, since it's a different kind of mechanism (stateful counting) from anything this hook does today.

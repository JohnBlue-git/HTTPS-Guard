# TLS version violation

**Emits:** `OemSecurityEvent.1.0.HttpsTlsVersionViolation` (Critical) ·
**Enforces:** yes — blocklist, plus a TCP teardown when the full 4-tuple is known.

## Why detect this

bmcweb serves the entire Redfish management API — sensor readings, power
control, firmware update, user credentials — over HTTPS on port 443. TLS is the
*only* thing between that traffic and anyone who can see the wire.

TLS 1.0 and 1.1 are withdrawn (RFC 8996) and carry known, practical breaks:
POODLE, BEAST, weak or absent forward secrecy, RC4-class ciphers. A client
negotiating one is not a theoretical risk — it is a live downgrade attempt, a
legacy management tool nobody has revisited, or something deliberately weakening
the channel before doing anything else. Once negotiated, everything on that
connection, credentials included, is exposed to anyone on the path.

## How to detect

### Where this sits in the handshake

```
Client                                                             bmcweb (server)
  │                                                                      │
  ├── TCP SYN ─────────────────────────────────────────────────────────▶│
  │◀──────────────────────────────────────────────────────── SYN-ACK ───┤
  ├── ACK ─────────────────────────────────────────────────────────────▶│
  │                    (TCP handshake complete; no TLS yet)              │
  │                                                                      │
  ├── ClientHello (0x16, unencrypted) ─────────────────────────────────▶│
  │      legacy_version · cipher_suites[] · extensions (incl. SNI)       │
  │◀── ServerHello, Certificate, ... (0x16) ────────────────────────────┤
  ├── Finished (0x16) ─────────────────────────────────────────────────▶│
  │◀── Finished (0x16) ─────────────────────────────────────────────────┤
  │              (TLS handshake complete; ssl->version now set)          │
  │                                                                      │
  ├── application data, e.g. an HTTP request ──────────────────────────▶│
  │◀── application data, e.g. an HTTP response ─────────────────────────┤
  │                                                                      │
  ├── TCP FIN or RST ──────────────────────────────────────────────────▶│
```

**Where this sits:** the XDP check reads `legacy_version` out of the
ClientHello, before the TCP handshake above has even finished reaching bmcweb's
TLS stack — the earliest point anything in this diagram can be judged. The
uprobe check reads `ssl->version` only after both `Finished` messages, once
negotiation is done — the only point at which what was *actually agreed* exists
anywhere. That gap between the two markers is exactly why they can disagree, and
why only the earlier one is reachable on this project's target — see below.

Two sources see this, and they see genuinely different things.

### On the wire, before the handshake completes (XDP)

The ClientHello is the client's first message and unencrypted by definition. Its
`legacy_version` field already announces roughly how old a client is willing to
go — and it sits at a fixed offset:

```
TCP payload, first bytes:
┌───────────────┬─────────┬────────┬────────────────┬──────────────────┬─────────────────┐
│ 0x16          │ 2-byte  │ 2-byte │ 0x01           │ 3-byte           │ 2-byte          │
│ (TLS Handshk) │ version │ length │ (Client Hello) │ handshake length │ legacy_version  │◄─ read here
└───────────────┴─────────┴────────┴────────────────┴──────────────────┴─────────────────┘
  byte0          bytes1-2    3-4          5              6-8            9-10
                                          └── cursor = payload + 5 + 4 ──┘
```

**`legacy_version` is not necessarily the negotiated version.** A TLS-1.3-capable
client always sets it to `0x0303` for backward compatibility and signals the real
version in a `supported_versions` extension this hook does not parse. That is
fine for the case worth catching: a genuinely old client has no such trick to
fall back on and presents its true maximum here. A modern client merely *capable*
of more is correctly never flagged.

### After negotiation, from inside the process (uprobe)

The uprobe reads `ssl->version` out of the `SSL` object — the version that was
actually agreed, not merely offered:

| | How |
|---|---|
| Read | `bpf_probe_read_user()` at `SSL_VERSION_OFFSET` into `ssl` |
| Offset | generated at build time by `scripts/gen_ssl_offset.c` |
| Why generated | OpenSSL 3.x made `struct ssl_st` opaque, **and** it is a userspace type with no kernel BTF entry, so CO-RE cannot resolve it either — a CO-RE relocation for `ssl_st` fails at program load with "invalid CO-RE relocation" |
| Architecture-specific | 36 bytes on ARM 32-bit, 20 on x86_64 |

Identical for both directions: the negotiated version does not depend on which
way bytes are flowing.

**The unreachable half, stated honestly.** On the shipped image this path cannot
fire: it reads what was *negotiated*, and OpenSSL 3.x will not negotiate below
TLS 1.2. Only the XDP path is reachable here, and that is what was verified live.

### The one line of classification allowed in BPF

```c
is_violation = (tls_ver < 0x0303) ? 1 : 0;
```

This is the deliberate exception to "BPF is observational", and it exists because
XDP has to decide whether to drop *this* packet before userspace can see it. It
reaches the rule as `violation_hint`, and it is **not** redundant with the version
number: a genuinely-parsed wire `legacy_version` of `0x0000` *is* a violation,
whereas `tls_version == 0` from a uprobe only means "never observed". Collapsing
those two zeros shipped as a real bug once, caught in review rather than by the
implementer — which is why the rule reads two fields, not one:

```
violation = violation_hint || (tls_version > 0 && tls_version < 0x0303)
```

`0x0303` is TLS 1.2. The `> 0` guard keeps "unobserved" from reading as
"ancient"; `violation_hint` keeps that guard from suppressing a real wire zero.

## How to protect

Two tiers, and only the XDP path gets the first one.

**Synchronously, at line rate.** The XDP program submits the event to the ring
buffer *first* and then returns `XDP_DROP` — the handshake never completes and
bmcweb never sees the connection. Submitting first matters: submitting
invalidates the event pointer, so the drop decision reads a local variable rather
than `evt->tls.is_violation`.

**Asynchronously, milliseconds later.** The verdict is actionable, so
`dispatchVerdict()` blocklists the peer and — where a full 4-tuple is known —
tears the connection down with `SOCK_DESTROY`. The blocklist entry then makes
Tier 1 drop that source's *next* packet even on the uprobe-only path. See
[`actions/blocklist/DESIGN.md`](../../actions/blocklist/DESIGN.md) and
[`actions/tcp/DESIGN.md`](../../actions/tcp/DESIGN.md).

## What to hook

| Source | Hook | Gives |
|---|---|---|
| `xdp_tls` | `SEC("xdp")` on the NIC RX path | `legacy_version` + `is_violation`, full 4-tuple from the headers |
| `ssl_uprobe` | `uprobe/ssl_write` and the `ssl_read` entry+return pair on `libssl.so` | negotiated version; **no** connection tuple |

`TlsVersionDetection<RawT>` is templated over the raw layout, so both share one
rule and one event struct. Attach mechanics for either hook are in
[`programs/DESIGN.md`](../../programs/DESIGN.md).

## How to trigger it

See [README.md § Exercising the Detections](../../../../../README.md#exercising-the-detections)
for the runnable recipe and this detection's live-verification status.

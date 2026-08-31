# SNI anomaly

**Emits:** `OemSecurityEvent.1.0.HttpsSniAnomalyDetected` (Warning) ·
**Enforces:** **no — alert only**, for the same reason as
[`cipher_suite`](../cipher_suite/DESIGN.md).

## Why detect this

Two different things, sharing one message ID.

**A malformed SNI extension** is not something any standard client produces. An
unknown `name_type`, a declared hostname length running past the record, an
extension block that does not parse — these are hand-built packets, which on a
management interface means someone is probing rather than connecting.

**A hostname mismatch** says the client thinks it is talking to something else.
That is either a misdirected client, a stale DNS entry, or a scanner sweeping
addresses with a fixed hostname and not caring which answers.

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

**Where this sits:** inside the ClientHello, same message as `legacy_version`
and the offered cipher list — before the handshake has gone any further. By the
time `SSL_write`/`SSL_read` ever runs, this message is long gone, which is why
only the wire-side hook can see it at all.

Only a hook on the wire can see the SNI extension: it is inside the ClientHello,
before the handshake completes.

Only a hook on the wire can see a ClientHello at all: it is the client's first
message, and by the time `SSL_write` runs in bmcweb the handshake is long over.
So this is XDP-only, and the `requires` clause on the detection says so — naming
it in the uprobe hook's list does not compile.

The XDP program checks the TCP payload's first byte, and `0x16` (TLS Handshake)
is what sends it down this path:

```
Ethernet ─▶ IPv4? ─▶ blocklist_check(saddr) ─▶ TCP, port 443?
                            │
                  hit & unexpired ──▶ XDP_DROP   (before any parsing at all)
                            │
              miss/expired ──▶ first payload byte:
                                 ├─ 0x16 ──▶ parse the ClientHello
                                 └─ "GET "/"POST" ──▶ plaintext-HTTP-on-443 event
```

**The parse lives in `ebpf/parse_client_hello.h`, and it is shared verbatim with
the host tests.** It is written using only pointer arithmetic and `uint*_t` — no
BPF helpers — so the *actual shipped parser* compiles and runs host-side. That is
why `tests/test_client_hello_parsing.cpp` exercises the same code the kernel runs
rather than a reimplementation that could drift from it.

**Its byte-at-a-time read helpers exist to satisfy the verifier.** The
straightforward version was rejected outright:

```
invalid access to packet, off=31 size=1, R5(...r=29)
```

The verifier cannot follow a variable-offset read into a packet without a bounds
check it can prove, so `hg_ch_u8`/`hg_ch_u16` do one checked byte at a time. Do
not "simplify" them without reading why.

### Two checks, and the order between them is part of the rule

**Malformed fires unconditionally** — the structure itself is the signal, so no
configuration is needed.

**Mismatch fires only when configured.** `HTTPS_GUARD_EXPECTED_SNI` holds the
name this BMC answers to, and when it is unset mismatch checking is off entirely.
There is no safe default: a BMC's hostname is a deployment fact, and guessing it
would alert on everything or nothing.

**Malformed is checked first, and that ordering matters.** A truncated hostname is
reported as malformed and *never compared*. If a clipped capture were compared as
though complete it could produce a false mismatch or — worse — a false match.
Capture is capped at 63 bytes, so this is a case that actually occurs.

Comparison is case-insensitive on both sides, since SNI hostnames are.

## How to protect — and why this one does not

Same reasoning as `cipher_suite`: this fires on a handshake bmcweb will refuse
anyway, and the blocklist applies to a source address on every port, so enforcing
on an odd hostname could lock an administrator out of SSH. A Redfish event is the
proportionate response.

## What to hook

`xdp_tls`, `SEC("xdp")`. See [`programs/DESIGN.md`](../../programs/DESIGN.md).

## How to trigger it

See [README.md § Exercising the Detections](../../../../../README.md#exercising-the-detections)
for the runnable recipe and this detection's live-verification status.

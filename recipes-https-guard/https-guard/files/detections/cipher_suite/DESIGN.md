# Weak cipher suite

**Emits:** `OemSecurityEvent.1.0.HttpsWeakCipherSuiteDetected` (Warning) ·
**Enforces:** **no — alert only.** Not an oversight; see below.

## Why detect this

A client asking a BMC for RC4 or EXPORT-grade crypto is a meaningful signal even
when the handshake then fails: an ancient management tool, a misconfiguration, or
a downgrade probe sizing up what the server will accept.

**Offering is not negotiating.** bmcweb refuses anything it does not like, so
this fires on *intent* rather than outcome. Hence Warning rather than Critical —
unlike [`tls_version`](../tls_version/DESIGN.md), which can fire on a version
that actually was negotiated.

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
and the SNI extension — an offer, not yet a negotiated outcome. Same reason as
[`sni`](../sni/DESIGN.md): nothing later in this diagram ever exposes the
offered list again, so a wire-side hook is the only place this is visible.

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

### What "weak" covers

22 code points across five categories, curated in `weak_cipher_suites.hpp`: NULL
encryption, EXPORT-grade key sizes, RC4, single-DES and 3DES, and anonymous key
exchange. Each carries a short reason that goes into the message, so the event
says *why* a suite is weak rather than only naming it.

Capture is capped at 32 suites, and the true offered count travels separately —
so a clipped list is distinguishable from a genuinely short one, and the message
reports both.

## How to protect — and why this one does not

This detection originally set `actionable = true`. Live testing settled it
immediately: the blocklist is enforced in XDP against the source address for
**every port**, so one crafted ClientHello offering RC4 blocklisted the peer and
instantly cut off the SSH session running the test.

On a real BMC that is a self-inflicted denial of service. One scanner packet, or
one legacy tool behind a shared NAT address, would lock every administrator
sharing that address out of *all* BMC services for the blocklist TTL. Merely
offering a weak suite in a handshake bmcweb then refuses does not justify that.

So the response is proportionate to the signal: a Redfish event, and nothing
else. If a site wants enforcement here it belongs behind an explicit opt-in, not
the default. Background in
[`actions/blocklist/DESIGN.md`](../../actions/blocklist/DESIGN.md).

## What to hook

`xdp_tls`, `SEC("xdp")` on the NIC RX path. Attach mechanics — the BPF-link
ownership that makes attachment leaks structurally impossible, and the
native→generic→skip fallback — are in
[`programs/DESIGN.md`](../../programs/DESIGN.md).

## How to trigger it

See [README.md § Exercising the Detections](../../../../../README.md#exercising-the-detections)
for the runnable recipe and this detection's live-verification status.

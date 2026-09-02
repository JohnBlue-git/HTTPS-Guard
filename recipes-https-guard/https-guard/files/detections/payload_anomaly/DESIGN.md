# Payload anomaly

**Emits:** `OemSecurityEvent.1.0.HttpsPayloadAnomalyDetected` (Warning) ·
**Enforces:** yes — blocklist the peer, plus a TCP teardown when the full
4-tuple is known.

## Why detect this

Signature matching on HTTPS traffic is normally impossible without terminating
the connection: on the wire it is ciphertext. And the traffic worth inspecting on
a BMC is exactly the traffic that is encrypted — Redfish requests carrying
credentials, power commands, firmware payloads.

There is a second reason, less obvious and arguably more important. The uprobe
attaches to `libssl.so` itself, not to bmcweb, so **every process on the system**
that links that library and calls those functions fires it. A compromised BMC
service exfiltrating data over TLS, or a tool that has no business making
outbound HTTPS connections at all, shows up here exactly as a legitimate client
does.

## How to detect

A uprobe is a breakpoint on a function's address *inside a specific ELF file*.
The kernel fires it for every process that has that file mapped and calls that
function. Which means it sees the call **before encryption on write, after
decryption on read** — the actual plaintext OpenSSL is about to hand to the
kernel, or has just received from it.

```
REQUEST — Client → bmcweb  (e.g. "GET /redfish/v1/... HTTP/1.1")

  Client sends CIPHERTEXT over the wire
              │
              ▼
  ── kernel: TCP recv, handed to OpenSSL's BIO ──
              │
              ▼  still CIPHERTEXT
  SSL_read(ssl, buf, num)
    buf is an OUTPUT param — OpenSSL decrypts internally and
    fills buf DURING the call, so it is uninitialised at entry
              │
              ▼  entry probe: stash ssl/buf pointers, keyed by pid_tgid
        ...OpenSSL decrypts...
              │
              ▼  return probe (retprobe=true): read the real byte count
                 from PT_REGS_RC — `num` is only the buffer's capacity —
                 THEN read buf, now populated
        ◄── uprobe reads the PLAINTEXT request HERE
              │
              ▼  PLAINTEXT from here on
  bmcweb request handling (routing, auth, Redfish logic)


RESPONSE — bmcweb → Client  (e.g. an HTTP/1.1 200 with a JSON body)

  bmcweb has a PLAINTEXT response ready
              │
              ▼  PLAINTEXT
  SSL_write(ssl, buf, num)
    buf[0..num) is plaintext and already valid AT ENTRY
        ◄── uprobe reads the PLAINTEXT response HERE
              │
              ▼  ...OpenSSL encrypts...
  ── kernel: TCP send, ciphertext handed to the wire ──
              │
              ▼  CIPHERTEXT from here on
  Client receives CIPHERTEXT over the wire
```

**Why `SSL_read` needs two probes and `SSL_write` needs one.** `SSL_write`'s
buffer already holds what is about to be sent, so a single entry probe reads it
directly. `SSL_read`'s buffer is the opposite — an output parameter OpenSSL fills
*during* the call — so reading it at entry captures uninitialised garbage, not the
received request. Hence a paired probe: the entry half stashes the `ssl`/`buf`
pointers in a small hash map keyed by `pid_tgid` (register state at return no
longer holds the original arguments), and the return half retrieves them.

**And it must use `PT_REGS_RC`, not `num`.** The return value is how many bytes
were actually read; `num` is only the buffer's *capacity*. Using `num` would copy
trailing stale bytes as though they had been received.

That asymmetry is why the read side was added second, and why it matters:
`SSL_write` alone only ever sees what bmcweb **sends**. Attacker-controlled bytes
— a crafted URL, a malicious header — arrive in what bmcweb **receives**. Watching
only the write side meant this detection fired only when bmcweb happened to
reflect bad input back in a response.

**Source for all of this:** the two BPF probes, the `pid_tgid`-keyed scratch
map and the 127-byte copy are in
[`ssl_uprobe.bpf.h`](../../programs/ssl_uprobe/ebpf/ssl_uprobe.bpf.h)
(`uprobe/ssl_write`, and the `uprobe/ssl_read` entry/exit pair); the `pid = -1`
attach itself is in
[`SslUprobeProgram.cpp`](../../programs/ssl_uprobe/src/SslUprobeProgram.cpp).

### Where this sits in the handshake

```
Client                                                          bmcweb (server)
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
  ├── HTTP REQUEST, e.g. GET /redfish/v1/... (ciphertext) ─────────────▶│  ◄── bmcweb: SSL_read() RETURN reads the just-decrypted buf
  │◀── HTTP RESPONSE, e.g. 200 OK + JSON body (ciphertext) ─────────────┤  ◄── bmcweb: SSL_write() ENTRY reads buf before OpenSSL encrypts
  │     (repeats for every request/response pair on this connection)     │
  ├── TCP FIN or RST ──────────────────────────────────────────────────▶│
```

**Where this sits:** the application-data lines near the bottom, at the exact
moment `SSL_write`/`SSL_read` crosses the OpenSSL boundary — plaintext on both
sides of that call, ciphertext everywhere else in this diagram. The XDP path
instead watches for traffic that never gets this far at all: plaintext HTTP
arriving on port 443, which fails before any `0x16` message above is ever sent.

### The rule

Eight case-insensitive substrings against the captured plaintext:

```
../..    union select    or 1=1    drop table
/etc/passwd    %2e%2e%2f    cmd.exe    wget http
```

Path traversal raw and percent-encoded, SQL injection, command-execution markers.
Deliberately a small high-signal list rather than a ruleset: this runs per event
on a BMC, and a false positive here **enforces**.

**Source:** the list and its `evaluate()` are in
[`PayloadAnomalyDetector.hpp`](PayloadAnomalyDetector.hpp), against the event
struct in [`PayloadEvent.hpp`](PayloadEvent.hpp). The `IDetection` glue that
reaches this rule from either hook's raw bytes is
[`PayloadAnomalyDetection.hpp`](PayloadAnomalyDetection.hpp) — templated on the
raw struct so one definition serves both the uprobe and XDP paths (see
`detections/CLAUDE.md`'s "Why the rules take concrete types, and where
concepts went").

### The XDP path sees something different

Plaintext HTTP arriving on port 443 — a misconfigured client, a protocol-confusion
probe, a scanner. That traffic usually never reaches `SSL_write` at all, because
the TLS handshake fails before any application code runs, so the wire is the only
place it is visible.

The BPF-side parsing that produces this hook's `payload_snippet` is in
[`xdp_tls.bpf.h`](../../programs/xdp_tls/ebpf/xdp_tls.bpf.h); the host-side hook
is [`XdpTlsProgram.cpp`](../../programs/xdp_tls/src/XdpTlsProgram.cpp).

## How to protect

The verdict is actionable: blocklist the peer, and tear the connection down if a
full 4-tuple is known. `SOCK_DESTROY` is what makes this enforceable *despite*
TLS — it destroys the kernel socket for that exact 4-tuple, which the application
and its encryption have no say over. This tail (`dispatchVerdict()`) is shared by
every detection, not specific to this one — see
[`dispatch.cpp`](../core/engine/dispatch.cpp).

For a uprobe event the tuple is not known up front and has to be recovered from
`/proc`, lazily, only because this verdict enforces. That resolution **fails
closed**: if the PID owns more than one established connection the event is left
unresolved and enforcement declines rather than guessing, because acting on the
wrong connection would blocklist an uninvolved host. This lazy resolution and its
fail-closed rule live in
[`proc_peer_resolver.hpp`](../../programs/ssl_uprobe/src/proc_peer_resolver.hpp),
behind the [`IPeerResolver`](../core/event/IPeerResolver.hpp) interface every
uprobe-fed detection shares.

## What to hook

| Source | Hook | Gives |
|---|---|---|
| `ssl_uprobe` | `uprobe/ssl_write` (entry) + `uprobe/ssl_read` (entry + `retprobe`) on `libssl.so`, `pid = -1` | up to 127 bytes of plaintext, either direction |
| `xdp_tls` | `SEC("xdp")` | plaintext-HTTP-on-443 bytes |

Attach mechanics, including why `pid = -1` is deliberate, are in
[`programs/DESIGN.md`](../../programs/DESIGN.md).

## Limits worth knowing

- **Capped at 127 bytes per call.** A signature landing entirely past that offset in a single call is not seen. Observed directly: a signature in a late custom header did not fire, while the same signature early in the request path did — on both directions.
- **Process identity is not verified.** `pid = -1` means this cannot distinguish bmcweb from anything else using the same library, and the reported process name is self-reported `comm`, changeable by the process itself (`prctl(PR_SET_NAME)`, or just naming the binary anything). Treat it as a hint. [`cert_access/`](../cert_access/DESIGN.md) is the stronger mechanism aimed at a related but distinct question.
- **One request usually produces two events** — the client's write and bmcweb's read of the same bytes. The second frequently cannot be attributed to a connection and declines to enforce.

## How to trigger it

See [README.md § Exercising the Detections](../../../../../README.md#exercising-the-detections)
for the runnable recipe and this detection's live-verification status.

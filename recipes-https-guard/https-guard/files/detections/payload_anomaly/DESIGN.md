# Payload anomaly

**Emits:** `OemSecurityEvent.1.0.HttpsPayloadAnomalyDetected` (Warning) ·
**Enforces:** yes.

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
Process (e.g. bmcweb)
       │  calls SSL_write(ssl, buf, num)        calls SSL_read(ssl, buf, num)
       ▼                                         ▼
┌──────────────────────────────────────┐   ┌────────────────────────────────────────┐
│ OpenSSL (libssl.so.3), userspace     │   │ SSL_read(ssl, buf, num)                │
│                                      │   │   buf is an OUTPUT param — OpenSSL     │
│ SSL_write(ssl, buf, num)             │   │   fills it DURING the call, so it is   │
│   buf[0..num) is plaintext and       │   │   uninitialised at entry               │
│   already valid AT ENTRY             │   │       ▼                                │
│      ◄── uprobe attached HERE        │   │ entry probe: stash ssl/buf ptrs,       │
│                                      │   │   keyed by pid_tgid                    │
│   ...encrypts, writes to the socket  │   │       ▼                                │
└──────────────────┬───────────────────┘   │ return probe (retprobe=true): read the │
                   │ encrypted only        │   real byte count from PT_REGS_RC,     │
                   ▼ from here on          │   THEN read buf — now populated        │
             TCP socket → wire             └──────────────────┬─────────────────────┘
                                                              ▼ decrypted only
                                                        TCP socket ← wire
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

### Where this sits in the handshake

```
Client                                                          bmcweb (server)
  │                                                                    │
  ├── TCP SYN ─────────────────────────────────────────────────────────▶│
  │◀──────────────────────────────────────────────────────── SYN-ACK ──┤
  ├── ACK ──────────────────────────────────────────────────────────────▶│
  │                    (TCP handshake complete; no TLS yet)            │
  │                                                                    │
  ├── ClientHello (0x16, unencrypted) ─────────────────────────────────▶│
  │      legacy_version · cipher_suites[] · extensions (incl. SNI)     │
  │◀── ServerHello, Certificate, ... (0x16) ─────────────────────────────┤
  ├── Finished (0x16) ───────────────────────────────────────────────────▶│
  │◀── Finished (0x16) ──────────────────────────────────────────────────┤
  │              (TLS handshake complete; ssl->version now set)        │
  │                                                                    │
  ├── application data, e.g. an HTTP request ────────────────────────────▶│
  │◀── application data, e.g. an HTTP response ──────────────────────────┤
  │                                                                    │
  ├── TCP FIN or RST ───────────────────────────────────────────────────▶│
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

### The XDP path sees something different

Plaintext HTTP arriving on port 443 — a misconfigured client, a protocol-confusion
probe, a scanner. That traffic usually never reaches `SSL_write` at all, because
the TLS handshake fails before any application code runs, so the wire is the only
place it is visible.

## How to protect

The verdict is actionable: blocklist the peer, and tear the connection down if a
full 4-tuple is known. `SOCK_DESTROY` is what makes this enforceable *despite*
TLS — it destroys the kernel socket for that exact 4-tuple, which the application
and its encryption have no say over.

For a uprobe event the tuple is not known up front and has to be recovered from
`/proc`, lazily, only because this verdict enforces. That resolution **fails
closed**: if the PID owns more than one established connection the event is left
unresolved and enforcement declines rather than guessing, because acting on the
wrong connection would blocklist an uninvolved host.

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

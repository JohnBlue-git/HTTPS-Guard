# `ssl_uprobe` — OpenSSL `SSL_write`/`SSL_read` uprobes (PRIMARY hook)

## Why detect this

bmcweb serves the entire Redfish management API — sensor readings, power control, firmware update, user credentials — over HTTPS on port 443. TLS is the *only* thing standing between that traffic and anyone who can see the wire. Two distinct things can go wrong here, and this hook exists to catch both:

**1. A downgraded or legacy TLS connection.** TLS 1.0/1.1 (and SSLv3, though OpenSSL 3.x won't even negotiate that far) carry known, practical breaks — POODLE, BEAST, weak/no forward secrecy, RC4-class ciphers. A client that negotiates one of these isn't a theoretical risk: it's a live downgrade attack in progress, a misconfigured/legacy management tool, or a client actively trying to weaken the channel before doing something else. Once negotiated, everything on that connection — including whatever credentials or commands ride over it — is exposed to anyone positioned on the network path.

**2. A malicious or compromised process talking TLS on this BMC at all.** This hook attaches to `SSL_write`/`SSL_read` in `libssl.so` itself, not to bmcweb specifically — every process on the system that links this exact library and calls either function fires it, unconditionally. That's deliberate: a compromised BMC service (or something that shouldn't be making outbound TLS connections at all) exfiltrating data, or a tool other than bmcweb probing something over HTTPS, shows up here exactly the same way a legitimate client does. It's also the hook's biggest open gap — see [Known limitations](#known-limitations) below.

**3. An attack signature arriving in the request, not just the response.** `SSL_write` alone only ever sees what bmcweb *sends*. Attacker-controlled bytes — a crafted URL, a malicious header — arrive in what bmcweb *receives*, i.e. `SSL_read`. Watching only the write side means `PayloadAnomalyDetector` only ever catches an attack if bmcweb happens to reflect the bad input back in its response. This hook mirrors both directions specifically to close that gap — see [How to detect](#how-to-detect) for why `SSL_read` needs a fundamentally different probe shape than `SSL_write`.

```
┌─────────────────────────────────────────────────────────────┐
│  Who might trigger this hook, and why it matters            │
│                                                             │
│  Legitimate: curl / Redfish client → bmcweb, normal TLS 1.3 │
│      → nothing fires; classified OK, just logged            │
│                                                             │
│  Attack #1: legacy/downgrading client → bmcweb, TLS < 1.2   │
│      → TlsVersionDetector fires: Critical                   │
│                                                             │
│  Attack #2: any process on the BMC ≠ bmcweb, calling        │
│             SSL_write via the same libssl.so                │
│      → hook fires identically — the uprobe doesn't know     │
│        or care which process it is (comm is self-reported   │
│        and spoofable; nothing here verifies identity —      │
│        that's the whole point of the planned BPF-LSM        │
│        cert-access guard, a *much* stronger mechanism)      │
└─────────────────────────────────────────────────────────────┘
```

## How to detect

A **uprobe** is a breakpoint set on a function's address *inside a specific ELF file* (here, `libssl.so.3`) — the kernel fires it for every process that has that file mapped and calls that function, regardless of which process it is. That's fundamentally different from a kprobe (kernel function) or an XDP hook (packets on the wire): a uprobe sees the call **before encryption on write, after decryption on read** — i.e., it sees the actual plaintext OpenSSL is about to hand to the kernel, or just received from it.

```
Process (e.g. bmcweb)
       │
       │  calls SSL_write(ssl, buf, num)         calls SSL_read(ssl, buf, num)
       ▼                                          ▼
┌───────────────────────────────────────────┐    ┌────────────────────────────────────────┐
│  OpenSSL (libssl.so.3), userspace         │    │  OpenSSL (libssl.so.3), userspace       │
│                                           │    │                                          │
│  SSL_write(ssl, buf, num)                 │    │  SSL_read(ssl, buf, num)                 │
│    ├─ ssl->version   (already negotiated) │    │    buf is an OUTPUT param — OpenSSL      │
│    ├─ buf[0..num)    (plaintext, pre-TLS,  │    │    fills it DURING the call, so it's     │
│    │   already valid at ENTRY)            │    │    uninitialized at entry                │
│    └─ encrypts, then writes to the socket │    │        ▼                                 │
│         ◄── uprobe attached HERE          │    │  entry probe (SEC("uprobe/ssl_read")):   │
│             SEC("uprobe/ssl_write")       │    │  stash ssl/buf ptrs, keyed by pid_tgid    │
└───────────────────┬───────────────────────┘    │        ▼                                 │
                    │  encrypted bytes only      │  return probe (retprobe=true): read       │
                    │  from here on              │  actual bytes-read count from PT_REGS_RC, │
                    ▼                            │  THEN read buf — now populated            │
              TCP socket → wire                  └──────────────────┬───────────────────────┘
                                                                     │  decrypted bytes only
                                                                     ▼  up to this point
                                                              TCP socket ← wire
```

**Why `SSL_read` needs two probes, not one.** `SSL_write`'s `buf` already holds the plaintext to send when the call is entered, so a single entry-only uprobe can read it directly. `SSL_read`'s `buf` is the opposite: an output parameter OpenSSL fills *during* the call, so at entry it's uninitialized — reading it there would capture garbage, not the received request. The fix is a paired entry+return uprobe: `https_guard_ssl_read_entry` stashes the `ssl`/`buf` pointers (keyed by `pid_tgid`, into a small `BPF_MAP_TYPE_HASH` scratch map — register state at return no longer holds the original call's arguments), and `https_guard_ssl_read_exit` (attached with `retprobe=true`) retrieves them, reads the actual bytes-read count from the return value (`PT_REGS_RC`, **not** the original `num` argument — that's only the buffer's *capacity*, and using it instead would copy trailing stale/uninitialized bytes as if they'd been received), and only then reads `buf`.

**What `ssl_uprobe.bpf.h` actually reads**, on every call, from every process, for both directions:

| Field | How | Notes |
|---|---|---|
| `tls_version` | `bpf_probe_read_user()` at `SSL_VERSION_OFFSET` into `ssl` | Offset is build-time-generated (`scripts/gen_ssl_offset.c`) — OpenSSL 3.x made `struct ssl_st` opaque, and it's a userspace type with no kernel BTF entry, so CO-RE can't resolve it either. Architecture-specific: 36 bytes on ARM 32-bit, 20 on x86_64. Identical for both directions — the negotiated version doesn't depend on which way the bytes are flowing. |
| `payload_snippet` | `bpf_probe_read_user()`, up to 127 bytes of `buf` | What bmcweb is **sending** (`SSL_write`) or **receiving** (`SSL_read`) — see [Why detect this](#why-detect-this), point 3. |
| `direction` | Set by the hook itself (`HG_UPROBE_DIR_WRITE` / `HG_UPROBE_DIR_READ`), not read from the process | Surfaced to userspace as `hg_event.is_inbound` — `true` for `SSL_read` (the request side, where attacker-controlled input actually lives), `false` for `SSL_write`. |
| `pid` / `tgid` / `process` (comm) | `bpf_get_current_pid_tgid()` / `bpf_get_current_comm()` | `process` is self-reported by the kernel's task struct and can be changed by the process itself (`prctl(PR_SET_NAME)`, or just naming the binary anything) — treat it as a hint, not an identity proof. |

The BPF side makes **no decision** — no severity, no violation flag, nothing, for either direction. It fills these fields and submits to the shared ring buffer (`bpf_ringbuf_submit`), unconditionally returning 0 (pass). `SslUprobeProgram::parseEvent()` (userspace) then:
1. Calls the libbpf-free `parseUprobeEventFields()` (in `parse_uprobe_event.hpp`, extracted specifically to be unit-testable) to copy these fields into the common `hg_event`, regardless of which direction produced them.
2. Resolves the PID to an actual TCP socket 4-tuple via `ProcPeerResolver::getTcpSockets()` — parsing `/proc/<pid>/net/tcp`, preferring a connection on port 443 — since a uprobe has no direct access to socket info the way a network-layer hook would.

## How to defend (enforcement)

```
uprobe_event ──► SslUprobeProgram::parseEvent() ──► hg_event
                                                        │
                                                        ▼
                              detectors_[HG_SOURCE_UPROBE], in order:
                              ┌─────────────────────────────────────┐
                              │ 1. TlsVersionDetector               │
                              │    tls_version > 0 && < TLS 1.2?    │
                              │    → Verdict{Critical, actionable}  │
                              ├─────────────────────────────────────┤
                              │ 2. PayloadAnomalyDetector           │
                              │    SQLi/traversal signature in      │
                              │    payload_snippet?                 │
                              │    → Verdict{Warning, actionable}   │
                              └─────────────────────────────────────┘
                                                        │
                                     no match ──────────┼────────── match
                                        │                            │
                                        ▼                            ▼
                          Verdict{OK, not actionable}      Verdict{actionable=true}
                                        │                            │
                                        │                            ▼
                                        │            src_ip_v4 resolved?
                                        │                 │yes         │no
                                        │                 ▼            ▼
                                        │      BlockTcpAction   log a warning:
                                        │      (SOCK_DESTROY,   "no TCP sockets
                                        │       kills the       found, cannot
                                        │       connection      SOCK_DESTROY"
                                        │       at the kernel
                                        │       level — works
                                        │       even though
                                        │       the app thinks
                                        │       it's still
                                        │       encrypted)
                                        │            +
                                        │      BlocklistAddAction
                                        │      (writes source IP
                                        │       into the shared BPF
                                        │       map — feeds Tier 1's
                                        │       synchronous XDP_DROP
                                        │       for this source's
                                        │       *next* packet, on
                                        │       platforms with XDP)
                                        │                 │
                                        └────────────┬────┘
                                                     ▼
                                          LogAction (always,
                                          regardless of severity —
                                          Redfish event JSON)
```

`SOCK_DESTROY` (via `TcpDestroyer`, `NETLINK_INET_DIAG`) is what makes this enforceable at all despite TLS: it tears down the kernel-level TCP socket for the exact 4-tuple, which the application (and its encryption) has no say over — the connection simply stops existing out from under it.

## What's hooked, concretely

- **Hook points:** `SSL_write(SSL *ssl, const void *buf, int num)` and `SSL_read(SSL *ssl, void *buf, int num)`, both in `HTTPS_GUARD_SSL_LIB` (default `/usr/lib/libssl.so.3`, configurable via `https-guard.conf`).
- **Attach:** `attachOneUprobe()` (in `SslUprobeProgram.cpp`) wraps `bpf_program__attach_uprobe_opts(prog, -1, lib_path, 0, &opts)` for each of the three BPF programs below — `pid = -1` means *every* process, not just bmcweb. See [Why detect this](#why-detect-this) for why that's deliberate.
- **BPF programs, all in `ssl_uprobe.bpf.h`:**
  - `SEC("uprobe/ssl_write")` — `https_guard_ssl_write`, entry-only.
  - `SEC("uprobe/ssl_read")` — `https_guard_ssl_read_entry` (entry, stashes args) and `https_guard_ssl_read_exit` (`retprobe=true`, does the actual read + submit).
- **Raw event struct:** `struct uprobe_event` in `ssl_uprobe_event.h` — carries a `direction` field (`enum hg_uprobe_direction`) distinguishing the two; no socket info (unavailable from uprobe context), resolved separately by `ProcPeerResolver`.
- **Attach criticality:** `SSL_write` attaching is this hook module's required signal (unchanged from before the `SSL_read` mirror); either half of the `SSL_read` pair failing to attach is logged but non-fatal, since `SSL_write` alone is still fully functional. The daemon only actually refuses to start if *zero* hooks (this one and `xdp_tls`) attach at all — see `programs/CLAUDE.md`.

## Known limitations

**Process identity isn't verified.** `pid = -1` means this hook can't distinguish bmcweb from any other process using the same OpenSSL library, and the `process` field it reports is self-reported and spoofable. Today, nothing here checks whether the calling binary actually *is* bmcweb (its real executable path, its cgroup, anything harder to fake than `comm`). The BPF-LSM certificate-access guard (`programs/lsm_cert_guard/`) is a different, stronger mechanism aimed at a related but distinct question — *who's opening `/etc/ssl/certs/https/server.pem`* — using a real-executable-path check (resolved in userspace via `/proc/<pid>/exe`, not self-reported `comm`); see its own `DESIGN.md` for why even that mechanism can only enforce asynchronously on this hardware, not synchronously the way file access denial otherwise might suggest.

**Payload snippets are capped at 127 bytes.** Both directions truncate to `HG_PAYLOAD_SNIPPET_LEN - 1`. An attack signature landing entirely past that offset in a single `SSL_write`/`SSL_read` call — e.g. deep in a long header list — won't appear in `payload_snippet` and won't be caught by `PayloadAnomalyDetector`. Observed directly during ticket 02's live verification: a signature placed in a custom header didn't trigger, while the same signature placed early in a request path (`/etc/passwd`) did, on both directions.

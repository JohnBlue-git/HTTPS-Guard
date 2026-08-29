# 02 — Mirror the SSL_write uprobe onto SSL_read

**What to build:** A second uprobe on OpenSSL's `SSL_read(SSL *ssl, void *buf, int num)`, capturing the plaintext a process *receives* the same way `ssl_uprobe.bpf.h` already captures what it *sends*. Route its events through the exact same detectors (`TlsVersionDetector`, `PayloadAnomalyDetector`) and the exact same enforcement path — this closes the gap documented in `programs/ssl_uprobe/DESIGN.md`'s "Known limitations": attacker-controlled input arrives in requests (`SSL_read`), not responses (`SSL_write`), so today's payload-anomaly rules mostly only fire if a response happens to reflect bad input back.

**Blocked by:** None — can start immediately

**Status:** done

- [x] `SSL_read` is hooked via a uprobe, capturing at minimum: the negotiated TLS version, a plaintext snippet of what was read, and PID/process — the same fields `uprobe_event` already carries for the write side
- [x] Both directions' events are classified by the same detector registry entries already registered for the uprobe source — no new detector is required for this ticket, and no existing detector's logic changes
- [x] The two directions remain distinguishable in the raw event (e.g. a `direction` field, or two hooks sharing one raw struct) — resolve the exact mechanism against what's simplest given `IHookModule`'s one-`eventSource()`-per-module shape; the natural fit is one hook module attaching both `SSL_write` and `SSL_read` uprobes and tagging its own parsed events, not two modules racing to claim the same `hg_event_source`
- [x] Enforcement (BlockTcpAction/BlocklistAddAction) fires identically regardless of which direction triggered the verdict
- [x] Unit tests cover the new parsing/tagging logic in isolation, following the same pattern as the existing detector tests
- [x] Verified against a real request containing one of `PayloadAnomalyDetector`'s existing signatures (e.g. a URL query string containing `union select`) — confirms this ticket actually closes the gap it exists to close, not just that the plumbing compiles

## Comments

Went with one `SslUprobeProgram` attaching both directions, tagged via a new `direction` field on `uprobe_event` (repurposing what was unused padding) — matches the ticket's suggested shape exactly.

**The real subtlety here:** `SSL_write`'s buffer already holds plaintext at entry (a simple entry-only uprobe works), but `SSL_read`'s buffer is an *output* parameter OpenSSL fills during the call — an entry-only hook would have captured uninitialized memory, not the received request. Fixed with a paired entry+return uprobe (`https_guard_ssl_read_entry`/`https_guard_ssl_read_exit`, the latter attached with `retprobe=true`): the entry probe stashes `ssl`/`buf` pointers keyed by `pid_tgid` into a small scratch map (register state at return no longer holds the original call's arguments), and the exit probe retrieves them, reads the actual bytes-read count from `PT_REGS_RC(ctx)` (not the original `num` argument, which is only the buffer's *capacity* — using it instead would copy trailing stale bytes as if they were received data), and only then reads `buf`.

`SSL_write` attaching is still this hook module's required signal (unchanged from before); if either half of the `SSL_read` pair fails to attach, it's logged but non-fatal, since `SSL_write` alone is still fully functional.

Extracted the raw-struct-to-`hg_event` field mapping into `parse_uprobe_event.hpp` (a free function, no `/proc` or libbpf dependency) specifically so the new direction-tagging logic is genuinely unit-testable — this is the same class of seam the original spec scoped detector testing to, just one layer over. 12/12 test cases, 26/26 assertions pass, compiled and run directly with g++ (`-Wall -Wextra`, zero warnings).

Real end-to-end verification (a live request containing a `PayloadAnomalyDetector` signature, actually getting caught via the new `SSL_read` path) needs a real kernel/QEMU boot, same as the rest of this hook — in progress on the shared build machine.

**Update:** Verified against a live QEMU boot (johnblue, SLIRP). Two early attempts appeared not to trigger and were investigated via `/sys/kernel/debug/tracing/trace_pipe` raw `bpf_printk` output before concluding both were test-design misses, not code bugs:
- `curl -s -k "https://127.0.0.1/redfish/v1/...?query=union%2520select..."` — curl percent-encodes the space in `union select` to `%20`, so the literal rule substring never appears on the wire; correctly did not fire.
- A custom `X-Test-Injection: union select` header — likely landed outside the 127-byte payload snippet window (`HG_PAYLOAD_SNIPPET_LEN`); not conclusively diagnosed further since the third test below made it moot.

The raw trace_pipe output first confirmed the entry+return pairing itself is mechanically correct end-to-end on the real target kernel: `curl-1146 ... SSL_write hit pid=1146 num=133` immediately followed by `bmcweb-252 ... SSL_read hit pid=252 num_read=133` — same byte count, write then read, exactly as designed.

A third test — a path-traversal signature (`/etc/passwd`, no spaces, no encoding, guaranteed early in the byte stream) — definitively closed this out. `journalctl -u https-guard-daemon` showed **both directions catching the same payload**: `curl` (PID 1146, then again PID 1283 on a repeat) flagged on `direction=write` (its own outbound request), and `bmcweb` (PID 252) flagged on `direction=read` — the new mirror — for the exact same signature, both at `severity=Warning`, both correctly triggering `BlocklistAddAction ... rule '/etc/passwd'`. This is exactly the gap this ticket was built to close: before this ticket, only the `SSL_write` (response) side was observed, so an attack signature arriving in a *request* with no reflected response would have gone undetected; now the request side alone is sufficient.

Two pre-existing, out-of-scope observations noted for the record (neither is a regression from this ticket, neither blocks it):
- `BlockTcpAction: SOCK_DESTROY failed ... netlink_error=-2 (No such file or directory)` — the short-lived curl connection had already closed by the time enforcement ran; `TcpDestroyer` targeting an already-gone socket is a pre-existing edge case, not something `direction` tagging introduced.

  **Update — that explanation was wrong.** While verifying ticket 04 the real cause surfaced: `TcpDestroyer` feeds host-byte-order ports into netlink's `idiag_sport`/`idiag_dport`, which require network order, so the kernel looks up a byte-swapped port and correctly answers `-ENOENT`. It fails the same way against a live, mid-handshake connection, so "the socket had already closed" was not what was happening. Still pre-existing and still not introduced by this ticket, but it means TCP-kill enforcement has never actually worked — tracked as ticket 08.
- The logged source IP reads as `1.0.0.127` rather than `127.0.0.1` — an artifact of this being a loopback self-test topology (guest curling itself), not seen with real external peers; `ProcPeerResolver` wasn't touched by this ticket.

  **Update — that explanation was also wrong.** It is a byte-order bug in `ProcPeerResolver::parseProcNetEntry`, which applied a byte swap that `/proc/net/tcp`'s format does not call for, reversing every resolved address. Nothing to do with loopback: it would have blocklisted `1.0.0.127` instead of `127.0.0.1` for real external peers too — enforcement aimed at an entirely different address than the one observed. Confirmed by comparing the resolved tuple against `getsockname`/`getpeername` on a socket whose real addresses were known, and fixed under ticket 13.

  Two wrong explanations in this one comment block (this, and the `SOCK_DESTROY` one above) came from reading a plausible story into log output instead of checking it. Both surfaced later only because something else forced a closer look at the same lines.


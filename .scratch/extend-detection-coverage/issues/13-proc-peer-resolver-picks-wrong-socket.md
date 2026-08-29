# 13 — ProcPeerResolver returns namespace-wide sockets, so enforcement can target the wrong peer

**What to build:** Make the uprobe path's peer resolution actually identify the connection the probed process is using, or fail closed when it can't — instead of selecting a socket that may belong to an unrelated process.

**Blocked by:** None — can start immediately

**Status:** done

## The bug

`ProcPeerResolver::getTcpSockets(pid)` documents itself as returning

> all established TCPv4 connections **belonging to that process**

It does not filter by process. `/proc/<pid>/net/tcp` is **network-namespace**-scoped, not process-scoped: it lists every TCP socket in the netns that pid belongs to. Identifying which of those a process actually owns requires matching socket inodes against `/proc/<pid>/fd/*`, which this code never does. On a BMC — where essentially everything shares one netns — that means the returned list is the entire system's TCP table (505 entries on the dev host).

`SslUprobeProgram::parseEvent` then selects from that list:

```cpp
const TcpSocketEntry* best = &sockets[0];
for (const auto& sock : sockets) {
    if (sock.dst_port == 443) { best = &sock; break; }
}
```

So: first entry whose *remote* port is 443, else whichever entry happened to be parsed first.

For the primary case this hook exists to watch, that heuristic is pointed the wrong way. bmcweb is the HTTPS **server**, so its connections have *local* port 443 and an ephemeral remote port. An entry with `dst_port == 443` is therefore a *client* connection to some HTTPS server — not bmcweb's own socket. When no entry matches, `sockets[0]` is arbitrary.

## Why this matters

The selected 4-tuple is what enforcement acts on:

- `BlocklistAddAction` blocklists `src_ip_v4` — and the XDP blocklist drops that address on **every port**, not just 443 (established in ticket 04, where a blocklist entry cut off the test's own SSH session). Selecting the wrong socket therefore risks locking out an uninvolved host.
- `BlockTcpAction` targets the full 4-tuple for `SOCK_DESTROY`, so it would tear down someone else's connection — currently masked by ticket 08 (the byte order bug means `SOCK_DESTROY` never matches anything at all), but that mask disappears the moment 08 is fixed.

**These interact badly: fixing 08 without fixing this turns a no-op into a wrong-target action.** Sequence accordingly.

## Evidence

Read directly from the code — the function opens `/proc/<pid>/net/tcp`, loops every line, and pushes each parsed entry with no ownership check. The docstring's "belonging to that process" is simply not implemented.

**Then confirmed empirically, and it's worse than "may pick the wrong process".** Measuring `/proc/net/tcp` on the dev host:

```
state 0A (LISTEN)      : 447 entries
state 01 (ESTABLISHED) :  42 entries
```

The current code never filters on state either, so the overwhelming majority of candidates are *listening* sockets — which have no peer at all (`rem_address` is `00000000:0000`). Since the `dst_port == 443` heuristic only matches client-side connections, a bmcweb event normally falls through to `sockets[0]`, i.e. very likely a LISTEN entry.

That is exactly what this session's own logs show:

```
BlockTcpAction: SOCK_DESTROY failed for 1.0.0.127:3095 -> 0.0.0.0:0 reason=...
```

`-> 0.0.0.0:0` is a listening socket's blank remote address. So enforcement was being aimed at a non-connection — and the `1.0.0.127` on the left is the byte-order bug from ticket 08 showing up in the same line. Both defects were visible in output that had already been read during ticket 02's verification and were mistaken for "the connection had already closed".

Useful column facts (verified on a live `/proc/net/tcp`, not from memory): `col[3]` is state (`01` = ESTABLISHED, `0A` = LISTEN), and `col[9]` is the socket inode — the field needed to match against `/proc/<pid>/fd/*`, and the one the current parser skips with a `(void)0` placeholder.

- [x] Peer resolution either genuinely identifies a socket owned by the probed PID (inode match against `/proc/<pid>/fd/*`), or explicitly reports "unresolved" rather than guessing
- [x] When resolution fails or is ambiguous, enforcement does **not** fire on a guessed 4-tuple — the existing "no TCP sockets found, cannot SOCK_DESTROY" path already demonstrates the fail-closed behaviour to extend
- [x] The server-side case is handled correctly: for bmcweb, the relevant socket has *local* port 443, so any port heuristic that survives must account for direction (and `hg_event.is_inbound` from ticket 02 is available to disambiguate)
- [x] The docstring is corrected to describe what the function actually does — the current wording is what made this look correct on review
- [x] Verified that the resolved 4-tuple matches the connection genuinely in use, checked against an independent source (`ss`/`netstat` output or the client's own port), not just that *some* 4-tuple was produced
- [x] LISTEN sockets are excluded — a listening socket has no peer, so it can never be the connection an `SSL_write`/`SSL_read` belongs to (state `01` / ESTABLISHED is the only useful one here)
- [x] Cost is considered alongside ticket 11's caching note: inode matching adds `/proc/<pid>/fd` directory reads per event, so this should land in a form that a short-TTL cache can still front. **Note this ticket makes the hot path more expensive before 11 makes it lazy** — measure it, and say so plainly rather than shipping a quiet regression

## Known ceiling on what this can fix

Even with correct ownership filtering, a uprobe event carries no indication of *which* of the process's sockets the `SSL_write`/`SSL_read` belonged to. For a server like bmcweb with N concurrent connections, ownership narrows the candidates to N, not to 1. So the honest outcome is:

- exactly one established owned socket → resolved, safe to act on
- zero → unresolved
- more than one → **unresolved, deliberately**, rather than guessing

That means uprobe-path enforcement will often decline to act on a busy server. That is the correct trade: acting on the wrong connection blocklists an address on every port (ticket 04's incident), and a missed enforcement is recoverable where a wrongly-blocklisted administrator is not.

Resolving this properly would mean reading the socket fd out of the `SSL` object in BPF (via its `BIO`), the same build-time-offset technique already used for `ssl->version`. That is a genuinely different piece of work and belongs in its own ticket, not here.

## Comments

`resolveEstablishedPeer(pid)` replaces the old guess. It intersects the socket inodes the process actually owns (read from `/proc/<pid>/fd`, where each socket fd is a `socket:[N]` symlink) against the ESTABLISHED entries of `/proc/<pid>/net/tcp` (`col[9]` is the inode; `col[3] == "01"` is ESTABLISHED), and returns a `PeerResolution` that is either a single unambiguous connection or an explicit refusal with a reason. `getTcpSockets()` now also filters out non-ESTABLISHED states, and its docstring says what it really returns — namespace-wide sockets — rather than the "belonging to that process" claim that made the old code look correct on review.

`SslUprobeProgram` fails closed: an unresolved event leaves the 4-tuple zeroed and logs the reason, so the existing "no TCP sockets found, cannot SOCK_DESTROY" path declines to enforce instead of acting on a guess.

**A second bug found while verifying, fixed here.** The first test run showed the resolver reporting `1.0.0.127` where the kernel reported `127.0.0.1` — `parseProcNetEntry` was applying a byte swap that `/proc/net/tcp`'s format does not call for. The kernel prints that field as `%08X` of the `__be32` address read as a native integer, so parsing it straight back to a native integer already reproduces the correct network-order byte layout, on both endiannesses; the swap reversed it. Every resolved address was therefore the reverse of the real one, meaning `BlocklistAddAction` was blocking a different address entirely. This had been recorded twice in earlier tickets as a loopback test artifact; it was not, and both notes are now corrected.

### Verification

Host-side against sockets whose real addresses came from `getsockname`/`getpeername` — an independent source, as the ticket required, rather than reading the daemon's own log back:

| Case | Result |
|---|---|
| process owns only a LISTEN socket | not resolved — "pid owns no established TCP connection" |
| forked child owning exactly one established socket | resolved; `127.0.0.1 local=34270 remote=35601`, matching the kernel exactly |
| process owning several established sockets | not resolved — "cannot attribute event to one" |

The single-connection case needed a `fork()`: the first attempt connected to a listener in the same process, which means that process owns *both* ends, so it legitimately reported "multiple". That was a flaw in the test, not the code — and the code refusing to guess there is exactly the intended behaviour.

Cross-compiles clean for the target.

### Cost, stated plainly

This makes the hot path more expensive, not less: every uprobe event now also reads `/proc/<pid>/fd` and readlinks each entry. That is a deliberate correctness-over-speed trade for now, and ticket 11 is what removes it — making enrichment lazy so it only runs when a verdict is actionable, plus a short-TTL cache. Worth doing soon rather than later.

### What this cannot fix

Ownership narrows the candidates to the connections the process owns, not to the one connection a given `SSL_write` used — a uprobe event carries no socket identity. So a busy server will often be legitimately unresolvable, and enforcement will decline. That is the right trade (blocklisting the wrong address applies to every port), but closing the gap properly means reading the fd out of the `SSL` object's `BIO` in BPF, which is its own piece of work.

### QEMU verification, and an open question it raised

On a real boot the fail-closed path works exactly as intended — no more bogus blocklist entries, and no more `SOCK_DESTROY` attempts against `-> 0.0.0.0:0`. Every uprobe event during a live HTTPS request now logs:

```
https_guard: PID 252 (bmcweb): peer unresolved (pid owns no established TCP connection); enforcement will be skipped for this event
```

That is correct behaviour for the code, but the *reason* deserves following up, because it means uprobe-path enforcement may never fire for bmcweb at all. Inspecting the target directly while a request was in flight:

```
bmcweb socket inodes (/proc/<pid>/fd): 4143, 4583, 4721
each mapped against /proc/<pid>/net/tcp:  none present in the TCP table
the one ESTABLISHED row (inode 7409):     0100007F:A91E -> 0100007F:01BB
                                          i.e. the *client's* socket, not bmcweb's
```

So bmcweb's own fds at that moment were unix-domain / listening sockets, and the only established TCP socket in the namespace belonged to the client. A transient inode (8216) was present in an earlier sample and gone in a later one, so the sampling may simply have missed the accepted connection — this is **not conclusive** either way.

**Why this is still an improvement, and why it is not "enforcement works".** Before this ticket the resolver returned a LISTEN socket or an arbitrary entry and enforcement acted on it — wrong target, real harm. Now it declines. But declining every time is not the goal, and if bmcweb's accepted sockets genuinely never appear as owned established TCP sockets by this method, then `/proc`-based resolution is the wrong mechanism for the uprobe path rather than merely a buggy one.

Worth investigating before tickets 14 and 08 are treated as making uprobe enforcement meaningful:

- [ ] Determine whether bmcweb's accepted connection sockets ever appear among its own `/proc/<pid>/fd` entries as ESTABLISHED TCP — sampling reliably mid-connection, e.g. against a deliberately slow/held request rather than a fast `curl`
- [ ] Check whether `evt.pid` being the **thread id** (BPF's `bpf_get_current_pid_tgid()` low word) rather than the process id matters here: `/proc/<tid>/fd` shares the process fd table so it should not, but it has not been confirmed, and bmcweb is multi-threaded
- [ ] Check whether socket activation / fd passing (systemd) changes which process owns the connection fd on this image
- [ ] If `/proc` resolution genuinely cannot attribute bmcweb's connections, reconsider the mechanism — reading the fd from the `SSL` object's `BIO` in BPF (already noted under "known ceiling") stops being an optional refinement and becomes the only workable route

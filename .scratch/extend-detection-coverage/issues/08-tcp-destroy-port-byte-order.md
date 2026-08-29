# 08 — Fix the port byte order that stops SOCK_DESTROY from ever matching a socket

**What to build:** Make `BlockTcpAction`/`TcpDestroyer` actually terminate the connection it's told to. Today it never does: the TCP-kill countermeasure has been silently failing on every event, for every hook, since it was written.

**Blocked by:** None (14 landed first, as required)

**Status:** done

## The bug

Both event sources hand `hg_event` **host**-byte-order ports:

- `programs/ssl_uprobe/proc_peer_resolver.hpp` — its struct fields are explicitly commented `/* host byte order */`, parsed from `/proc/<pid>/net/tcp`'s hex (`"01BB"` → `443`).
- `programs/xdp_tls/xdp_tls.bpf.h` — `evt->src_port = bpf_ntohs(tcp->source)`, i.e. converted from wire order to host order.

`actions/tcp/TcpDestroyer.cpp` then assigns them straight into the netlink request — `msg.req.id.idiag_sport = src_port_` — but `inet_diag_sockid` requires **network** byte order. Its own diagnostic logging (`ntohs(src_port_)`) shows the mismatch is a genuine misunderstanding rather than a deliberate convention: it prints the value as though it were network order, which is why the logs show a byte-swapped port.

Net effect: the kernel is asked to destroy a socket on a port that doesn't exist, so it returns `-ENOENT` and the real connection is left untouched.

## Evidence

Observed live on QEMU while verifying ticket 04. A crafted ClientHello arriving on port 443 produced:

```
BlockTcpAction: SOCK_DESTROY failed for 10.0.2.2:20670 -> 10.0.2.15:47873 ... netlink_error=-2 (No such file or directory)
```

`47873` is `0xBB01`; the real port, 443, is `0x01BB` — exactly byte-swapped. `-ENOENT` is the kernel saying "no such socket", which is the expected result of looking up the wrong port.

This also **corrects a wrong explanation recorded earlier** in `02-ssl-read-mirror.md`'s comments, which attributed the same `netlink_error=-2` to the short-lived curl connection having already closed. That may sometimes be true, but it is not the cause here: a live, mid-handshake connection failed the same way, and the byte-swapped port in the message is the actual reason. Ticket 02's note has been amended.

## Why it wasn't caught before

Nothing asserts on it. `BlockTcpAction` logs its own failure and moves on (deliberately non-fatal, so one failed countermeasure can't take down the daemon), and the `LogAction` Redfish event is emitted either way — so from the outside, detection looks like it's working end to end. The blocklist half of enforcement *does* work (it's a BPF map keyed on IP, no ports involved), which further masks it: a blocklisted source really does get dropped by XDP on its next packet, so "enforcement" appears effective even with TCP-kill dead.

- [x] `TcpDestroyer` receives ports in the byte order netlink actually wants, with the convention stated at the seam (either it converts, or its callers do — pick one and document it where `hg_event`'s port fields are declared, since both hooks populate them)
- [x] The fix is verified against a **real, live** connection on QEMU: the connection is observably terminated (client sees the reset / connection drop), not merely a "SOCK_DESTROY succeeded" log line
- [x] `ntohs()` in `TcpDestroyer`'s logging is made consistent with whatever convention is chosen, so the diagnostic output stops contradicting the code
- [x] A regression test covers the byte-order contract at the seam — this bug was invisible precisely because nothing asserted on it
- [x] Confirm whether the uprobe path was *also* broken by this (it populates the same fields from `/proc`, so it almost certainly was) rather than assuming the XDP path is the only affected one

## Comments

**Byte order fixed.** `TcpDestroyer` now applies `htons()` to the ports when filling `inet_diag_sockid`, whose `idiag_sport`/`idiag_dport` are `__be16`, while addresses continue to copy verbatim (they are already network order — and are now *correctly* network order after ticket 13 removed a bogus byte swap in `ProcPeerResolver`). The misleading comment that claimed "all address/port fields are already in network byte order" is replaced with the actual convention, and the diagnostic logging no longer applies `ntohs()` to values that were never network order — which is what made the byte-swapped port visible as `47873` in the first place.

The convention itself is now documented where the fields are declared, in `hg_event.hpp`, since both hooks populate them and the previous absence of any statement is what allowed a consumer to assume wrongly.

**Why this ticket is not closed.** Its acceptance criterion asks for a real connection observably terminated, not just a success log line. That cannot be demonstrated yet: tracing the enforcement path to set up the test surfaced that `hg_event`'s `src`/`dst` pair means the *local* end for uprobe events and the *remote* end for XDP events, so the 4-tuple handed to netlink is correctly oriented for one hook and inverted for the other. A live teardown test would therefore pass or fail for reasons unrelated to byte order. Filed as ticket 14, which also carries the more serious half of that finding — for uprobe events the blocklist has been receiving the BMC's own address.

Fixing byte order was still worth landing on its own: it is a self-contained, verified-by-inspection correction, and leaving it in place while 14 is resolved means the remaining work is purely about orientation rather than two entangled problems at once.

## Update — byte order was real, but it was never why this failed

Retested against a genuinely live connection (`openssl s_client` holding the
socket open for 25s, verified alive both before and after the enforcement
window, so timing is ruled out). The logged tuple is now correct in every
respect:

```
BlockTcpAction: SOCK_DESTROY failed for 127.0.0.1:43276 -> 127.0.0.1:443 ... netlink_error=-2
```

Ports in host order (`43276`, `443` — no longer the byte-swapped `47873`),
address no longer reversed, local-then-remote orientation correct per ticket
14. And it still returned `-ENOENT`.

**Root cause: `CONFIG_INET_DIAG` is not enabled in this kernel.** The
mechanism SOCK_DESTROY needs was never compiled in.

What made this so misleading is that `CONFIG_SOCK_DIAG` *is* on — pulled in
by `CONFIG_UNIX_DIAG` and `CONFIG_PACKET_DIAG` — so the `NETLINK_INET_DIAG`
socket opens successfully, the request is accepted, and a well-formed
`NLMSG_ERROR` comes back. But without `INET_DIAG` there is no AF_INET
handler registered, and `net/core/sock_diag.c`'s `__sock_diag_cmd()` bails
long before it looks at the 4-tuple:

```c
hndl = sock_diag_lock_handler(req->sdiag_family);
if (hndl == NULL)
        return -ENOENT;
```

So *every* request failed identically no matter what was asked for. An
`-ENOENT` from a socket-lookup API reads naturally as "that socket doesn't
exist", which is exactly the wrong conclusion — and it is why this was first
explained away as a closed connection (ticket 02), then as a byte-order bug
(this ticket), then as a wrong-orientation bug (ticket 14). Each of those was
a genuine defect found and fixed on the way, and each would have prevented
this working once the kernel could answer at all. None of them was the
blocker.

Fixed by adding `CONFIG_INET_DIAG=y`, `CONFIG_INET_TCP_DIAG=y` and
`CONFIG_INET_DIAG_DESTROY=y` to `recipes-kernel/linux/bpf-kernel-config.cfg`.
This is the same shape as ticket 03's discovery, where `CONFIG_BPF_LSM=y` was
inert because `CONFIG_SECURITY` was never enabled: a feature the project
depends on, declared nowhere and silently absent.

### Lesson worth keeping

Three separate wrong explanations were recorded for this one error line, each
plausible, each derived by reading the code rather than asking the kernel
what it was actually complaining about. The thing that finally settled it was
looking up where that specific errno is returned from in the kernel source.
When a syscall or netlink API returns an errno that *could* mean "your
arguments are wrong", confirm the feature is present before debugging the
arguments.

- [x] Re-verify on QEMU with INET_DIAG enabled: a live connection is observably torn down (client sees the drop), not merely a success log line

### Verified — enforcement actually works now

With `CONFIG_INET_DIAG` enabled, tested against a connection held open by
`openssl s_client` for 30s so there was a genuinely live socket to act on:

```
BlockTcpAction: destroyed TCP connection 127.0.0.1:33736 -> 127.0.0.1:443
    reason=Attack signature detected from process 'openssl' (PID 428), rule '/etc/passwd'
```

and on the client side, `errno=103` (ECONNABORTED) with the process gone —
where the identical test on the previous kernel left it alive past 14s. Both
halves matter: the log line alone would not have shown the connection really
died, and the client's abort alone would not have shown *this* code caused
it.

One further defect surfaced in the process. The request used
`NLM_F_REQUEST` without `NLM_F_ACK`, and netlink only replies on error under
that flag — so once the kernel could honour the request, success became
completely silent and this code waited for a reply that never arrived. For a
security daemon that is backwards: a successful teardown is the event most
worth recording. Worse, it actively misled the earlier diagnosis — while
`INET_DIAG` was absent *every* request errored, so a reply always came back
and a failure was always logged, which made the problem look like malformed
request contents. Adding `NLM_F_ACK` makes the kernel answer either way and
makes the `nl_err == 0` "destroyed TCP connection" branch reachable; it had
been dead code since it was written.

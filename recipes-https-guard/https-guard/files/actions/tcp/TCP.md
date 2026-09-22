# `BlockTcpAction` — killing a live connection

**What it does:** asks the kernel to destroy one TCP socket, by 4-tuple, via
`NETLINK_INET_DIAG` / `SOCK_DESTROY`.

**Why that works despite TLS:** it tears down the *kernel* socket. The
application, and its encryption, have no say — the connection simply stops
existing out from under it. There is no need to decrypt anything, inject
anything, or wait for the peer.

## Preconditions, both of which are real

**A full 4-tuple.** A verdict attributed to an *address* rather than a
connection — every one of the three counter detections — has no local endpoint
and no ports. Asking netlink to destroy a zero tuple produced a guaranteed
`-ENOENT` and a misleading "SOCK_DESTROY failed" line, so `dispatchVerdict()`
checks for a full tuple first and blocklists without a teardown otherwise.

**`CONFIG_INET_DIAG` in the kernel.** Enabled in
`recipes-kernel/linux/bpf-kernel-config.cfg`, and its absence is the single most
misleading failure this project has hit — see below.

## Byte order and orientation, stated because both were wrong once

`inet_diag_sockid`'s `idiag_sport`/`idiag_dport` are `__be16`, so
`TcpDestroyer` applies `htons()`. Addresses are copied verbatim, because
`EventMeta` already holds them in network order. The convention is documented
where the fields are declared — both producers fill them, and the previous
absence of any statement is what let a consumer assume wrongly.

The tuple is **local first, then remote**, which netlink requires. `EventMeta`'s
role-based naming exists so that is unambiguous; under `src_`/`dst_` the XDP
tuple was inverted here while the uprobe one was correct.

This field-population logic — family selection, orientation, port byte
order — is now `TcpDestroyer::populateRequest()`, a pure static function with
no socket and no I/O, unit-tested in `tests/actions/tcp_destroyer_test.cpp`.
It didn't exist when the bugs above were live; the tests pin both incidents
by name (a swapped orientation, a byte-swapped port) so they cannot recur
silently.

## Dual-stack (IPv4 and IPv6)

`TcpDestroyer`/`BlockTcpAction` take a `bool is_ipv6` plus a 16-byte address
for each end, rather than a bare `uint32_t` — the same convention
`EventMeta::IpAddress` uses, so a caller building one of these from an
`EventMeta` copies `.bytes` straight across. For an IPv4 tuple, only the
first 4 bytes are meaningful; `populateRequest()` copies all 16 regardless,
which is correct for both families since an IPv4 `IpAddress` already carries
zero bytes past the first 4.

The blocklist half of enforcement (`actions/blocklist/`) stays IPv4-only —
its BPF map is keyed on a 32-bit address, deliberately not extended here. An
IPv6-attributed verdict is therefore enforced by teardown alone;
`dispatchVerdict()` logs that blocklisting was skipped rather than leaving
that silent.

## The `-ENOENT` story, kept because the lesson generalises

`SOCK_DESTROY` failed on **every event, for every hook, for a long time**, and
three separate explanations were recorded before the real one:

1. *"The connection already closed."* Plausible for a short-lived `curl`, and wrong: a connection held open for 25s and verified alive on both sides failed identically.
2. *"The port byte order is wrong."* Genuinely was — the logged port was `47873` where `0x01BB` is 443, exactly byte-swapped. Fixed, and it still returned `-ENOENT`.
3. *"The tuple is the wrong way round."* Also genuinely was, for one of the two hooks. Fixed, and it still returned `-ENOENT`.

The actual cause: **`CONFIG_INET_DIAG` was not enabled.** What made it so
misleading is that `CONFIG_SOCK_DIAG` *is* on — pulled in by `UNIX_DIAG` and
`PACKET_DIAG` — so the netlink socket opens, the request is accepted, and a
well-formed `NLMSG_ERROR` comes back. But with no AF_INET handler registered,
`net/core/sock_diag.c`'s `__sock_diag_cmd()` bails long before it looks at the
4-tuple:

```c
hndl = sock_diag_lock_handler(req->sdiag_family);
if (hndl == NULL)
        return -ENOENT;
```

So every request failed identically no matter what was asked for. An `-ENOENT`
from a socket-lookup API reads naturally as "that socket doesn't exist", which is
precisely the wrong conclusion.

**The lesson worth keeping:** when a syscall or netlink API returns an errno that
*could* mean "your arguments are wrong", confirm the feature is present before
debugging the arguments. Each of the three wrong explanations was derived by
reading our own code; what settled it was finding where that errno is returned
from in the kernel source.

Also worth knowing: `NLM_F_ACK` must be set, or success is silent and there is
nothing to distinguish it from a request that vanished.

## Why the failure hid for so long

`BlockTcpAction` logs its own failure and moves on — deliberately, so one failed
countermeasure cannot take down the daemon — and the Redfish event is emitted
either way. From outside, detection looked like it worked end to end. The
blocklist half of enforcement *does* work (a BPF map keyed on IP, no ports
involved), which masked it further: a blocklisted source really was dropped on
its next packet, so "enforcement" appeared effective with TCP-kill entirely dead.

Nothing asserted on it. The verification standard for this action is therefore
**a client observing its own connection drop** — `openssl s_client` exiting 103
— not a log line saying the call succeeded.

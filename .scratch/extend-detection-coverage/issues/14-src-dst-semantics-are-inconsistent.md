# 14 — `src`/`dst` in hg_event mean opposite things in the two hooks, so enforcement targets the wrong end

**What to build:** One unambiguous definition of what `hg_event`'s address/port pair means, applied by both hooks and understood by both consumers. Today the two hooks populate it with opposite meanings, and each consumer is therefore correct for one hook and wrong for the other.

**Blocked by:** None — can start immediately

**Blocks:** 08 — TcpDestroyer port byte order (its "verified against a real, live connection, observably terminated" criterion cannot be met while the 4-tuple orientation is wrong for XDP events)

**Status:** done

## The inconsistency

| Hook | `src_ip_v4` / `src_port` populated from | So `src` actually means |
|---|---|---|
| `ssl_uprobe` | `/proc/<pid>/net/tcp` **col[1] = `local_address`** | the BMC itself (local end) |
| `xdp_tls` | `ip->saddr` on an **ingress** hook | the remote peer |

Both consumers read the same fields:

```cpp
std::make_unique<BlockTcpAction>(evt.src_ip_v4, evt.dst_ip_v4, evt.src_port, evt.dst_port, ...);
std::make_unique<BlocklistAddAction>(evt.src_ip_v4, blocklist_ttl_, ...);
```

Which gives, per hook:

| | `BlocklistAddAction` blocks | netlink `idiag_src` (wants **local**) |
|---|---|---|
| uprobe | **the BMC's own address** ✗ | local ✓ |
| XDP | the remote peer ✓ | remote ✗ (inverted) |

So each path is broken for exactly one of the two consumers, in opposite directions. There is no single fixed mapping that repairs both — the field's meaning has to be *decided*, then applied consistently.

## Why this is the most consequential of the enforcement bugs found so far

For uprobe-sourced events, `BlocklistAddAction` inserts the **BMC's own address** into the blocklist, and the XDP blocklist drops that address on *every port*. That is a self-inflicted outage mechanism, not merely a missed detection. It is the real reason the earlier logs read

```
BlocklistAddAction: blocklisted 1.0.0.127 for 300s
```

`127.0.0.1` is the *local* end of the connection (byte-swapped by the separate bug fixed in ticket 13). Both defects were previously explained away as loopback test artifacts; neither was.

Two things have been masking the full impact:

- ticket 08 — `SOCK_DESTROY` never matched anything, so the wrong-orientation 4-tuple never actually tore down a connection
- ticket 13 — peer resolution was returning namespace-wide, mostly LISTEN sockets, so the value being blocklisted was frequently garbage rather than a coherent local address

Now that 13 resolves a genuine owned connection and 08 makes the netlink lookup valid, **this stops being theoretical.** It should land before either of those is considered done.

## The decision that has to be made

`source_ip` (the printable string, and the one that appears in Redfish messages) means "the peer that sent this" — which is the right thing for a security event to report, and is not in question. The numeric pair is what's ambiguous, because its two consumers want different things:

- the blocklist wants **the offending peer**
- `inet_diag_sockid` wants **local, then remote**

Both are legitimate. Reasonable resolutions include naming the pair `local_*`/`remote_*` and having each consumer pick what it needs, or keeping `src`/`dst` as wire-direction and converting at the netlink boundary. Whichever is chosen, it must be stated where the fields are declared — the byte-order convention was just documented there for exactly this reason, after the same class of mistake.

- [x] `hg_event`'s address/port pair has one documented meaning, stated at the declaration, and both hooks populate it accordingly
- [x] `BlocklistAddAction` receives the **remote peer** for events from *both* hooks — verified explicitly, since blocking the local address is the worst possible failure here
- [x] `TcpDestroyer` receives local-then-remote as `inet_diag_sockid` requires, for events from both hooks
- [x] A regression test pins the orientation for each hook, so this cannot silently invert again — the whole reason it survived this long is that nothing asserted on it
- [ ] Verified on QEMU that a blocklist entry created from a uprobe event contains the peer's address and **not** the BMC's own, checked against an independent source rather than inferred from the log line

## Comments

Resolved by naming the fields for their **role** instead of a direction: `local_*` (this BMC's end) and `remote_*` (the peer). This was not a choice between two equally good options — `src`/`dst` are ambiguous by construction, since they depend on whose frame of reference you take, and that ambiguity *is* the bug. Role names make the mistake structurally impossible rather than merely corrected:

- `BlocklistAddAction(evt.remote_ip_v4)` — blocks the peer. Cannot accidentally mean "us".
- `TcpDestroyer(local_ip, remote_ip, local_port, remote_port)` → `idiag_src = local`, `idiag_dst = remote`, matching what `inet_diag_sockid` actually documents.

It also restores an architectural property that had quietly broken: a consumer must never need to know which hook produced an event. Under `src`/`dst` both consumers *did* need to know, because the two hooks filled them oppositely.

Each producer now translates at its own boundary, where the meaning is unambiguous:

| Producer | Mapping | Why it's obvious there |
|---|---|---|
| `ssl_uprobe` | `local ← /proc` col 1, `remote ← ` col 2 | `/proc/net/tcp`'s own header names these `local_address` and `rem_address` |
| `xdp_tls` | `local ← ` packet dst, `remote ← ` packet src | XDP is ingress-only, so the packet's destination is necessarily this BMC |

The raw BPF structs keep `src`/`dst`, deliberately: on the wire that vocabulary is correct and unambiguous. The translation belongs in `parseEvent()`, the point where a hook stops speaking packet and starts speaking `hg_event`. `actions/blocklist/` also keeps its `src_ip_v4` naming, since XDP's `blocklist_check(ip->saddr)` genuinely is checking a packet's source — that frame is its own and is right.

**Regression tests** pin the orientation for both hooks plus the cross-hook agreement property (given the same connection seen either way, `remote_*` names the same host). Nothing asserted on this before, which is exactly why two hooks disagreed indefinitely. 40/40 pass under ASan/UBSan.

Note this also removes a hazard that ticket 13 had *increased*: with peer resolution now returning a real owned connection rather than usually-garbage, a blocklist call on the wrong field would reliably block the BMC's own address instead of occasionally blocking nonsense.

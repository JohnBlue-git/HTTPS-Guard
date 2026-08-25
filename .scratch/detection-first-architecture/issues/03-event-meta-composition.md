# 03 — Replace the polymorphic hg_event base with composed EventMeta

**What to build:** Delete the `hg_event` base class. Each event type becomes a
plain struct that *contains* a shared `EventMeta` (timestamp, pid/tgid, comm,
the connection tuple, lazy peer resolution) instead of inheriting it.

**Blocked by:** 02 — it rewrites the same call sites

**Status:** done

## Why

`hg_event` exists to be downcast from. Once handler dispatch is typed
(ticket 05) nothing needs a common base — but several things still need the
common *fields*, so they become a member rather than a base class. This is the
same move that just landed on the raw side, where `hg_event_hdr` is nested
rather than inherited.

## What still needs the common fields, and must keep working

- `RedfishEventMessage` reads `timestamp_ns` and `pid`.
- The enforcement gate reads `remote_ip_v4`, `local_ip_v4` and both ports, and
  calls `ensurePeerResolved()`.
- The verdict message text for several rules names `process` and `pid`.

`ensurePeerResolved()` currently lives on `hg_event` with `mutable` memo
members. Moving it onto `EventMeta` keeps that working, but note the memo is
only safe because one event is touched by one classification at a time — which
is a threading requirement now that the sweep runs concurrently with a record.
Keep that comment with the code it constrains.

- [x] `hg_event` is gone; every event type composes `EventMeta`
- [x] Events are still non-copyable, or the reason they no longer need to be is stated — the old `= delete` existed to prevent slicing, which stops being the reason once there is no base class
- [x] Lazy peer resolution still runs only on the enforcing path, and the concurrency note travels with it
- [x] The enforcement gate still keys on "an address is present", NOT on whether resolution ran — ticket 11's regression, which a rewrite of this exact code is the most likely thing to reintroduce
- [x] Redfish `Id`/`EventId` still carry a real timestamp (the bug fixed alongside the nested-struct work)
- [x] 60/60 host tests still pass; QEMU baseline unchanged

## Comments

`hg_event` is gone. Every event type is now a plain struct **containing** an
`EventMeta`, the same move the raw BPF side already made with `hg_event_hdr`.

The non-copyable question the ticket raised answered itself: `= delete` on the
copy constructor existed to prevent *slicing*, and with no base class there is
nothing to slice. Events are ordinary copyable structs again, which is also why
the sweeper can build one on the stack and hand it to a handler by const
reference instead of allocating.

`ensurePeerResolved()` moved onto `EventMeta`, memo and all, and the threading
note travelled with it — that memo is only safe because one event is touched by
one classification at a time, which is a real constraint now that the sweep runs
concurrently with a record.

The enforcement gate came through intact and is worth naming again, because a
rewrite of exactly this code is the most likely way to reintroduce ticket 11's
regression: it keys on **an address being present**, not on whether resolution
ran. XDP events and synthesised rate events carry no resolver at all, so gating
on `ensurePeerResolved()` would silently skip enforcement for both.

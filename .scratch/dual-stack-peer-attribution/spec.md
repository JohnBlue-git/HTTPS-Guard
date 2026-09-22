# Dual-stack peer attribution for the ssl_uprobe hook

Status: done — see ./issues/ (01-03 fully done; 04 done with two caveats)

## Problem Statement

HTTPS-Guard's uprobe-fed detections (TLS-version violations, payload anomalies)
can only enforce — blocklist the source, tear down the exact TCP connection —
when the triggering event can be attributed to a specific 4-tuple. Today's
attribution mechanism (`ProcPeerResolver`) intersects a process's owned socket
inodes with its established TCP connections read from `/proc`, and it fails
closed the moment the reporting process owns more than one established
connection at once.

That is bmcweb's normal operating state. It is a long-running server usually
holding several simultaneous Redfish/KVM/WebUI connections, so the process the
tool most needs to enforce against — bmcweb, receiving an attacker's payload
via `SSL_read` — is exactly the one whose events routinely go unattributed and
therefore unenforced. Only the simpler case (a single-connection client, e.g. a
local `openssl s_client` test) reliably gets torn down today.

The mechanism is also IPv4-only: it parses `/proc/<pid>/net/tcp` but not
`tcp6`. A dual-stack bmcweb listener (a plain `ListenStream=443` produces one)
means any client arriving over IPv6 compounds the gap regardless of connection
count.

## Solution

Uprobe-fed events against bmcweb's own connections resolve to a specific
4-tuple far more often — including when bmcweb has multiple connections open
at once, and including connections from IPv6 clients — without ever risking a
*wrong* attribution, which would blocklist or tear down an uninvolved
connection instead of the offending one.

This is achieved by moving the identity link from an after-the-fact `/proc`
guess to an in-kernel binding made at the moment OpenSSL's handshake functions
run, using the kernel's own knowledge of which socket the calling thread was
just handling. Where the kernel-side binding can't be made — a connection that
predates the daemon's attach, or one whose accept and first read genuinely ran
on different threads — the tool falls back to today's `/proc`-based resolution
unchanged, so the worst case is no worse than current behavior.

## User Stories

1. As a BMC operator, I want a malicious payload sent to bmcweb over HTTPS to
   have its TCP connection torn down, so that the attack cannot continue even
   though bmcweb has other connections open at the same time.
2. As a BMC operator, I want an attacker connecting over IPv6 to be
   blocklisted and disconnected just like one connecting over IPv4, so that a
   dual-stack deployment isn't a blind spot.
3. As a BMC operator, I want the daemon to never blocklist or disconnect a
   connection that isn't the one that actually misbehaved, so that a wrong
   attribution never locks out an innocent host — including one of my own
   admin sessions.
4. As an on-call responder reading the daemon's logs, I want to see why a
   given uprobe event could or couldn't be attributed to a connection, so I
   can tell a real gap from expected fail-closed behavior.
5. As an on-call responder, I want events for connections that predate the
   daemon's startup to still have a chance at attribution via the existing
   `/proc`-based fallback, so a restart doesn't create a blind spot beyond
   what already exists today.
6. As a developer extending HTTPS-Guard, I want the new attribution mechanism
   to live inside the existing `ssl_uprobe` hook rather than as a new hook
   family, so I don't need to reason about a new hook-module subclass, a new
   ring-buffer source, or a new registration point for something that isn't a
   new detection source.
7. As a developer, I want the kernel-side binding to never bind the wrong
   tuple to the wrong SSL session, so that even under an unverified assumption
   about bmcweb's threading model, the failure mode is "falls back to
   unresolved" — never "resolves incorrectly."
8. As a developer, I want the correlation state (per-thread tuple records, and
   the per-SSL-session tuple map) to be bounded and self-cleaning, so a
   long-running daemon doesn't leak memory across the lifetime of many
   short-lived connections.
9. As a developer, I want a session's teardown to clear its map entry
   immediately, and a periodic sweep to catch anything missed, so the map
   can't grow unbounded if a connection ends abnormally (including one this
   daemon itself tore down).
10. As a developer, I want the kernel-side observation of raw socket
    activity to filter to port-443 sockets, so the mechanism doesn't add
    measurable overhead to every TCP socket on the box for a benefit that
    only ever applies to the one port HTTPS-Guard protects.
11. As a developer, I want both the accept side and the connect side of the
    handshake hooked symmetrically with the existing write/read pair, so both
    server-accepted and client-initiated local connections (e.g. `openssl
    s_client` during testing) can bind.
12. As a developer writing tests, I want the new dual-stack tuple carried on
    the raw uprobe event, and the fill logic that turns it into the shared
    event-metadata type, to be unit-testable with hand-built raw structs and
    no kernel, so attribution gets the same test coverage every other parse
    step in this codebase already has.
13. As a developer writing tests, I want the TCP-teardown action's
    request-population logic for both IPv4 and IPv6 to be unit-testable
    without opening a real netlink socket, so the byte-order/family-selection
    logic — the exact class of bug this file's own history warns about — is
    covered before it ships.
14. As a maintainer, I want the "already resolved vs. needs a resolver"
    contract on the shared event-metadata type to stay exactly as it is
    today, so uprobe-sourced events and XDP-sourced events are handled
    identically by every downstream consumer.
15. As a security reviewer, I want this feature to only ever *add*
    information (a resolved tuple) to events that today carry none, so no
    existing detection's behavior on the "resolver present" path changes.
16. As a BMC operator, I want the daemon's attach-time log output to report
    whether the new kernel-side observation attached successfully, mirroring
    how uprobe/XDP/LSM attach outcomes are already reported, so "N of M hooks
    active" stays a meaningful health signal.
17. As a developer, I want a connection whose 4-tuple truly cannot be
    determined to still result in "decline to enforce," never a guess, so
    this feature doesn't weaken the project's existing fail-closed guarantee
    anywhere.
18. As a developer extending detections, I want the IPv6 support introduced
    here scoped to the shared event-metadata type and the TCP-teardown action
    only, so landing this doesn't require also reworking the XDP wire parser,
    the blocklist map, or the rate-counter map.
19. As an on-call responder, I want the limitations documentation to say
    plainly that XDP-fed detections and blocklisting remain IPv4-only after
    this change, so I don't assume IPv6 protection is uniform across the
    whole tool.
20. As a developer, I want the per-thread correlation record consumed
    exactly once, so a stale record from an unrelated earlier connection on
    the same thread can never be mistaken for the current one.

## Implementation Decisions

- Two new kernel-side lookup tables, shared within the `ssl_uprobe` hook's BPF
  program: one keyed on the calling thread (thread-group id + thread id)
  holding the most recent port-443 socket tuple it touched; one keyed on the
  OpenSSL session pointer holding the tuple bound to it.
- Kernel-side observation of raw socket read/write activity populates the
  per-thread table, filtered to sockets whose local or remote port is 443,
  checked from the kernel's own socket structure rather than any
  userspace-visible signal.
- The handshake-acceptance and handshake-initiation entry points are hooked
  (new, symmetric with the existing data read/write hooks) and each consumes
  the current thread's per-thread record exactly once — read and cleared
  together — to populate the session-keyed table. "Exactly once" is the
  safety property: a record that doesn't match the current thread's most
  recent activity is never reused or guessed at.
- The existing data read/write hooks look up the session-keyed table using
  the session pointer they already receive, and on a hit embed the resolved
  tuple (address family, local/remote address, local/remote port) directly
  into the raw event they already submit. On a miss, the event carries an
  absent tuple exactly as it does today — entirely in-kernel, no new
  userspace-visible traffic.
- A session-teardown hook removes the corresponding session-keyed entry
  immediately. A bounded periodic sweep — the same shape as the existing
  per-source counter sweep — evicts stale per-thread and session-keyed
  entries as a safety net for teardowns this hook doesn't observe.
- The raw uprobe event gains a connection-tuple sub-structure (address-family
  tag, dual-stack address bytes, local/remote ports) alongside its existing
  TLS-version/payload fields. Absence is represented the same way an
  unknown field already is elsewhere in this wire format: zeroed.
- The shared event-metadata type gains a dual-stack representation of the
  connection tuple (an address-family tag plus enough bytes for either an
  IPv4 or IPv6 address). Every existing consumer that only ever dealt with
  IPv4 continues to work unchanged.
- The uprobe hook's event-fill step gains a case parallel to the one the wire
  hook already uses: when the raw event's tuple is present, populate the
  shared event metadata directly and leave its resolver unset (today's
  "already resolved" contract, currently exercised only by the wire hook's
  events); when absent, set the resolver to the hook exactly as today,
  preserving the existing `/proc`-based fallback unchanged.
- The TCP-teardown action gains an address-family branch: given a dual-stack
  tuple, it selects the IPv4 or IPv6 request shape and populates the
  corresponding kernel socket-diagnostics fields (address family, ports in
  the byte order that boundary already requires today, and either the
  single-word or four-word address representation the family needs).
- No new hook family, no new entry in the hook-registration point, no new
  detection. This is entirely inside the existing `ssl_uprobe` hook's attach
  step and the existing shared event-metadata/TCP-teardown types.
- The wire (XDP) hook's parser, the blocklist map's key type, and the
  per-source rate-counter map's key type are unchanged and remain IPv4-only.

## Testing Decisions

Good tests here assert the observable behavior of the fill step and the
TCP-teardown action's request construction against hand-built inputs — never
the kernel-side correlation itself, which cannot be exercised without a real
kernel and is out of reach for this project's host-side suite by the same
rule that already excludes BPF-map and socket-privileged behavior from it.

- **Event-fill step.** Extend the existing shared event-metadata test file
  with cases for a raw uprobe event that already carries a tuple (asserts
  fields populated, resolver left unset — direct precedent: the existing
  "an event that already knows its address needs no resolver to enforce"
  case, today exercised only via a wire-hook-shaped event) and one that
  doesn't (asserts today's fallback path is still selected). Both
  IPv4-shaped and IPv6-shaped present-tuple cases belong here.
- **TCP-teardown action.** This code has no unit tests today. New tests
  should cover its request-population logic in isolation from the real
  netlink socket it also owns — given a local tuple, a remote tuple and a
  family, assert the constructed request's address family, port byte order
  and address fields are correct for both IPv4 and IPv6. Prior art for
  "isolate the pure field-population from the I/O" is this same file's
  existing free function that already separates the message-envelope wiring
  from the class that owns the socket.
- **Not unit-tested, verified live instead.** Whether a real handshake
  actually produces a bound tuple, and specifically whether a bmcweb session
  holding more than one established connection at once now resolves an
  attack signature it previously wouldn't have — verified the same way this
  project already verifies wire-hook enforcement: a live QEMU boot checked
  against real log output, exercising the multi-connection case this feature
  exists for.

## Out of Scope

- The wire (XDP) hook's parser, the blocklist map, and the per-source
  rate-counter map staying IPv4-only — a follow-on gap, to be recorded in the
  limitations documentation, not built here.
- Extending the `/proc`-based fallback itself to parse the IPv6 connection
  table. An IPv6 connection whose kernel-side bind is missed falls through to
  unresolved — the same fail-closed outcome as any other unresolved case
  today, just for a narrower set of situations (chiefly: a connection that
  already existed when the daemon started).
- Verifying bmcweb's actual threading model (whether it ever completes one
  connection's accept and first read on different OS threads) ahead of time.
  The design's safety property — single-use, per-thread correlation, never a
  wrong bind — is exactly what makes shipping without that verification
  acceptable.
- Any change to the blocklist's blast radius, TTL, or which rules are
  actionable. This feature only changes whether a tuple can be found, not
  what happens once one is found.
- Reading the socket descriptor out of the OpenSSL session object's BIO.
  Confirmed not viable for this project's Boost.Asio-based server (a memory
  BIO pair, not a socket BIO) — exactly why the kernel-side approach was
  chosen instead.

## Further Notes

This directly addresses two entries under LIMITATIONS.md's "Attribution and
enforcement" section — "Uprobe events often cannot be attributed to a
connection" and the open question about bmcweb's file descriptors — both of
which describe the mechanism this spec replaces. Once implemented, those
entries need rewriting to describe the shipped mechanism and its actual
remaining gaps, not the old one; that rewrite belongs to the companion
docs-restructuring effort tracked separately at
`.scratch/docs-restructure/`, sequenced *after* this spec lands so it
describes what actually shipped rather than the plan.

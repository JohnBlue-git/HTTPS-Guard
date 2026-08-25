# Ticket priority

Decided rather than asked. The ordering principle: **make the detection we already ship trustworthy before adding more of it.** Every ticket below 08 adds new detections; 08–12 fix cases where the tool currently reports something that isn't true, or silently stops working.

| Order | Ticket | Why here |
|---|---|---|
| ✅ | **13** — ProcPeerResolver picks the wrong socket | Promoted above 08 deliberately. Peer resolution returns the whole network namespace's TCP table and then guesses, so enforcement can act on an uninvolved host — and the XDP blocklist drops that address on *every* port. Right now ticket 08 masks the worst of it (`SOCK_DESTROY` never matches anything), which means **fixing 08 first would convert a no-op into a wrong-target action.** This has to land first or together. |
| ✅ | **14** — src/dst mean opposite ends in the two hooks (DONE) | Found while setting up 08's live test. For uprobe events the blocklist receives **the BMC's own address**, and the XDP blocklist drops an address on every port — a self-inflicted outage, not a missed detection. Tickets 08 and 13 were masking it (nothing was ever actually torn down, and the resolved value was usually garbage); with both fixed, it stops being theoretical. |
| 4 | **08** — TcpDestroyer port byte order (finish: live teardown test) | Highest severity on its own terms: `SOCK_DESTROY` has *never* matched a socket, for either hook, so every Redfish message saying a connection was blocked is inaccurate. Small and understood — but see 13 above for why it must not go first. |
| ✅ | **11** — DetectLoop (DONE) | Ring-buffer callback does `/proc` parsing (505 lines/event on the dev host) on the thread libbpf needs back promptly; a full ring buffer drops events, and a dropped event is a missed detection nothing reports. Also absorbs 10, so it removes a whole failure mode (crash → permanent outage) rather than just relocating work. |
| ✅ | **09** — XDP attachment leak (DONE) | A routine `systemctl restart` silently drops the daemon to uprobe-only — losing TLS-version-on-the-wire, cipher-suite and SNI detection — while still reporting healthy. Easy to hit operationally; only a reboot recovers it on the target image. |
| ✅ | **12** — Per-hook directory reorganization (partly done: detections/ rename + engine move landed with 11) | Structural, no behavioural change. Sequenced after 11 because 11 rewrites who calls the detectors; reorganizing first means editing the same includes and CMake wiring twice. |
| ✅ | **15** — split hg_event's god object into per-hook detail | Every hook currently widens a 24-field struct in the classification layer that every other hook depends on, ~10 fields of which are meaningless for any given event. Pairs with 12 (hook-specific event detail and hook-specific detectors want to sit together) and is blocked by 11, which rewrites the same call sites. |
| ✅ | **05** — Connection-rate / SYN-flood / port-scan detection | New capability. Genuinely valuable, but a new detector resting on enforcement that doesn't work (08) and a pipeline that can drop events (11) is building on sand. |
| ✅ | **06** — Slowloris / TLS-renegotiation-storm detection | Also new capability, and it still has an open design question (whether `IDetector` needs a stateful variant) that 05's per-source-IP state work will largely answer — so it's cheaper after 05. |
| ✅ | **07** — Doc rewrites | Blocked by the above by construction; writing it earlier means rewriting it. |
| ✅ | **16** — Rebuild DetectLoop on Boost.Asio | Requested after 11 landed: the project had two long-lived worker loops built two different ways, and `DetectLoop` was the hand-rolled one. Consistency of idiom, plus the timed waits and shutdown races come from a library that has already got them right. Sequenced last because it rewrites the engine every other ticket depends on. |

**Superseded:** 10 (folded into 11).

## Where things stand

20 tickets created across both specs, 1 superseded, so 19 real pieces of work:

| | Count | Tickets |
|---|---|---|
| done | 20 | `split-hooks-and-detectors` 01–04; `extend-detection-coverage` 01, 02, 03, 04, 05, 06, 07, 08, 09, 11, 12, 13, 14, 15, 16 |
| remaining | 0 | — all tickets closed |

Four "done" entries carry caveats worth knowing before trusting them:

- **03** — one criterion is unverifiable on this hardware, not merely undone: ARM32 has no BPF trampoline, so the LSM hook cannot attach at all and there is nothing there to observe declining to deny.
- **06** — both new rules are verified live only at *lowered* thresholds, never the shipped defaults. Renegotiation fires (one-connection trigger, ~3 records vs a limit of 2). Slowloris is not reliably reproducible through a SLIRP hostfwd — an earlier run reached 5 held connections but a re-measurement saw only ~1 of 3–8 arrive at the guest; it needs a real netdev / bridged network to exercise dependably.
- **13** — all original criteria met, but four follow-up questions were appended after the QEMU run. bmcweb's own fds during a live request were unix-domain/listening sockets, so uprobe-path enforcement may never resolve. Fail-closed is working; whether `/proc` is the right mechanism at all is now open.
- **16** — done and verified, but its tests live in `tests/detectloop/` with a documented build command rather than in the CMake test target, because `DetectLoop.cpp` cannot be built by a test binary that is deliberately free of kernel dependencies. Wiring it into CMake is a real follow-up.

## Reasoning worth keeping

Ticket 16 adds a variant of the same lesson that did *not* need hardware: the naive single-threaded translation of `DetectLoop` to Asio silently reintroduced ticket 05's sweep starvation, and that was caught by deliberately running the counterfactual (1 thread vs 2) rather than by reasoning about FIFO fairness. Measuring the thing you are about to argue is fine costs one build.

The three most consequential findings so far were all found by *running* the thing on real hardware, not by reading it: the ARM32 BPF-LSM trampoline gap (ticket 03), the verifier rejecting the ClientHello parser (04), and the blocklist locking out the test's own SSH session (04). Two of the top three items above (08, 09) were likewise found incidentally while verifying something else. That's the argument for keeping QEMU verification in the loop for every ticket rather than treating a clean cross-compile as done — the class of bug that matters here does not show up at compile time.

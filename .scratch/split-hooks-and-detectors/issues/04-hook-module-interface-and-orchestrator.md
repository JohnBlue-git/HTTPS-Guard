# 04 — Extract the hook-module interface and the two existing hooks, rewire the orchestrator

**What to build:** Turn attaching the OpenSSL uprobe and attaching the XDP program into self-contained modules behind one common interface (attach / event-source identity / parse), and rewire the orchestrator so it no longer hardcodes per-hook attach or parsing logic. The daemon's entry point becomes the composition root, constructing the concrete hook-module list and the detector registry (from ticket 03) and injecting both into the orchestrator.

**Blocked by:** 01 — Scaffold the new module layout and multi-layer build; 03 — Extract the detector interface and the two existing detection rules, with unit tests

**Status:** ready-for-agent

- [x] A common hook-module interface exists: attach (given the shared BPF object and a place to register resulting links), report an event-source identifier, and parse a raw event into the daemon's common event representation
- [x] The OpenSSL uprobe hook and the XDP hook are each implemented as standalone modules behind that interface
- [x] The XDP hook's existing non-fatal attach fallback (native mode, then generic/SKB mode, then a logged skip with uprobe-only operation) is preserved exactly
- [x] The orchestrator no longer contains hook-specific attach or parsing logic — it holds a collection of hook modules (constructed by the daemon's entry point) and dispatches generically by event-source identifier
- [x] The daemon's entry point constructs the concrete hook-module list and the detector registry and injects both into the orchestrator
- [x] End-to-end behavior (attach, detect, log, enforce) has been manually re-verified against QEMU to match pre-refactor behavior exactly

## Comments

First five criteria implemented and verified by careful manual trace (every #include cross-checked against the CMake include-path graph, every symbol traced to its source) — the implementing sandbox has no cmake/clang/libbpf-dev/QEMU, so this could not be compiled or run end-to-end.

**QEMU verification completed** on the shared build machine (`build/johnblue`): `bitbake https-guard-openbmc` and `bitbake obmc-phosphor-image` both succeeded under the real cross-compilation toolchain (after fixing three cross-compile-only path bugs the sandbox couldn't have caught — see the "Fix cross-compile build" commit). Booted the resulting image in QEMU SLIRP mode and confirmed via `systemctl`/`journalctl`: uprobe attached, XDP attached in native mode, `https_guard: enforcement active via 2 of 2 hook(s)` (the new generic log line from this ticket, proving the refactored code — not a stale binary — is what's actually running), ring buffer created, ActionLoop started. Sent real HTTPS requests to bmcweb; the daemon correctly classified them as `OK`/`HttpsTrafficObserved` end-to-end through the new IHookModule → IDetector → Verdict → RedfishEventMessage pipeline, producing well-formed Redfish JSON. Could not force an actual TLS-version violation live (curl/OpenSSL 3.x always negotiates TLS 1.3 regardless of `--tlsv1.x`, a pre-existing documented limitation, not something fixable from the client side) — that exact path is covered instead by the unit tests from ticket 03.

One behavioral risk worth flagging for that verification pass: `HttpGuardProgram::attachProgram()`'s summary log line changed from naming each hook explicitly ("enforcement active via uprobe(SSL_write) xdp") to a generic count ("enforcement active via N of M hook(s)"), since the orchestrator no longer knows hook names — only `IHookModule::attach/eventSource/parseEvent`, per the agreed interface. Each hook still logs its own specific attach outcome internally, so no diagnostic information is actually lost, but anything scraping that particular summary line's exact text (a log-parsing script, a test assertion) would need updating.

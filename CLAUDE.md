# HTTPS-Guard

An eBPF-based network security tool for OpenBMC. It hooks into bmcweb's TLS traffic (uprobes on OpenSSL `SSL_write`/`SSL_read`, primary; XDP on the wire, auxiliary; a BPF-LSM guard on the HTTPS certificate file, auxiliary — currently alert-only on this project's ARM32 target, see `detections/cert_access/DESIGN.md`), classifies what it observes, and reacts (kill the TCP connection, blocklist the source, log a Redfish event).

**Pipeline: Detect → Classify → Dispatch.** The source tree under `recipes-https-guard/https-guard/files/` is organized around exactly those three stages — `programs/` attaches BPF hooks and hands raw records over, `detections/` owns the event types, the parsing and the rules that judge them, `actions/` carries out the response. Each has its own `CLAUDE.md`; start there before editing anything inside.

**How to make each of the nine event types fire**, which Redfish message ID each produces, and which have actually been driven end-to-end on hardware: [README.md § Exercising the Detections](README.md#exercising-the-detections) — the trigger recipes and the verification status live there, next to the commands, rather than in LIMITATIONS.md. Platform, capture and attribution limits that no amount of testing will change: [LIMITATIONS.md](LIMITATIONS.md) — worth reading before trusting any detection or enforcement claim. Full architecture, event struct layouts, and the security-model rationale: [DESIGN.md](DESIGN.md). Build/QEMU/deployment instructions: [README.md](README.md). **Every unit documents itself.** `detections/<family>/DESIGN.md` answers *why detect this, how to detect it, how to protect, what to hook* for one detection (nine of them, including `traffic_observed`); `actions/<kind>/DESIGN.md` does the same per countermeasure. Three layer documents cover the machinery: `programs/DESIGN.md` (`BpfProgram`/`HttpGuardProgram` and per-hook attach), `detections/DESIGN.md` (`DetectLoop`), `actions/DESIGN.md` (`ActionLoop`).

**Working here:**
- BPF-side code (`.bpf.c`/`.bpf.h`) is observational only for `ssl_uprobe`/`xdp_tls` — they capture raw fields and a line-rate hint at most (`xdp_tls`'s `is_violation`); all parsing and classification live in `detections/`. `lsm_cert_guard` is the one exception with a real (if currently unreachable — see its `DESIGN.md`) in-kernel deny branch, since a file-open decision has no equivalent to "classify asynchronously, act on future traffic" the way network events do.
- **Two seams are meant to grow.** A new hook derives from `BpfProgram`, implements `attach()`/`eventSource()`, holds its detections as members and overrides `ringBufferHandler()` to submit them — one line in `programs/core/main.cpp` besides. A new **detection** is one directory under `detections/<family>/` holding its event struct, its rule, its `IDetection` implementation and its `DESIGN.md`, plus one entry in the list of whichever hook can feed it. Nothing else changes, including the composition root.
- **A detection parses and evaluates itself.** `IDetection::inspect(data, size, meta)` returns a `Verdict` or `nullopt`; `DetectLoop` evaluates the submitted list concurrently and dispatches the lowest-index verdict. Nothing outside a detection knows what an event is, and there is no downcast anywhere on the path.
- **List order is priority order, and it lives in the hook.** A ClientHello can satisfy several detections at once and only the lowest-index verdict is dispatched, so `xdp_tls` puts its two enforcing detections ahead of its two alert-only ones. The loop logs which index claimed each record, so the ordering is observable at runtime.
- Two ticket sets are closed: `.scratch/extend-detection-coverage/` (20 tickets, detection coverage and enforcement correctness — three carry "done with caveats" notes worth reading) and `.scratch/detection-first-architecture/` (8 tickets, this layout). See `.claude/agents/issue-tracker.md`.

## Agent skills

### Issue tracker

Issues and specs live as local markdown files under `.scratch/`. See `.claude/agents/issue-tracker.md`.

### Triage labels

Default five canonical triage roles, used as-is (recorded as a `Status:` line, not GitHub labels). See `.claude/agents/triage-labels.md`.

### Domain docs

Single-context: `CONTEXT.md` + `docs/adr/` at this directory's root (created lazily as needed, not yet present). See `.claude/agents/domain.md`.

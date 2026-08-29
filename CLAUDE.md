# HTTPS-Guard

An eBPF-based network security tool for OpenBMC. It hooks into bmcweb's TLS traffic (uprobes on OpenSSL `SSL_write`/`SSL_read`, primary; XDP on the wire, auxiliary; a BPF-LSM guard on the HTTPS certificate file, auxiliary — currently alert-only on this project's ARM32 target, see its own `DESIGN.md`), classifies what it observes, and reacts (kill the TCP connection, blocklist the source, log a Redfish event).

**Pipeline: Detect → Classify → Dispatch.** The source tree under `recipes-https-guard/https-guard/files/` is organized around exactly those three stages — `programs/` attaches BPF hooks and parses raw events, `detectors/` decides whether a parsed event is a violation, `actions/` carries out the response. Each has its own `CLAUDE.md`; start there before editing anything inside.

Full architecture, event struct layouts, and the security-model rationale: [DESIGN.md](DESIGN.md). Build/QEMU/deployment instructions: [README.md](README.md). Per-hook detection rationale with diagrams: `programs/ssl_uprobe/DESIGN.md`, `programs/xdp_tls/DESIGN.md`, and `programs/lsm_cert_guard/DESIGN.md`.

**Working here:**
- BPF-side code (`.bpf.c`/`.bpf.h`) is observational only for `ssl_uprobe`/`xdp_tls` — they capture raw fields and a line-rate hint at most (`xdp_tls`'s `is_violation`); all classification lives behind `IDetector` in `detectors/`. `lsm_cert_guard` is the one exception with a real (if currently unreachable — see its `DESIGN.md`) in-kernel deny branch, since a file-open decision has no equivalent to "classify asynchronously, act on future traffic" the way network events do.
- `IHookModule` (attach/eventSource/parseEvent) and `IDetector` (evaluate → optional `Verdict`) are the two seams meant to grow: a new hook or a new detection rule should only ever require a new class implementing one of these plus one new line in `programs/core/main.cpp`'s composition root, never a change to `HttpGuardProgram` itself.
- Remaining pending work — cipher-suite/SNI detection, connection-rate detection, Slowloris/TLS-renegotiation-storm detection, and doc rewrites — is tracked in `.scratch/` (see `.claude/agents/issue-tracker.md`).

## Agent skills

### Issue tracker

Issues and specs live as local markdown files under `.scratch/`. See `.claude/agents/issue-tracker.md`.

### Triage labels

Default five canonical triage roles, used as-is (recorded as a `Status:` line, not GitHub labels). See `.claude/agents/triage-labels.md`.

### Domain docs

Single-context: `CONTEXT.md` + `docs/adr/` at this directory's root (created lazily as needed, not yet present). See `.claude/agents/domain.md`.

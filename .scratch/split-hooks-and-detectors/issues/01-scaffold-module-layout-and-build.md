# 01 — Scaffold the new module layout and multi-layer build

**What to build:** Move every existing source file to its final location under the agreed layout (`programs/core`, `programs/ssl_uprobe`, `programs/xdp_tls`, `detectors/core`, `detectors/shared`, plus the `actions/log` addition), split the single BPF source and its shared event structs per hook, reorganize the build into one `CMakeLists.txt` per top-level concern, and update the BitBake recipe's file references to match. The daemon must build and behave identically to today when this is done — this is pure move/rename/split, no new interfaces or logic changes.

**Blocked by:** None — can start immediately

**Status:** ready-for-agent

- [x] Every existing source file has moved to its final location per the agreed layout, with nothing left under the old flat locations
- [x] The single BPF object still compiles from one aggregator source that includes a header per hook, with the shared event-source discriminator and per-hook raw event structs split into their owning hook's own header
- [x] The build is organized as one `CMakeLists.txt` per top-level concern (programs, detectors, actions) plus the root build definition — no single shared list of every source file in the project
- [x] The BitBake recipe's file references are updated to match the new paths and the recipe still parses/builds
- [x] The daemon builds successfully and its observable behavior (attach log lines, classification, enforcement, logging output) is unchanged from before the move
- [x] No new interfaces, no detector/hook-module abstractions introduced yet

## Comments

Implemented in commits `c49caa4` (renames) and `94512c8` (new split files, multi-layer build, recipe update).

**Update:** originally verified only by manual `#include` trace (the implementing sandbox had no cmake/clang/libbpf-dev). Later confirmed for real on the shared build machine via `bitbake https-guard-openbmc` + a QEMU boot (see ticket 04's Comments) — the manual trace's one gap was three cross-compile-only output-path bugs (`ssl_version_offset.h`, `https_guard.bpf.o`, `action_runner` all drifting into subdirectory binary dirs once their targets moved into per-concern `CMakeLists.txt` files), fixed in the "Fix cross-compile build" commit. Everything else the manual trace concluded held up.

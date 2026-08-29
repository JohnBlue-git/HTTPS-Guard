# Source tree

The actual C++/eBPF source for the `https-guard-openbmc` BitBake recipe (`../https-guard-openbmc.bb`, one level up). Three top-level concerns, one per pipeline stage, plus support directories:

- **`programs/`** — Detect. Attaches BPF hooks, parses raw events. See `programs/CLAUDE.md`.
- **`detectors/`** — Classify. Pure rules deciding whether a parsed event is a violation. See `detectors/CLAUDE.md`.
- **`actions/`** — Dispatch. Async countermeasures (log, kill connection, blocklist). See `actions/CLAUDE.md`.
- **`tests/`** — doctest unit tests for `detectors/`. No kernel/BPF/root/QEMU dependency; builds host-side only (`HTTPS_GUARD_BUILD_TESTS`, defaults off when cross-compiling).
- **`scripts/gen_ssl_offset.c`** — host tool that determines `ssl_st.version`'s offset at build time (OpenSSL 3.x made the struct opaque).
- **`service/`** — systemd units and their shell wrappers.

## Build system

One `CMakeLists.txt` per concern (`actions_lib`, `detectors_lib`, `programs_lib`), plus this directory's root `CMakeLists.txt` tying them into the final executables (`https_guardd`, `action_runner`) and the BPF object. Adding a source file to one concern's directory should never require touching another concern's `CMakeLists.txt`.

**A trap to know about:** a target's default output directory mirrors the *source* subdirectory its `add_executable`/custom-command lives in, not this directory's build root. If you add a new build artifact that the `.bb` recipe's `do_install()` needs to find, either define it in the root `CMakeLists.txt` or force its output path back to `${CMAKE_BINARY_DIR}` explicitly — see `programs/CMakeLists.txt` and `actions/CMakeLists.txt` for the two existing examples (`https_guard.bpf.o` and `action_runner`), and `DESIGN.md`'s Build System section for the full story of the bug this caused once.

## Whole-pipeline docs

`DESIGN.md` at the repo root covers this entire tree in depth — build system internals, event struct layouts, the `IHookModule`/`IDetector`/`Verdict` interfaces, and the security-model rationale for why detection is asynchronous while blocklist enforcement is synchronous. Read it before making a structural change here.

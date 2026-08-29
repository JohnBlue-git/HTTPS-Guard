# 02 — Stand up a minimal unit-test framework and build target

**What to build:** Integrate a unit-test framework into the build with a dedicated test target, independent of the daemon binary and of any BPF/kernel/root dependency, proven by a placeholder test that runs end-to-end.

**Blocked by:** 01 — Scaffold the new module layout and multi-layer build

**Status:** done

- [x] A test framework is selected and integrated into the build (e.g. via CMake `FetchContent`, matching the project's existing pattern for fetching dependencies like Boost)
- [x] A dedicated test build target/binary exists and is runnable independently of the daemon binary and of any BPF/kernel/root dependency
- [x] At least one placeholder test exists and passes, proving the harness runs end-to-end (build → execute → report pass/fail)
- [x] Running the tests requires no elevated privileges, no kernel BPF support, and no QEMU environment
- [x] No changes to daemon logic or behavior

## Comments

Picked doctest (single-header, MIT), `find_package` first then `FetchContent` fallback pinned to v2.4.11 — same pattern already used for Boost. Defaults off when `CMAKE_CROSSCOMPILING` (tests are a host-side dev tool, not something that needs to build for the BMC target image). Verified for real: fetched the pinned doctest.h and compiled+ran `tests/test_placeholder.cpp` directly with g++ in the implementing sandbox (no cmake available there) — 1/1 test cases, 1/1 assertions passed. The CMake/FetchContent wiring itself could not be exercised end-to-end at the time (no cmake in the sandbox) — later confirmed for real via `bitbake`/QEMU (see ticket 04).

**Update:** `test_placeholder.cpp` removed once ticket 03 gave the suite real tests (`test_detectors.cpp`) — its only job was proving the harness ran before any real test existed, and a broken harness now fails those instead. `DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN` moved to `test_detectors.cpp`, the only remaining `.cpp` in the `https_guard_tests` binary.

# Tests

Host-side unit tests for `detections/` — no kernel, BPF, root or QEMU access
at *runtime*: no test ever opens a BPF map, kills a socket or needs
privilege. `https_guard_tests` does link `libbpf` and `actions_lib` at build
time regardless (see the comment in `CMakeLists.txt`) — `detections_lib`'s
object files need those symbols to resolve even though nothing here calls
into them. Built with GoogleTest, fetched via CMake `FetchContent` the same
way Boost is (see `../CMakeLists.txt`) when it isn't already on the system.
Off by default when cross-compiling for the target image
(`HTTPS_GUARD_BUILD_TESTS`, see the root `CMakeLists.txt`), since these exist
for development, not for the BMC.

## Layout

One file per detection family, mirroring `detections/<family>/`, so a test
for a detection lives at the same address as the detection itself:

```
tests/
├── parsing/
│   └── client_hello_parsing_test.cpp   # programs/xdp_tls/ebpf/parse_client_hello.h
├── detections/
│   ├── tls_version_test.cpp            # detections/tls_version/
│   ├── payload_anomaly_test.cpp        # detections/payload_anomaly/
│   ├── cert_access_test.cpp            # detections/cert_access/
│   ├── cipher_suite_test.cpp           # detections/cipher_suite/
│   ├── sni_test.cpp                    # detections/sni/
│   ├── rate_sweep_test.cpp             # detections/rate_sweep/ (ConnRate, Slowloris, Renegotiation)
│   └── traffic_observed_test.cpp       # detections/traffic_observed/
├── core/
│   ├── event_meta_test.cpp             # detections/core/event/ — EventMeta, lazy peer resolution
│   └── dispatch_priority_test.cpp      # detections/core/engine/ — cross-detection ordering
├── support/
│   └── make_uprobe_event.hpp           # shared raw-record builder, used by 3 of the files above
├── run-ptest                           # ptest entry point — see "Running on target (ptest)" below
└── detectloop/                         # DetectLoop scheduling harness — see below
```

`support/make_uprobe_event.hpp` exists because three files
(`tls_version_test.cpp`, `payload_anomaly_test.cpp`,
`traffic_observed_test.cpp`) each need a real `uprobe_event` wire record to
drive a detection's `inspect()` end-to-end; it's shared rather than
duplicated three times.

`core/` holds what doesn't belong to any single family: `EventMeta` and its
lazy peer-resolution contract (`event_meta_test.cpp`), and the property that
list order — not any per-detection precedence field — decides which verdict
a hook dispatches when more than one detection would fire on the same record
(`dispatch_priority_test.cpp`).

Each detection's rule (`*Detector`, pure classification) and its
`IDetection` wrapper (parse + classify from a raw record, see
`../detections/CLAUDE.md`) are tested together in one file per family —
splitting them further would scatter tests for the same detection across two
files for no benefit.

## Building and running (host)

```sh
cmake -S .. -B build -DHTTPS_GUARD_BUILD_TESTS=ON
cmake --build build --target https_guard_tests
ctest --test-dir build
```

## Running on target (ptest)

`https-guard-openbmc.bb` also wires this suite into BitBake's `ptest`
mechanism, so it can run as the real cross-compiled binary on the target (or
QEMU) rather than only host-side. With `ptest` in `DISTRO_FEATURES`:

- `DEPENDS` picks up `googletest` (`meta-oe`), so `find_package(GTest)` in
  `CMakeLists.txt` finds a real cross-compiled GTest in the sysroot and the
  `FetchContent` fallback (which needs network access, unavailable mid-build)
  is never reached.
- `EXTRA_OECMAKE` forces `HTTPS_GUARD_BUILD_TESTS=ON`, so the normal
  `do_compile` cross-compiles `https_guard_tests` alongside `https_guardd`.
- `do_install_ptest()` installs the binary and `run-ptest` under
  `${PTEST_PATH}` (`/usr/lib/https-guard-openbmc/ptest`), producing an
  `https-guard-openbmc-ptest` package.
- `run-ptest` runs the binary and translates GoogleTest's `[ RUN ]`/`[ OK ]`/
  `[ FAILED ]` lines into the `PASS:`/`FAIL:` lines `ptest-runner` expects.

None of this touches a normal build: `ptest.bbclass` deletes the
`*_ptest_base` tasks entirely when `ptest` isn't in `DISTRO_FEATURES`, so
`HTTPS_GUARD_BUILD_TESTS` stays at its ordinary cross-compiling default
(`OFF`) and `googletest` is never added to `DEPENDS`.

To exercise it: build with `ptest` enabled, install
`https-guard-openbmc-ptest` into the image (or the `ptest-runner` package
image feature), then on the target run `ptest-runner` or
`/usr/lib/https-guard-openbmc/ptest/run-ptest` directly.

## The DetectLoop harness (`detectloop/`)

`detectloop/detectloop_harness.cpp` exercises the **real**
`detections/core/engine/DetectLoop.cpp` — the Boost.Asio loop that owns
parse → classify → dispatch — for properties that are about its
*scheduling* rather than about any detection rule:

| Check | Why it is here |
|---|---|
| Admission is bounded, drop-newest, counted | `asio::post()` is an unbounded queue. On a ~1GB BMC an OOM takes *all* detection with it, where a drop costs one event. |
| Records classified in arrival order | Justifies drop-newest: what is kept is a coherent prefix of history. |
| The sweep is not starved by a record backlog | This exact failure shipped once (ticket 05) and a single-threaded `io_context` reintroduces it by FIFO fairness alone. |
| A throwing detector costs one event, not the daemon | The handlers are `noexcept`; without the per-item boundary a `bad_alloc` is `std::terminate`. |
| Oversized / null / empty `submit()`, and `stop()` idempotence | Boundaries libbpf's callback can actually hit. |

### Why it is not part of `https_guard_tests`

`tests/CMakeLists.txt` builds a binary that deliberately links **nothing**
with a kernel dependency, which is what lets the real parsers be tested
rather than reimplementations. `DetectLoop.cpp` does not fit that: it pulls
in the actions and `nlohmann/json`, and `ConnRateSweeper.cpp` calls libbpf.

So this harness replaces the collaborators at **link time** — `ActionLoop`,
the three actions and libbpf's two map calls are defined in the harness
itself — and only `DetectLoop.cpp` and `ConnRateSweeper.cpp` are compiled
from real source (as is `rate_sweep/`'s three rule headers, which
`ConnRateSweeper.cpp` now calls directly — they're header-only and pull in
no kernel dependency, so nothing about them needs stubbing). Recording the
timestamp of each `bpf_map_get_next_key(fd, nullptr, …)` is how sweep
cadence is observed.

### Building it

Needs `boost` (host), plus `nlohmann/json.hpp` and `bpf/bpf.h` on the
include path — the latter two are most easily taken from the recipe
sysroot, since both are header-only for what this uses:

```sh
SR=<build>/tmp/work/<arch>/https-guard-openbmc/1.0/recipe-sysroot/usr/include
mkdir -p /tmp/hginc && cp -r "$SR/nlohmann" "$SR/bpf" /tmp/hginc/

cd recipes-https-guard/https-guard/files
g++ -std=c++20 -g -O1 -fsanitize=address,undefined -DBOOST_ERROR_CODE_HEADER_ONLY \
    -I/tmp/hginc \
    -Idetections/core/contract -Idetections/core/event -Idetections/core/engine \
    -Idetections/core/sweep -Idetections/tls_version -Idetections/rate_sweep \
    -Iactions -Iactions/core -Iactions/log -Iprograms/xdp_tls/ebpf \
    tests/detectloop/detectloop_harness.cpp \
    detections/core/engine/DetectLoop.cpp detections/core/sweep/ConnRateSweeper.cpp \
    -o /tmp/dl -lpthread
/tmp/dl
```

Exits non-zero on failure. Also run it with `-fsanitize=thread` instead —
the sweep runs concurrently with a record by design, so this is the one
place in the project where a data race is possible, and TSan is what proves
detector statelessness is holding. (TSan may need `setarch -R` on recent
kernels.)

**Folding this into the CMake test target is a genuine follow-up**, not a
dead end: the top-level `CMakeLists.txt` already requires `nlohmann_json` and
`libbpf` to configure at all, so a second test executable compiling
`DetectLoop.cpp` with these doubles would build wherever the project does.
It is left out here only because that change could not be verified on the
development host used for this work, which has no `cmake`.

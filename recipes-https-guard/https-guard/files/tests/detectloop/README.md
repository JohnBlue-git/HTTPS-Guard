# DetectLoop harness

Exercises the **real** `detections/core/DetectLoop.cpp` — the Boost.Asio loop
that owns parse → classify → dispatch — for the properties that are about its
*scheduling* rather than about any detection rule:

| Check | Why it is here |
|---|---|
| Admission is bounded, drop-newest, counted | `asio::post()` is an unbounded queue. On a ~1GB BMC an OOM takes *all* detection with it, where a drop costs one event. |
| Records classified in arrival order | Justifies drop-newest: what is kept is a coherent prefix of history. |
| The sweep is not starved by a record backlog | This exact failure shipped once (ticket 05) and a single-threaded `io_context` reintroduces it by FIFO fairness alone. |
| A throwing detector costs one event, not the daemon | The handlers are `noexcept`; without the per-item boundary a `bad_alloc` is `std::terminate`. |
| Oversized / null / empty `submit()`, and `stop()` idempotence | Boundaries libbpf's callback can actually hit. |

## Why it is not part of `https_guard_tests`

`tests/CMakeLists.txt` builds a binary that deliberately links **nothing** with
a kernel dependency, which is what lets the real parsers be tested rather than
reimplementations. `DetectLoop.cpp` does not fit that: it pulls in the actions
and `nlohmann/json`, and `ConnRateSweeper.cpp` calls libbpf.

So this harness replaces the collaborators at **link time** — `ActionLoop`,
the three actions and libbpf's two map calls are defined in the harness itself
— and only `DetectLoop.cpp` and `ConnRateSweeper.cpp` are compiled from real
source. Recording the timestamp of each `bpf_map_get_next_key(fd, nullptr, …)`
is how sweep cadence is observed.

## Building it

Needs `boost` (host), plus `nlohmann/json.hpp` and `bpf/bpf.h` on the include
path — the latter two are most easily taken from the recipe sysroot, since both
are header-only for what this uses:

```sh
SR=<build>/tmp/work/<arch>/https-guard-openbmc/1.0/recipe-sysroot/usr/include
mkdir -p /tmp/hginc && cp -r "$SR/nlohmann" "$SR/bpf" /tmp/hginc/

cd recipes-https-guard/https-guard/files
g++ -std=c++20 -g -O1 -fsanitize=address,undefined -DBOOST_ERROR_CODE_HEADER_ONLY \
    -I/tmp/hginc \
    -Idetections/core -Idetections/tls_version -Idetections/conn_rate \
    -Idetections/slowloris -Idetections/renegotiation \
    -Iactions -Iactions/core -Iactions/log -Iprograms/xdp_tls/ebpf \
    tests/detectloop/detectloop_harness.cpp \
    detections/core/DetectLoop.cpp detections/conn_rate/ConnRateSweeper.cpp \
    -o /tmp/dl -lpthread
/tmp/dl
```

Exits non-zero on failure. Also run it with `-fsanitize=thread` instead — the
sweep runs concurrently with a record by design, so this is the one place in
the project where a data race is possible, and TSan is what proves detector
statelessness is holding. (TSan may need `setarch -R` on recent kernels.)

**Folding this into the CMake test target is a genuine follow-up**, not a
dead end: the top-level `CMakeLists.txt` already requires `nlohmann_json` and
`libbpf` to configure at all, so a second test executable compiling
`DetectLoop.cpp` with these doubles would build wherever the project does. It
is left out here only because that change could not be verified on the
development host used for this work, which has no `cmake`.

# Tests

Host-side tests for `detections/` and the DetectLoop scheduling boundary. They
need no kernel, BPF runtime, root or QEMU access: no test opens a BPF map, kills
a socket or needs privilege.

The suite uses GoogleTest and GoogleMock. CMake fetches GoogleTest v1.15.2 when
the `GTest::gmock` target is not already available. GMock injects behavior at
the existing `IDetection` interface, so tests can return selected verdicts,
throw exceptions, and verify concurrent calls without changing production
interfaces. Purpose-built probes remain for timing and arrival-order checks,
where recorded measurements are clearer than call expectations.

`HTTPS_GUARD_BUILD_TESTS` is off by default when cross-compiling for the target
image. These are development and ptest targets, not daemon runtime code.

### GoogleTest and GoogleMock basics

GoogleTest (`gtest`) supplies the test case macro, test runner and assertions.
Tests are grouped by a suite name and a case name; both names appear in the
GoogleTest output:

```cpp
TEST(TlsVersionDetectorTest, FlagsLegacyVersion)
{
      TlsVersionEvent event;
      event.tls_version = 0x0302;  // TLS 1.1

      const auto verdict = TlsVersionDetector{}.evaluate(event);

      ASSERT_TRUE(verdict.has_value());  // stop if later access needs a value
      EXPECT_EQ(verdict->severity, "Critical");
      EXPECT_TRUE(verdict->actionable);
}
```

Use `ASSERT_*` when a failed condition makes the rest of the test unsafe or
meaningless. Use `EXPECT_*` when later assertions can still provide useful
failure information. Common assertions in this repository are `EXPECT_EQ`,
`EXPECT_TRUE`, `EXPECT_FALSE`, `ASSERT_TRUE` and `ASSERT_NE`.

GoogleMock (`gmock`) supplies mock objects for virtual interfaces. Include
`<gmock/gmock.h>`, derive a mock from the production interface, and declare
methods with `MOCK_METHOD`:

```cpp
class MockPeerResolver final : public IPeerResolver
{
public:
      MOCK_METHOD(bool, resolvePeer, (EventMeta&), (const, noexcept, override));
};
```

Then describe the interaction before exercising the real code. This example
proves that parsing stores the resolver but does not perform the expensive
peer lookup:

```cpp
MockPeerResolver resolver;
EXPECT_CALL(resolver, resolvePeer(::testing::_)).Times(0);

EventMeta meta;
TrafficObservedDetection<struct uprobe_event> detection{&resolver};
detection.inspect(&raw, sizeof(raw), meta);

EXPECT_EQ(meta.peer_resolver, &resolver);
EXPECT_EQ(meta.remote_ip_v4, 0u);
```

`::testing::_` matches any argument. Other useful matchers include
`Eq(value)`, `NotNull()` and `Field(&Type::member, matcher)`. `Times(1)` means
exactly one call; `Times(0)` means the method must not be called. A mock's
default behavior can be set with `ON_CALL`, while `EXPECT_CALL` states the
interaction the test requires:

```cpp
EXPECT_CALL(resolver, resolvePeer(::testing::_))
      .Times(1)
      .WillOnce(::testing::Invoke([](EventMeta& resolved) noexcept {
            resolved.remote_ip_v4 = 0x0100000A;
            return true;
      }));

EXPECT_TRUE(meta.ensurePeerResolved());
EXPECT_TRUE(meta.ensurePeerResolved());  // memoized: still only one call
```

`Return(value)` is enough for a method with no output parameter; `Invoke`
lets the fake method mutate an output reference and return a value. The
`event_meta_test.cpp` tests use these two actions to verify both successful
and failed resolution, including the no-retry behavior.

For the DetectLoop fan-out, GMock injects two `IDetection` objects and verifies
that both are evaluated even though the lower-index verdict wins:

```cpp
EXPECT_CALL(first, inspect(::testing::_, ::testing::_, ::testing::_))
      .WillOnce(::testing::Return(std::optional<Verdict>{verdict_a}));
EXPECT_CALL(second, inspect(::testing::_, ::testing::_, ::testing::_))
      .WillOnce(::testing::Return(std::optional<Verdict>{verdict_b}));

const std::array<const IDetection*, 2> detections{&first, &second};
loop.submit(bytes, sizeof(bytes), detections);
```

The production detector/parser is real in these examples. GMock replaces only
the collaborator at an interface boundary; mocking the detector under test
would merely verify the mock setup instead of verifying classification.

```text
GTest:  real detector/parser -> real result -> assertions
GMock:  real pipeline        -> injected collaborator -> call expectations
```

Build and run the tests with:

```sh
ctest --test-dir build --output-on-failure
# or run one GoogleTest binary directly:
./build/tests/https_guard_tests --gtest_filter=TlsVersionDetectorTest.*
```

## Layout

```text
tests/
├── parsing/
│   └── client_hello_parsing_test.cpp
├── detections/
│   ├── tls_version_test.cpp
│   ├── payload_anomaly_test.cpp
│   ├── cert_access_test.cpp
│   ├── cipher_suite_test.cpp
│   ├── sni_test.cpp
│   ├── rate_sweep_test.cpp
│   └── traffic_observed_test.cpp
├── core/
│   ├── event_meta_test.cpp
│   └── dispatch_priority_test.cpp
├── support/
│   └── make_uprobe_event.hpp
├── detectloop/
│   └── detectloop_harness.cpp
├── run-ptest
└── CMakeLists.txt
```

`parsing/` contains parser tests. `support/` contains shared fixtures and
builders used by several tests; it is intentionally separate from a generic
`utils/` directory so the role of each helper remains clear.

The ordinary `https_guard_tests` target tests real parsers and detector rules.
It links the existing `detections_lib` and `actions_lib` object targets because
their objects and usage requirements are already part of the project build.

The separate `detectloop_harness` target tests scheduling properties of the
real `DetectLoop.cpp` and `ConnRateSweeper.cpp`. It uses a GMock
`IDetection` for the fan-out and priority test, plus local link-time doubles
for `ActionLoop`, actions, `dispatchVerdict()` and the two libbpf map calls.
It does not link the complete `detections_lib` or `actions_lib` objects, since
those would reintroduce the collaborators being replaced.

The current test split is deliberate:

| Test area | Framework/style | What it proves |
|---|---|---|
| `parsing/` | GTest, real parser | Wire bytes are parsed correctly and safely. |
| `detections/` | GTest, real detector and detection wrapper | Rules, boundaries and returned verdicts are correct. |
| `core/dispatch_priority_test.cpp` | GTest, real detection list | Real detection order produces the expected winner. |
| `core/event_meta_test.cpp` | GTest + GMock `IPeerResolver` | Lazy resolution, exactly-once memoization and no retry after failure. |
| `detectloop/` | GTest-style checks + GMock `IDetection` | Scheduling, fan-out, exception boundaries and priority injection. |

## DetectLoop harness

The harness covers properties that belong to the loop rather than an
individual detection rule:

| Check | Why it is here |
|---|---|
| Admission is bounded, drop-newest, counted | `asio::post()` is unbounded; one dropped event is preferable to an OOM that kills all detection. |
| Records are classified in arrival order | The record strand preserves a coherent prefix when newest records are dropped. |
| The sweep is not starved by a record backlog | The timer runs outside the record strand on the second worker. |
| A throwing detector costs one event, not the daemon | The per-record `noexcept` boundary catches detector failures. |
| Oversized/null/empty submit and idempotent stop | These are boundaries the libbpf callback can actually reach. |
| Lowest-index verdict wins | GMock verifies every detection is called, while dispatch still chooses the first result. |

The test boundary is:

```text
real code under test
  DetectLoop.cpp
  ConnRateSweeper.cpp
  rate_sweep rule headers
        |
        v
injected collaborators
  GMock IDetection instances
  local action/dispatch doubles
  local bpf_map_lookup_elem/get_next_key doubles
```

The doubles keep the harness independent of a kernel and make scheduling
observable. In particular, the fake `bpf_map_get_next_key()` records the time
at which each sweep starts. The rate rules remain real header-only code.

## CMake build graph

Build both test executables through the same root CMake invocation:

```sh
cmake -S recipes-https-guard/https-guard/files -B build \
      -DHTTPS_GUARD_BUILD_TESTS=ON -DHTTPS_GUARD_BUILD_BPF=OFF \
      -DHTTPS_GUARD_FETCH_LIBBPF=ON
cmake --build build --target https_guard_tests detectloop_harness
ctest --test-dir build
```

```text
root CMakeLists.txt
├─ discover libbpf, nlohmann_json and Boost once
│  └─ optional HTTPS_GUARD_FETCH_LIBBPF uses ExternalProject for libbpf's Makefile
├─ if HTTPS_GUARD_BUILD_TESTS
│  ├─ find_package(Threads)
│  └─ https_guard_test_deps (INTERFACE)
│     └─ shared test include paths, libraries and compile flags
├─ actions/     └─ actions_lib (OBJECT)
├─ detections/  └─ detections_lib (OBJECT)
├─ programs/    └─ programs_lib (OBJECT) + optional BPF object
└─ tests/
   ├─ FetchContent GoogleTest/GMock once when GTest::gmock is unavailable
   ├─ https_guard_tests
   │  └─ GTest + detections_lib + actions_lib + https_guard_test_deps
   └─ detectloop_harness
      └─ GMock + real engine sources + local link-time doubles
```

`https_guard_test_deps` is created in the root [CMakeLists.txt](../CMakeLists.txt)
and consumed by [tests/CMakeLists.txt](CMakeLists.txt). This keeps package
discovery and common host flags in one place. The harness's production source
selection remains explicit so its doubles cannot be shadowed by real object
library definitions.

For sanitizer runs, add `-DCMAKE_CXX_FLAGS=-fsanitize=address,undefined -g`
to the configure command and rebuild `detectloop_harness`. ThreadSanitizer is
also useful for the concurrent sweep, though it may need `setarch -R` on recent
kernels.

## Running on target (ptest)

The recipe wires `https_guard_tests` into BitBake's ptest mechanism. With
`ptest` in `DISTRO_FEATURES`, `DEPENDS` supplies cross-compiled googletest,
`HTTPS_GUARD_BUILD_TESTS=ON` is forced, and `do_install_ptest()` installs the
test binary and `run-ptest` under `${PTEST_PATH}`. The test runner translates
GoogleTest output into the `PASS:`/`FAIL:` lines expected by `ptest-runner`.

Without `ptest`, the ptest tasks are removed and the normal cross-compiled
build keeps tests disabled. To exercise ptest, install
`https-guard-openbmc-ptest` and run `ptest-runner` on the target.

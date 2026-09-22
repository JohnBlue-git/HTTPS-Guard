# Unit-test target: exercises pure C++ logic — currently the detections/
# layer (IDetection implementations) — with no kernel/BPF/root/QEMU access at
# runtime (nothing here opens a BPF map, kills a socket or needs privilege).
# It does link libbpf and actions_lib (see the comment below) since
# detections_lib's object files need those symbols to resolve, even though no
# test ever calls into them. Uses GoogleTest (BSD-3-Clause) fetched the same
# way Boost is fetched above when not already present on the system, so this
# doesn't introduce a new dependency-management pattern.

find_package(GTest QUIET)

if(NOT TARGET GTest::gmock)
    message(STATUS "GoogleTest/GMock not found on system; fetching GoogleTest v1.15.2 via CMake FetchContent")
    set(INSTALL_GTEST OFF CACHE BOOL "" FORCE)
    FetchContent_Declare(
        googletest
        URL https://github.com/google/googletest/archive/refs/tags/v1.15.2.tar.gz
        DOWNLOAD_EXTRACT_TIMESTAMP TRUE
    )
    FetchContent_MakeAvailable(googletest)
endif()

# One file per detection family, mirroring detections/<family>/, plus
# parsing/ (the shared wire parser) and core/ (the engine-level contracts:
# EventMeta/peer resolution, and cross-detection dispatch priority). See
# TESTS.md for the layout and the reasoning behind it.
add_executable(https_guard_tests
    parsing/client_hello_parsing_test.cpp
    detections/tls_version_test.cpp
    detections/payload_anomaly_test.cpp
    detections/cert_access_test.cpp
    detections/cipher_suite_test.cpp
    detections/sni_test.cpp
    detections/rate_sweep_test.cpp
    detections/traffic_observed_test.cpp
    core/event_meta_test.cpp
    core/dispatch_priority_test.cpp
    actions/tcp_destroyer_test.cpp
)
# detections_lib is an OBJECT library whose sources (dispatch.cpp,
# ConnRateSweeper.cpp) call into actions_lib and raw libbpf. Object libraries
# don't auto-chain a second level of object-library links, so — matching the
# same explicit listing detect_runner already uses in detections/CMakeLists.txt
# — actions_lib and libbpf must be named here too, or the final link fails
# with undefined references, even though no TEST_CASE ever calls into either
# at runtime: nothing here constructs a DetectLoop, dispatches a verdict, or
# touches a BPF map, only the plain parsers and *Detector rule classes.
target_link_libraries(https_guard_tests PRIVATE
    GTest::gtest_main
    GTest::gmock
    detections_lib
    actions_lib
    https_guard_test_deps
)

# The paths below are the few headers that live under programs/ because they
# are the BPF<->userspace wire format rather than code.
target_include_directories(https_guard_tests PRIVATE
    # The raw <hook>_event.h wire structs, and boundedString(). Every source's
    # parse() is header-only, so the tests exercise the real parser directly
    # rather than a reimplementation of it.
    ${CMAKE_SOURCE_DIR}/programs/ssl_uprobe/ebpf
    ${CMAKE_SOURCE_DIR}/programs/xdp_tls/ebpf
    ${CMAKE_SOURCE_DIR}/programs/lsm_cert_guard/ebpf
    ${CMAKE_SOURCE_DIR}/programs/utils
)

# Compile only the production engine sources exercised by this harness. Its
# link-time doubles replace actions, dispatch and libbpf, so the complete
# detections_lib/actions_lib object libraries must not be linked here.
add_executable(detectloop_harness
    detectloop/detectloop_harness.cpp
    ${CMAKE_SOURCE_DIR}/detections/core/engine/DetectLoop.cpp
    ${CMAKE_SOURCE_DIR}/detections/core/sweep/ConnRateSweeper.cpp
    ${CMAKE_SOURCE_DIR}/detections/core/sweep/SessionTupleSweeper.cpp
)
target_include_directories(detectloop_harness PRIVATE
    ${CMAKE_SOURCE_DIR}/detections/core/contract
    ${CMAKE_SOURCE_DIR}/detections/core/event
    ${CMAKE_SOURCE_DIR}/detections/core/engine
    ${CMAKE_SOURCE_DIR}/detections/core/sweep
    ${CMAKE_SOURCE_DIR}/detections/rate_sweep
    ${CMAKE_SOURCE_DIR}/actions
    ${CMAKE_SOURCE_DIR}/actions/core
    ${CMAKE_SOURCE_DIR}/actions/log
    ${CMAKE_SOURCE_DIR}/actions/blocklist
    ${CMAKE_SOURCE_DIR}/actions/tcp
    ${CMAKE_SOURCE_DIR}/programs/xdp_tls/ebpf
    ${CMAKE_SOURCE_DIR}/programs/ssl_uprobe/ebpf
)
target_link_libraries(detectloop_harness PRIVATE
    GTest::gmock
    https_guard_test_deps
)

include(CTest)
add_test(NAME https_guard_tests COMMAND https_guard_tests)
add_test(NAME detectloop_harness COMMAND detectloop_harness)

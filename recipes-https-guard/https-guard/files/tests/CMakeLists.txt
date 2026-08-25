# Unit-test target: exercises pure C++ logic — currently the detections/
# layer (IDetector implementations) — with no kernel/BPF/root/QEMU
# dependency. Uses doctest (single-header, MIT) fetched the same way
# Boost is fetched above when not already present on the system, so
# this doesn't introduce a new dependency-management pattern.

find_package(doctest QUIET)

if(NOT doctest_FOUND)
    message(STATUS "doctest not found on system; fetching doctest v2.4.11 via CMake FetchContent")
    FetchContent_Declare(
        doctest
        URL https://github.com/doctest/doctest/archive/refs/tags/v2.4.11.tar.gz
        DOWNLOAD_EXTRACT_TIMESTAMP TRUE
    )
    FetchContent_MakeAvailable(doctest)
endif()

add_executable(https_guard_tests
    test_detectors.cpp
    test_uprobe_parsing.cpp
    test_client_hello_parsing.cpp
)
target_link_libraries(https_guard_tests PRIVATE doctest::doctest detections_lib)

# These tests exercise the real parsers and the real rules with no kernel, no
# root and no actions linked. That is possible because everything they touch is
# deliberately dependency-free: each source's parse() is header-only,
# parse_client_hello.h is shared verbatim with the BPF program, and the rules
# are concept-bound templates over plain event structs.
#
# detections_lib is linked for the rest of the classification tree; the paths
# below are the few headers that live under programs/ because they are the
# BPF<->userspace wire format rather than code.
target_include_directories(https_guard_tests PRIVATE
    # The raw <hook>_event.h wire structs, and boundedString(). Every source's
    # parse() is header-only for exactly this reason: the tests exercise the
    # real parser, and they must not have to link the actions to do it.
    ${CMAKE_SOURCE_DIR}/programs/ssl_uprobe/ebpf
    ${CMAKE_SOURCE_DIR}/programs/xdp_tls/ebpf
    ${CMAKE_SOURCE_DIR}/programs/lsm_cert_guard/ebpf
    ${CMAKE_SOURCE_DIR}/programs/utils
)

include(CTest)
add_test(NAME https_guard_tests COMMAND https_guard_tests)

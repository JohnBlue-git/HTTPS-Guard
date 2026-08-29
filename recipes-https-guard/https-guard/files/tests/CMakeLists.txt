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

# These tests exercise the parsing headers under programs/ that are
# deliberately dependency-free (parse_uprobe_event.hpp, parse_client_hello.h)
# -- add just their header paths, not the full programs_lib, which would pull
# in libbpf via IHookModule.hpp/BpfProgram.cpp. That dependency-free property
# is what lets the *real* parsers be tested rather than reimplementations.
target_include_directories(https_guard_tests PRIVATE
    ${CMAKE_SOURCE_DIR}/programs/core
    ${CMAKE_SOURCE_DIR}/programs/ssl_uprobe/ebpf
    ${CMAKE_SOURCE_DIR}/programs/ssl_uprobe/src
    ${CMAKE_SOURCE_DIR}/programs/xdp_tls/ebpf
    ${CMAKE_SOURCE_DIR}/programs/utils
)

include(CTest)
add_test(NAME https_guard_tests COMMAND https_guard_tests)

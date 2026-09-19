cmake_minimum_required(VERSION 3.20)
project(https_guard LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

option(HTTPS_GUARD_BUILD_BPF "Build the HTTPS-Guard BPF object" ON)
set(HTTPS_GUARD_BPF_CLANG_EXECUTABLE "clang" CACHE STRING "Clang executable used for BPF builds")
set(HTTPS_GUARD_BPFTOOL_EXECUTABLE "bpftool" CACHE STRING "bpftool executable used to generate vmlinux.h")
set(HTTPS_GUARD_TARGET_VMLINUX "" CACHE FILEPATH "Target kernel vmlinux with BTF metadata")
set(HTTPS_GUARD_BPF_SYSROOT_INCLUDE "" CACHE PATH "Sysroot include path for BPF builds")
set(HTTPS_GUARD_BPF_SOURCE_PREFIX_MAP "" CACHE STRING "file-prefix-map for source paths")
set(HTTPS_GUARD_BPF_BINARY_PREFIX_MAP "" CACHE STRING "file-prefix-map for build paths")
set(HTTPS_GUARD_BPF_SYSROOT_PREFIX_MAP "" CACHE STRING "file-prefix-map for target sysroot paths")
set(HTTPS_GUARD_BPF_SYSROOT_NATIVE_PREFIX_MAP "" CACHE STRING "file-prefix-map for native sysroot paths")
set(HTTPS_GUARD_LIBSSL_PATH "" CACHE FILEPATH "Path to libssl.so for BTF CO-RE header generation (unused — see note below)")

include(FetchContent)
include(ExternalProject)

option(HTTPS_GUARD_FETCH_LIBBPF
    "Build libbpf from source when no system libbpf is available"
    OFF)

# Tests are host-side development tools. Decide this before creating their
# dependency target so cross-compiling the daemon does not configure test-only
# host dependencies by accident.
if(CMAKE_CROSSCOMPILING)
    option(HTTPS_GUARD_BUILD_TESTS "Build the HTTPS-Guard unit test binary" OFF)
else()
    option(HTTPS_GUARD_BUILD_TESTS "Build the HTTPS-Guard unit test binary" ON)
endif()

find_package(PkgConfig QUIET)
if(PkgConfig_FOUND)
    pkg_check_modules(LIBBPF QUIET libbpf)
endif()

if(NOT LIBBPF_FOUND)
    if(NOT HTTPS_GUARD_FETCH_LIBBPF)
        message(FATAL_ERROR
            "libbpf was not found. Install libbpf-dev or configure with "
            "-DHTTPS_GUARD_FETCH_LIBBPF=ON")
    endif()

    # libbpf v1.4.5 ships an upstream Makefile rather than a CMake project, so
    # FetchContent_MakeAvailable() cannot create a usable CMake target here.
    # Build its static archive with ExternalProject and expose it as one.
    set(LIBBPF_FETCH_SOURCE_DIR "${CMAKE_BINARY_DIR}/_deps/libbpf-src")
    ExternalProject_Add(libbpf_external
        URL https://github.com/libbpf/libbpf/archive/refs/tags/v1.4.5.tar.gz
        DOWNLOAD_EXTRACT_TIMESTAMP TRUE
        SOURCE_DIR ${LIBBPF_FETCH_SOURCE_DIR}
        CONFIGURE_COMMAND ""
        BUILD_IN_SOURCE TRUE
        BUILD_COMMAND ${CMAKE_MAKE_PROGRAM} -C <SOURCE_DIR>/src
            BUILD_STATIC_ONLY=1 NO_PKG_CONFIG=1
        INSTALL_COMMAND ""
        BUILD_BYPRODUCTS ${LIBBPF_FETCH_SOURCE_DIR}/src/libbpf.a
    )

    add_library(libbpf_fetched STATIC IMPORTED GLOBAL)
    set_target_properties(libbpf_fetched PROPERTIES
        IMPORTED_LOCATION ${LIBBPF_FETCH_SOURCE_DIR}/src/libbpf.a
        INTERFACE_INCLUDE_DIRECTORIES
            "${LIBBPF_FETCH_SOURCE_DIR}/src;${LIBBPF_FETCH_SOURCE_DIR}/include;${LIBBPF_FETCH_SOURCE_DIR}/include/uapi"
        INTERFACE_LINK_LIBRARIES "elf;z"
    )
    add_dependencies(libbpf_fetched libbpf_external)

    set(LIBBPF_FOUND TRUE)
    set(LIBBPF_INCLUDE_DIRS
        ${LIBBPF_FETCH_SOURCE_DIR}/src
        ${LIBBPF_FETCH_SOURCE_DIR}/include
        ${LIBBPF_FETCH_SOURCE_DIR}/include/uapi
    )
    set(LIBBPF_LIBRARY_DIRS "")
    set(LIBBPF_LIBRARIES libbpf_fetched)
endif()

find_package(nlohmann_json REQUIRED)
find_package(Boost 1.74 QUIET)

if(Boost_FOUND)
    set(BOOST_INCLUDE_DIR ${Boost_INCLUDE_DIRS})
    message(STATUS "Using system Boost includes: ${BOOST_INCLUDE_DIR}")
else()
    message(STATUS "Boost headers not found; fetching Boost 1.86 headers via CMake FetchContent")
    FetchContent_Declare(
        boost_headers
        URL https://downloads.sourceforge.net/project/boost/boost/1.86.0/boost_1_86_0.tar.gz
        DOWNLOAD_EXTRACT_TIMESTAMP TRUE
    )
    FetchContent_MakeAvailable(boost_headers)
    set(BOOST_INCLUDE_DIR ${boost_headers_SOURCE_DIR})
    message(STATUS "Using fetched Boost headers: ${BOOST_INCLUDE_DIR}")
endif()

if(HTTPS_GUARD_BUILD_TESTS)
    find_package(Threads REQUIRED)

    # Shared host-side dependencies for tests. The test subdirectory consumes
    # this target instead of rediscovering or relinking the same package setup.
    add_library(https_guard_test_deps INTERFACE)
    target_include_directories(https_guard_test_deps INTERFACE
        ${LIBBPF_INCLUDE_DIRS}
        ${nlohmann_json_INCLUDE_DIRS}
        ${BOOST_INCLUDE_DIR}
    )
    target_link_directories(https_guard_test_deps INTERFACE ${LIBBPF_LIBRARY_DIRS})
    target_link_libraries(https_guard_test_deps INTERFACE
        ${LIBBPF_LIBRARIES}
        nlohmann_json::nlohmann_json
        Threads::Threads
    )
    target_compile_definitions(https_guard_test_deps INTERFACE BOOST_ERROR_CODE_HEADER_ONLY)
endif()

# Each top-level concern owns its own CMakeLists.txt and produces one
# library target: actions_lib, detections_lib, programs_lib (the latter
# also owns the BPF object build, since that's what it compiles).  Adding
# a source file to one concern never requires touching this file.
add_subdirectory(actions)
add_subdirectory(detections)
add_subdirectory(programs)

# Tests are a host-side development tool (no kernel/BPF/QEMU dependency —
# see tests/CMakeLists.txt), not something that needs to run on the BMC target.
if(HTTPS_GUARD_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

add_executable(https_guardd
    programs/core/main.cpp
)
target_link_libraries(https_guardd PRIVATE programs_lib detections_lib actions_lib)

if(HTTPS_GUARD_BUILD_BPF)
    add_dependencies(https_guardd https_guard_bpf)
endif()

foreach(target IN ITEMS https_guardd action_runner detect_runner)
    target_include_directories(${target}
        PRIVATE
        ${LIBBPF_INCLUDE_DIRS}
        ${nlohmann_json_INCLUDE_DIRS}
        ${BOOST_INCLUDE_DIR}
    )

    target_link_directories(${target} PRIVATE ${LIBBPF_LIBRARY_DIRS})
    target_link_libraries(${target} PRIVATE ${LIBBPF_LIBRARIES} nlohmann_json::nlohmann_json)
    target_compile_definitions(${target} PRIVATE BOOST_ERROR_CODE_HEADER_ONLY)
    target_compile_options(${target} PRIVATE ${LIBBPF_CFLAGS_OTHER})
endforeach()

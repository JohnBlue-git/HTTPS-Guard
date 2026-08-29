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

find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBBPF REQUIRED libbpf)

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

# Each top-level concern owns its own CMakeLists.txt and produces one
# library target: actions_lib, detectors_lib, programs_lib (the latter
# also owns the BPF object build, since that's what it compiles).  Adding
# a source file to one concern never requires touching this file.
add_subdirectory(actions)
add_subdirectory(detectors)
add_subdirectory(programs)

# Tests are a host-side development tool (no kernel/BPF/QEMU dependency —
# see tests/CMakeLists.txt), not something that needs to run on the BMC
# target, so default them off when cross-compiling for the target image.
if(CMAKE_CROSSCOMPILING)
    option(HTTPS_GUARD_BUILD_TESTS "Build the HTTPS-Guard unit test binary" OFF)
else()
    option(HTTPS_GUARD_BUILD_TESTS "Build the HTTPS-Guard unit test binary" ON)
endif()
if(HTTPS_GUARD_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

add_executable(https_guardd
    programs/core/main.cpp
)
target_link_libraries(https_guardd PRIVATE programs_lib detectors_lib actions_lib)

if(HTTPS_GUARD_BUILD_BPF)
    add_dependencies(https_guardd https_guard_bpf)
endif()

foreach(target IN ITEMS https_guardd action_runner)
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

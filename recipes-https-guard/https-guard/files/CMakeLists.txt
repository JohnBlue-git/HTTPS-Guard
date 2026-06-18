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

if(HTTPS_GUARD_BUILD_BPF)
    if("${HTTPS_GUARD_TARGET_VMLINUX}" STREQUAL "")
        message(FATAL_ERROR "HTTPS_GUARD_TARGET_VMLINUX must point to the target kernel vmlinux when HTTPS_GUARD_BUILD_BPF is enabled")
    endif()

    if(NOT EXISTS "${HTTPS_GUARD_TARGET_VMLINUX}")
        message(FATAL_ERROR "Target kernel vmlinux not found: ${HTTPS_GUARD_TARGET_VMLINUX}")
    endif()

    if(CMAKE_SYSTEM_PROCESSOR MATCHES "^(arm|armv[0-9])")
        set(HTTPS_GUARD_BPF_TARGET_ARCH arm)
    elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "^(aarch64|arm64)")
        set(HTTPS_GUARD_BPF_TARGET_ARCH arm64)
    elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "^(i[3-6]86|x86_64)")
        set(HTTPS_GUARD_BPF_TARGET_ARCH x86)
    elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "^(powerpc|ppc64|ppc64le)")
        set(HTTPS_GUARD_BPF_TARGET_ARCH powerpc)
    elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "^riscv64")
        set(HTTPS_GUARD_BPF_TARGET_ARCH riscv)
    else()
        message(FATAL_ERROR "Unsupported processor for BPF target: ${CMAKE_SYSTEM_PROCESSOR}")
    endif()

    set(HTTPS_GUARD_BPF_OBJECT ${CMAKE_CURRENT_BINARY_DIR}/https_guard.bpf.o)
    set(HTTPS_GUARD_VMLINUX_HEADER ${CMAKE_CURRENT_BINARY_DIR}/vmlinux.h)

    add_custom_command(
        OUTPUT ${HTTPS_GUARD_VMLINUX_HEADER}
        COMMAND ${CMAKE_COMMAND} -E rm -f ${HTTPS_GUARD_VMLINUX_HEADER}
        COMMAND sh -c "${HTTPS_GUARD_BPFTOOL_EXECUTABLE} btf dump file '${HTTPS_GUARD_TARGET_VMLINUX}' format c > '${HTTPS_GUARD_VMLINUX_HEADER}'"
        DEPENDS ${HTTPS_GUARD_TARGET_VMLINUX}
        VERBATIM
        COMMENT "Generating target-kernel vmlinux.h for CO-RE"
    )

    set(HTTPS_GUARD_BPF_FLAGS
        -target bpf
        -D__TARGET_ARCH_${HTTPS_GUARD_BPF_TARGET_ARCH}
        -O2
        -g
        -I${CMAKE_CURRENT_BINARY_DIR}
        -I${CMAKE_CURRENT_SOURCE_DIR}/https_guard
    )

    if(LIBBPF_INCLUDE_DIRS)
        list(APPEND HTTPS_GUARD_BPF_FLAGS -I${LIBBPF_INCLUDE_DIRS})
    endif()

    if(HTTPS_GUARD_BPF_SYSROOT_INCLUDE)
        list(APPEND HTTPS_GUARD_BPF_FLAGS -I${HTTPS_GUARD_BPF_SYSROOT_INCLUDE})
    endif()

    foreach(prefix_map_var IN ITEMS
            HTTPS_GUARD_BPF_SOURCE_PREFIX_MAP
            HTTPS_GUARD_BPF_BINARY_PREFIX_MAP
            HTTPS_GUARD_BPF_SYSROOT_PREFIX_MAP
            HTTPS_GUARD_BPF_SYSROOT_NATIVE_PREFIX_MAP)
        if(NOT "${${prefix_map_var}}" STREQUAL "")
            list(APPEND HTTPS_GUARD_BPF_FLAGS -ffile-prefix-map=${${prefix_map_var}})
        endif()
    endforeach()

    add_custom_command(
        OUTPUT ${HTTPS_GUARD_BPF_OBJECT}
        COMMAND ${HTTPS_GUARD_BPF_CLANG_EXECUTABLE} ${HTTPS_GUARD_BPF_FLAGS}
                -c ${CMAKE_CURRENT_SOURCE_DIR}/https_guard/https_guard.bpf.c
                -o ${HTTPS_GUARD_BPF_OBJECT}
        DEPENDS
            ${HTTPS_GUARD_VMLINUX_HEADER}
            ${CMAKE_CURRENT_SOURCE_DIR}/https_guard/https_guard.bpf.c
        VERBATIM
        COMMENT "Compiling HTTPS-Guard BPF object"
    )


    add_custom_target(https_guard_bpf ALL DEPENDS ${HTTPS_GUARD_BPF_OBJECT})
endif()

add_executable(action_runner
    actions/core/main.cpp
    actions/core/ActionLoop.cpp
)

add_executable(https_guardd
    https_guard/main.cpp
    https_guard/https_guard_program.cpp
    actions/core/ActionLoop.cpp
    actions/log/LogAction.cpp
    actions/blocklist/Blocklist.cpp
    actions/blocklist/BlocklistAction.cpp
    actions/tcp/BlockTcpAction.cpp
    actions/tcp/TcpDestroyer.cpp
    ebpf/bpf_program.cpp
)


if(HTTPS_GUARD_BUILD_BPF)
    add_dependencies(https_guardd https_guard_bpf)
endif()

foreach(target IN ITEMS https_guardd action_runner)
    target_include_directories(${target}
        PRIVATE
        https_guard
        actions
        actions/core
        actions/blocklist
        actions/tcp
        actions/log
        ebpf
        ${LIBBPF_INCLUDE_DIRS}
        ${nlohmann_json_INCLUDE_DIRS}
        ${BOOST_INCLUDE_DIR}
    )

    target_link_directories(${target} PRIVATE ${LIBBPF_LIBRARY_DIRS})
    target_link_libraries(${target} PRIVATE ${LIBBPF_LIBRARIES} nlohmann_json::nlohmann_json)
    target_compile_definitions(${target} PRIVATE BOOST_ERROR_CODE_HEADER_ONLY)
    target_compile_options(${target} PRIVATE ${LIBBPF_CFLAGS_OTHER})
endforeach()

# Detect layer: the generic BPF lifecycle wrapper (core/src/BpfProgram),
# the HTTPS-Guard-specific orchestrator (core/src/HttpGuardProgram), and the
# per-hook attach/parse modules (ssl_uprobe/, xdp_tls/, lsm_cert_guard/).
# Also owns the BPF object build below, since core/ebpf/https_guard.bpf.c is
# what it compiles.
#
# core/ follows the same ebpf/ + src/ split as every hook directory, so what
# a file *is* is visible from its path rather than from its extension. main.cpp
# stays at the top of core/ deliberately: it is the composition root, not part
# of either half.

add_library(programs_lib OBJECT
    core/src/BpfProgram.cpp
    core/src/HttpGuardProgram.cpp
    ssl_uprobe/src/SslUprobeProgram.cpp
    xdp_tls/src/XdpTlsProgram.cpp
    lsm_cert_guard/src/LsmCertGuardProgram.cpp
)

target_include_directories(programs_lib
    PUBLIC
    # core/ splits the same way the hooks do; main.cpp includes
    # HttpGuardProgram.hpp from core/src.
    ${CMAKE_CURRENT_SOURCE_DIR}/core/ebpf
    ${CMAKE_CURRENT_SOURCE_DIR}/core/src
    # Each hook splits into ebpf/ (the BPF program and its raw event struct)
    # and src/ (the BpfProgram subclass). Classification rules are not
    # here at all -- they all live in ../detections/, which keeps this tree
    # the only one that depends on libbpf.
    ${CMAKE_CURRENT_SOURCE_DIR}/ssl_uprobe/ebpf
    ${CMAKE_CURRENT_SOURCE_DIR}/ssl_uprobe/src
    ${CMAKE_CURRENT_SOURCE_DIR}/xdp_tls/ebpf
    ${CMAKE_CURRENT_SOURCE_DIR}/xdp_tls/src
    ${CMAKE_CURRENT_SOURCE_DIR}/lsm_cert_guard/ebpf
    ${CMAKE_CURRENT_SOURCE_DIR}/lsm_cert_guard/src
    ${CMAKE_CURRENT_SOURCE_DIR}/utils
    ${LIBBPF_INCLUDE_DIRS}
    ${nlohmann_json_INCLUDE_DIRS}
    ${BOOST_INCLUDE_DIR}
)

# The hooks are BpfPrograms whose default ring-buffer handler submits to
# DetectLoop, which lives in detections/. actions_lib comes in transitively through
# detections_lib, but is named explicitly since main.cpp also touches it.
target_link_libraries(programs_lib PUBLIC detections_lib actions_lib)
target_compile_definitions(programs_lib PUBLIC BOOST_ERROR_CODE_HEADER_ONLY)

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

    # The recipe's do_install() looks for this directly under ${B} (the
    # top-level build dir), so its final location can't follow
    # CMAKE_CURRENT_BINARY_DIR (which would put it under <build>/programs/
    # now that this CMakeLists.txt lives in a subdirectory).
    set(HTTPS_GUARD_BPF_OBJECT ${CMAKE_BINARY_DIR}/https_guard.bpf.o)
    set(HTTPS_GUARD_VMLINUX_HEADER ${CMAKE_CURRENT_BINARY_DIR}/vmlinux.h)

    add_custom_command(
        OUTPUT ${HTTPS_GUARD_VMLINUX_HEADER}
        COMMAND ${CMAKE_COMMAND} -E rm -f ${HTTPS_GUARD_VMLINUX_HEADER}
        COMMAND sh -c "${HTTPS_GUARD_BPFTOOL_EXECUTABLE} btf dump file '${HTTPS_GUARD_TARGET_VMLINUX}' format c > '${HTTPS_GUARD_VMLINUX_HEADER}'"
        DEPENDS ${HTTPS_GUARD_TARGET_VMLINUX}
        VERBATIM
        COMMENT "Generating target-kernel vmlinux.h for CO-RE"
    )

    # Userspace struct access (ssl_st, OpenSSL):
    #
    # We do NOT use CO-RE (bpf_core_read) for userspace structs because
    # CO-RE relocations require the target type to exist in the kernel's
    # BTF — but ssl_st is a userspace struct from libssl.so, not a kernel
    # struct.  Any CO-RE relocation for ssl_st fields would fail at BPF
    # program load time with "invalid CO-RE relocation".
    #
    # Instead we generate a header with the compile-time offset of
    # ssl_st.version using offsetof() from the actual OpenSSL header,
    # then use bpf_probe_read_user() with that offset to read the
    # TLS version directly from userspace memory.
    # ------------------------------------------------------------------
    # When cross-compiling (Yocto), gen_ssl_offset is built by the bitbake
    # recipe (https-guard-openbmc.bb) using the host compiler, and the
    # generated ssl_version_offset.h is passed in via HTTPS_GUARD_SSL_OFFSET_HEADER.
    # When not cross-compiling, we build it here with CMake.
    # ------------------------------------------------------------------
    set(HTTPS_GUARD_SSL_OFFSET_BINARY ${CMAKE_CURRENT_BINARY_DIR}/gen_ssl_offset)
    set(HTTPS_GUARD_SSL_OFFSET_HEADER ${CMAKE_CURRENT_BINARY_DIR}/ssl_version_offset.h)

    if(NOT CMAKE_CROSSCOMPILING)
        # Native build: compile gen_ssl_offset with the regular compiler
        add_custom_command(
            OUTPUT ${HTTPS_GUARD_SSL_OFFSET_BINARY}
            COMMAND ${CMAKE_C_COMPILER}
                    -o ${HTTPS_GUARD_SSL_OFFSET_BINARY}
                    ${CMAKE_SOURCE_DIR}/scripts/gen_ssl_offset.c
            DEPENDS ${CMAKE_SOURCE_DIR}/scripts/gen_ssl_offset.c
            VERBATIM
            COMMENT "Building ssl_st offset detection helper"
        )

        add_custom_command(
            OUTPUT ${HTTPS_GUARD_SSL_OFFSET_HEADER}
            COMMAND ${HTTPS_GUARD_SSL_OFFSET_BINARY} > ${HTTPS_GUARD_SSL_OFFSET_HEADER}
            DEPENDS ${HTTPS_GUARD_SSL_OFFSET_BINARY}
            VERBATIM
            COMMENT "Generating ssl_version_offset.h from actual OpenSSL headers"
        )
    else()
        # Cross-compiling: expect the recipe to provide ssl_version_offset.h
        # The bitbake recipe generates this file before CMake runs.
        if(NOT EXISTS "${HTTPS_GUARD_SSL_OFFSET_HEADER}")
            message(WARNING "ssl_version_offset.h not found. Cross-compilation requires the bitbake recipe to generate it.")
        endif()
    endif()

    set(HTTPS_GUARD_BPF_FLAGS
        -target bpf
        -D__TARGET_ARCH_${HTTPS_GUARD_BPF_TARGET_ARCH}
        -O2
        -g
        -I${CMAKE_CURRENT_BINARY_DIR}
        # hg_event_source.h lives with the event vocabulary in the
        # classification tree; the BPF side compiles it as C, so it needs the
        # path too.
        -I${CMAKE_SOURCE_DIR}/detections/core/event
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

    # core/ebpf/https_guard.bpf.c is a thin aggregator: it declares the
    # shared ring buffer map and #includes each hook's own <hook>.bpf.h
    # (relative includes, e.g. ../../ssl_uprobe/ebpf/ssl_uprobe.bpf.h) — so
    # compiling this one file pulls in every hook's BPF program into a
    # single object.
    add_custom_command(
        OUTPUT ${HTTPS_GUARD_BPF_OBJECT}
        COMMAND ${HTTPS_GUARD_BPF_CLANG_EXECUTABLE} ${HTTPS_GUARD_BPF_FLAGS}
                -c ${CMAKE_CURRENT_SOURCE_DIR}/core/ebpf/https_guard.bpf.c
                -o ${HTTPS_GUARD_BPF_OBJECT}
        DEPENDS
            ${HTTPS_GUARD_VMLINUX_HEADER}
            ${HTTPS_GUARD_SSL_OFFSET_HEADER}
            ${CMAKE_CURRENT_SOURCE_DIR}/core/ebpf/https_guard.bpf.c
            ${CMAKE_SOURCE_DIR}/detections/core/event/hg_event_source.h
            ${CMAKE_CURRENT_SOURCE_DIR}/ssl_uprobe/ebpf/ssl_uprobe.bpf.h
            ${CMAKE_CURRENT_SOURCE_DIR}/ssl_uprobe/ebpf/ssl_uprobe_event.h
            ${CMAKE_CURRENT_SOURCE_DIR}/xdp_tls/ebpf/xdp_tls.bpf.h
            ${CMAKE_CURRENT_SOURCE_DIR}/xdp_tls/ebpf/xdp_tls_event.h
            ${CMAKE_CURRENT_SOURCE_DIR}/xdp_tls/ebpf/conn_rate.bpf.h
            ${CMAKE_CURRENT_SOURCE_DIR}/lsm_cert_guard/ebpf/lsm_cert_guard.bpf.h
            ${CMAKE_CURRENT_SOURCE_DIR}/lsm_cert_guard/ebpf/lsm_cert_guard_event.h
            ${CMAKE_SOURCE_DIR}/actions/blocklist/blocklist.bpf.h
        VERBATIM
        COMMENT "Compiling HTTPS-Guard BPF object"
    )

    add_custom_target(https_guard_bpf ALL DEPENDS ${HTTPS_GUARD_BPF_OBJECT})
endif()

SUMMARY = "HTTPS-Guard OpenBMC event bridge service"
DESCRIPTION = "Bridges HTTPS-Guard anomaly signals to OpenBMC DBus Logging and Journal for Redfish EventService dispatch"
LICENSE = "MIT"
LIC_FILES_CHKSUM = "file://${COMMON_LICENSE_DIR}/MIT;md5=0835ade698e0bcf8506ecda2f7b4f302"


DEPENDS += "libbpf pkgconfig clang-native bpftool-native nlohmann-json boost openssl"
# googletest (meta-oe) is only needed to cross-compile the tests/ ptest binary;
# find_package(GTest) in tests/CMakeLists.txt picks it up from the sysroot this
# stages, so building with ptest enabled never needs network access to fetch it.
DEPENDS:append = " ${@bb.utils.contains('PTEST_ENABLED', '1', 'googletest', '', d)}"
inherit systemd
inherit cmake
inherit pkgconfig
inherit ptest

# =============================================================================
# PACKAGECONFIG: choose which systemd services are auto-enabled
#
#   "daemon" (default)      — enable the real eBPF-based https-guardd daemon.
#                             Disables the simulator.
#
#                             This is the default because the daemon is the
#                             point of the layer: shipping the simulator by
#                             default meant a first boot looked like it was
#                             working while detecting nothing real.
#
#                             It does raise the bar for a default build. The
#                             daemon needs the BPF object, so this flag also
#                             turns HTTPS_GUARD_BUILD_BPF ON (see the python()
#                             block below) -- which needs clang-native,
#                             bpftool-native, and a target kernel built with
#                             CONFIG_DEBUG_INFO_BTF so vmlinux carries BTF. All
#                             three are already in DEPENDS, but a machine whose
#                             kernel lacks BTF will now fail at configure time
#                             where the old default silently skipped BPF
#                             entirely. Use "simulation" there.
#
#                             At runtime it also wants CONFIG_BPF and
#                             CONFIG_UPROBE_EVENTS (plus CONFIG_NET_XDP for the
#                             XDP hook, and see recipes-kernel/linux/ for the
#                             fragment this layer adds). Missing XDP is
#                             non-fatal -- the daemon runs uprobe-only.
#
#   "simulation"            — enable the synthetic event generator instead, for
#                             a QEMU boot with no kernel eBPF/XDP support and no
#                             BPF toolchain. Disables the real daemon.
#
#   "both"                  — enable both daemon and simulator (for debugging,
#                             comparing real vs simulated events side by side).
#
# Event sink mode for the bridge service (controls how events reach
# EventService subscribers):
#
#   "dbus-only"     — emit via D-Bus xyz.openbmc_project.Logging.Create only.
#                     bmcweb's D-Bus monitor dispatches to subscribers.
#                     No /var/log/redfish filesystem write (avoids duplicates).
#
#   "journal-only"  — emit via systemd-cat + /var/log/redfish filesystem log.
#                     bmcweb's FilesystemLogWatcher dispatches to subscribers.
#
#   "event-both"    — emit to D-Bus AND systemd-cat.  Redfish EventService
#                     delivery is via D-Bus only (filesystem log skipped
#                     to avoid duplicate delivery).
# =============================================================================
PACKAGECONFIG ??= "daemon event-both"

PACKAGECONFIG[simulation] = ""
PACKAGECONFIG[daemon] = ""
PACKAGECONFIG[both] = ""

PACKAGECONFIG[dbus-only] = ""
PACKAGECONFIG[journal-only] = ""
PACKAGECONFIG[event-both] = ""

SRC_URI = " \
    file://service/ \
    file://https-guard.conf \
    file://CMakeLists.txt \
    file://scripts/ \
    file://programs/ \
    file://detections/ \
    file://actions/ \
    file://tests/ \
"

S = "${UNPACKDIR}"

RDEPENDS:${PN} += "bash systemd"

EXTRA_OECMAKE += " \
    -DHTTPS_GUARD_BUILD_BPF=${HTTPS_GUARD_BUILD_BPF} \
    -DHTTPS_GUARD_BPF_CLANG_EXECUTABLE=${STAGING_BINDIR_NATIVE}/clang \
    -DHTTPS_GUARD_BPFTOOL_EXECUTABLE=${STAGING_SBINDIR_NATIVE}/bpftool \
    -DHTTPS_GUARD_TARGET_VMLINUX=${WORKDIR}/target-kernel-vmlinux \
    -DHTTPS_GUARD_BPF_SOURCE_PREFIX_MAP=${S}=/usr/src/debug/${PN}/${PV} \
    -DHTTPS_GUARD_BPF_BINARY_PREFIX_MAP=${B}=/usr/src/debug/${PN}/${PV} \
    -DHTTPS_GUARD_BPF_SYSROOT_PREFIX_MAP=${RECIPE_SYSROOT}= \
    -DHTTPS_GUARD_BPF_SYSROOT_NATIVE_PREFIX_MAP=${RECIPE_SYSROOT_NATIVE}= \
    ${@bb.utils.contains('PTEST_ENABLED', '1', '-DHTTPS_GUARD_BUILD_TESTS=ON', '', d)} \
"

# Note: We intentionally do NOT set HTTPS_GUARD_BPF_SYSROOT_INCLUDE here.
# The gen_ssl_offset host tool needs HOST OpenSSL headers, not target sysroot headers.
# When cross-compiling, passing the target sysroot causes compilation failures
# because the sysroot contains target-specific glibc headers (e.g. gnu/stubs-soft.h).
# The BPF compilation (clang -target bpf) gets its includes from the BPF_SYSROOT
# directly via the BPF_SYSROOT_INCLUDE flag in CMakeLists.txt when needed.

do_configure[depends] += "virtual/kernel:do_compile"

# Build-time vmlinux.h flow:
#   1. virtual/kernel:do_compile produces the target kernel ELF at
#      ${STAGING_KERNEL_BUILDDIR}/vmlinux. The kernel must have
#      CONFIG_DEBUG_INFO_BTF=y, which stores kernel BTF in that ELF. The
#      layer's recipes-kernel/linux/bpf-kernel-config.cfg enables it.
#   2. This task symlinks that ELF to ${WORKDIR}/target-kernel-vmlinux.
#   3. programs/CMakeLists.txt invokes native bpftool with
#      "btf dump file ... format c" and writes ${B}/programs/vmlinux.h.
#   4. clang -target bpf includes that generated header when compiling the
#      single https_guard.bpf.o object.
# vmlinux.h is therefore a generated build artifact, not a source file or a
# target runtime package. The target still needs CONFIG_BPF and hook-specific
# runtime options, but it does not need bpftool installed on the BMC.
#
# Userspace struct access (ssl_st) does NOT use CO-RE — see the note in
# https_guard.bpf.c and CMakeLists.txt for the rationale.
do_configure:prepend() {
    if [ "${HTTPS_GUARD_BUILD_BPF}" != "ON" ]; then
        return 0
    fi

    target_vmlinux=""

    # The preferred source is the kernel artifact staged by virtual/kernel.
    if [ -f "${STAGING_KERNEL_BUILDDIR}/vmlinux" ]; then
        target_vmlinux="${STAGING_KERNEL_BUILDDIR}/vmlinux"
    else
        target_vmlinux=$(find ${TMPDIR}/work -path '*/linux-*/*/linux-*-build/vmlinux' | head -n 1)

        if [ -z "${target_vmlinux}" ]; then
            target_vmlinux=$(find ${TMPDIR}/work -path '*/linux-*/*/image/boot/vmlinux-*' | head -n 1)
        fi
    fi

    if [ -z "${target_vmlinux}" ] || [ ! -f "${target_vmlinux}" ]; then
        bbfatal "Unable to locate target kernel vmlinux for CO-RE generation"
    fi

    # CMake consumes this stable path; it is only an input alias, not a copy.
    ln -sf "${target_vmlinux}" "${WORKDIR}/target-kernel-vmlinux"

    # Pre-build gen_ssl_offset with the NATIVE (build machine) compiler.
    # This tool needs host OpenSSL headers, not target sysroot headers.
    # In Yocto cross-compilation:
    #   - HOST_PREFIX = target compiler prefix (e.g., arm-openbmc-linux-gnueabi-)
    #   - BUILD_PREFIX = build machine compiler prefix (e.g., x86_64-linux-)
    #   - BUILD_CC = full path to build machine compiler
    # We use BUILD_CC which is the standard Yocto variable for native compilation.
    GEN_SSL_OFFSET_CC="${BUILD_CC}"
    
    echo "Building gen_ssl_offset with native compiler: ${GEN_SSL_OFFSET_CC}"
    ${GEN_SSL_OFFSET_CC} -o ${WORKDIR}/gen_ssl_offset ${S}/scripts/gen_ssl_offset.c || \
        bbfatal "Failed to build gen_ssl_offset host tool"
    
    echo "gen_ssl_offset built successfully"
}

# Override do_compile to generate ssl_version_offset.h before CMake runs.
# Written under programs/ because that's where programs/CMakeLists.txt's
# BPF compile step (-I${CMAKE_CURRENT_BINARY_DIR}) now looks for it, since
# that CMakeLists.txt lives in the programs/ subdirectory and CMake mirrors
# the source tree into the binary tree.
do_compile:prepend() {
    if [ "${HTTPS_GUARD_BUILD_BPF}" != "ON" ]; then
        return 0
    fi

    # Generate ssl_version_offset.h using the pre-built host tool
    echo "Generating ssl_version_offset.h..."
    mkdir -p ${B}/programs
    ${WORKDIR}/gen_ssl_offset > ${B}/programs/ssl_version_offset.h || \
        bbfatal "Failed to generate ssl_version_offset.h"

    echo "ssl_version_offset.h generated successfully"
    cat ${B}/programs/ssl_version_offset.h
}

# ---------------------------------------------------------------------------
# Determine which services to enable based on PACKAGECONFIG
# ---------------------------------------------------------------------------
python() {
    pkgconfig = d.getVar('PACKAGECONFIG').split()

    # Base services: always present
    enabled_services = [
        'https-guard-event-bridge.service',
    ]

    if 'daemon' in pkgconfig or 'both' in pkgconfig:
        enabled_services.append('https-guard-daemon.service')
        d.setVar('HTTPS_GUARD_BUILD_BPF', 'ON')
    else:
        bb.note('HTTPS-Guard: daemon disabled by PACKAGECONFIG choice')
        d.setVar('HTTPS_GUARD_BUILD_BPF', 'OFF')

    # If simulation is set (or both), enable the generator.
    # Note: "daemon" alone disables the generator.
    if 'simulation' in pkgconfig or 'both' in pkgconfig:
        enabled_services.append('simulated-event-generator.service')
    else:
        bb.note('HTTPS-Guard: simulation disabled by PACKAGECONFIG choice')

    d.setVar('SYSTEMD_SERVICE:' + d.getVar('PN'), ' '.join(enabled_services))

    # Compute event sink mode from PACKAGECONFIG flags.
    # This is used during do_install to stamp the config file.
    if 'dbus-only' in pkgconfig:
        d.setVar('HTTPS_GUARD_EVENT_MODE', 'dbus')
    elif 'journal-only' in pkgconfig:
        d.setVar('HTTPS_GUARD_EVENT_MODE', 'journal')
    else:
        d.setVar('HTTPS_GUARD_EVENT_MODE', 'both')
}

SYSTEMD_AUTO_ENABLE:${PN} = "enable"

do_install() {
    install -d ${D}${sbindir}
    install -m 0755 ${S}/service/https-guard-event-bridge.sh   ${D}${sbindir}/https-guard-event-bridge
    install -m 0755 ${S}/service/simulated-event-generator.sh ${D}${sbindir}/simulated-event-generator
    install -m 0755 ${S}/service/https-guard-daemon.sh          ${D}${sbindir}/https-guard-daemon

    # install compiled daemon if present
    if [ -x "${B}/https_guardd" ]; then
        install -m 0755 ${B}/https_guardd ${D}${sbindir}/https-guardd
    fi

    if [ -x "${B}/detect_runner" ]; then
        install -m 0755 ${B}/detect_runner ${D}${sbindir}/detect_runner
    fi

    if [ -x "${B}/action_runner" ]; then
        install -m 0755 ${B}/action_runner ${D}${sbindir}/action_runner
    fi

    # install BPF object if built
    if [ -f "${B}/https_guard.bpf.o" ]; then
        install -d ${D}${datadir}/https-guard
        install -m 0644 ${B}/https_guard.bpf.o ${D}${datadir}/https-guard/https_guard.bpf.o
    fi

    install -d ${D}${systemd_system_unitdir}
    install -m 0644 ${S}/service/https-guard-event-bridge.service   ${D}${systemd_system_unitdir}/
    install -m 0644 ${S}/service/simulated-event-generator.service ${D}${systemd_system_unitdir}/
    install -m 0644 ${S}/service/https-guard-daemon.service          ${D}${systemd_system_unitdir}/

    # -----------------------------------------------------------------------
    # Install config file with event mode stamped from PACKAGECONFIG.
    # HTTPS_GUARD_EVENT_MODE is computed in the python() anonymous function
    # above: "dbus" for dbus-only, "journal" for journal-only, "both" otherwise.
    # -----------------------------------------------------------------------
    install -d ${D}${sysconfdir}/default
    sed -e "s/@@EVENT_MODE@@/${HTTPS_GUARD_EVENT_MODE}/g" \
        ${S}/https-guard.conf > ${D}${sysconfdir}/default/https-guard
}

# Only runs when PTEST_ENABLED (ptest.bbclass deletes the task otherwise), at
# which point EXTRA_OECMAKE above already forced HTTPS_GUARD_BUILD_TESTS=ON,
# so ${B}/tests/https_guard_tests (see CLAUDE.md's note on cmake output paths
# mirroring source subdirectories) exists to install here.
do_install_ptest() {
    install -d ${D}${PTEST_PATH}
    install -m 0755 ${B}/tests/https_guard_tests ${D}${PTEST_PATH}/https_guard_tests
    install -m 0755 ${S}/tests/run-ptest ${D}${PTEST_PATH}/run-ptest
}

FILES:${PN} += " \
    ${sbindir}/action_runner \
    ${sbindir}/detect_runner \
    ${sbindir}/https-guardd \
    ${sbindir}/https-guard-event-bridge \
    ${sbindir}/simulated-event-generator \
    ${sbindir}/https-guard-daemon \
    ${datadir}/https-guard/https_guard.bpf.o \
    ${systemd_system_unitdir}/https-guard-event-bridge.service \
    ${systemd_system_unitdir}/simulated-event-generator.service \
    ${systemd_system_unitdir}/https-guard-daemon.service \
    ${sysconfdir}/default/https-guard \
"

SUMMARY = "HTTPS-Guard OpenBMC event bridge service"
DESCRIPTION = "Bridges HTTPS-Guard anomaly signals to OpenBMC DBus Logging and Journal for Redfish EventService dispatch"
LICENSE = "MIT"
LIC_FILES_CHKSUM = "file://${COMMON_LICENSE_DIR}/MIT;md5=0835ade698e0bcf8506ecda2f7b4f302"


DEPENDS += "libbpf pkgconfig clang-native bpftool-native nlohmann-json boost openssl"
inherit systemd
inherit cmake
inherit pkgconfig

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
    file://service/https-guard-event-bridge.sh \
    file://service/https-guard-event-bridge.service \
    file://service/https-guard-daemon.sh \
    file://service/https-guard-daemon.service \
    file://service/simulated-event-generator.service \
    file://service/simulated-event-generator.sh \
    file://https-guard.conf \
    file://CMakeLists.txt \
    file://programs/DESIGN.md \
    file://detections/DESIGN.md \
    file://actions/DESIGN.md \
    file://actions/log/DESIGN.md \
    file://actions/blocklist/DESIGN.md \
    file://actions/tcp/DESIGN.md \
    file://scripts/gen_ssl_offset.c \
    file://programs/CMakeLists.txt \
    file://programs/core/ebpf/https_guard.bpf.c \
    file://programs/core/main.cpp \
    file://programs/core/src/HttpGuardProgram.hpp \
    file://programs/core/src/HttpGuardProgram.cpp \
    file://programs/core/src/BpfProgram.hpp \
    file://programs/core/src/BpfProgram.cpp \
    file://programs/ssl_uprobe/src/proc_peer_resolver.hpp \
    file://programs/ssl_uprobe/ebpf/ssl_uprobe.bpf.h \
    file://programs/ssl_uprobe/ebpf/ssl_uprobe_event.h \
    file://programs/ssl_uprobe/src/SslUprobeProgram.hpp \
    file://programs/ssl_uprobe/src/SslUprobeProgram.cpp \
    file://programs/xdp_tls/ebpf/xdp_tls.bpf.h \
    file://programs/xdp_tls/ebpf/xdp_tls_event.h \
    file://programs/xdp_tls/ebpf/parse_client_hello.h \
    file://programs/xdp_tls/ebpf/conn_rate.bpf.h \
    file://programs/xdp_tls/src/XdpTlsProgram.hpp \
    file://programs/xdp_tls/src/XdpTlsProgram.cpp \
    file://programs/lsm_cert_guard/ebpf/lsm_cert_guard.bpf.h \
    file://programs/lsm_cert_guard/ebpf/lsm_cert_guard_event.h \
    file://programs/lsm_cert_guard/src/LsmCertGuardProgram.hpp \
    file://programs/lsm_cert_guard/src/LsmCertGuardProgram.cpp \
    file://programs/utils/bounded_string.hpp \
    file://detections/CMakeLists.txt \
    file://detections/core/event/hg_event_source.h \
    file://detections/core/engine/DetectLoop.hpp \
    file://detections/core/engine/DetectLoop.cpp \
    file://detections/core/main.cpp \
    file://detections/core/event/IPeerResolver.hpp \
    file://detections/core/contract/Verdict.hpp \
    file://detections/core/contract/IDetection.hpp \
    file://detections/core/event/event_meta_from.hpp \
    file://detections/core/contract/detection_traits.hpp \
    file://detections/traffic_observed/TrafficObservedDetection.hpp \
    file://detections/traffic_observed/DESIGN.md \
    file://detections/tls_version/TlsVersionEvent.hpp \
    file://detections/tls_version/TlsVersionDetection.hpp \
    file://detections/payload_anomaly/PayloadEvent.hpp \
    file://detections/payload_anomaly/PayloadAnomalyDetection.hpp \
    file://detections/cipher_suite/CipherSuiteEvent.hpp \
    file://detections/cipher_suite/CipherSuiteDetection.hpp \
    file://detections/sni/SniEvent.hpp \
    file://detections/sni/SniDetection.hpp \
    file://detections/cert_access/CertAccessEvent.hpp \
    file://detections/cert_access/CertAccessDetection.hpp \
    file://detections/tls_version/DESIGN.md \
    file://detections/payload_anomaly/DESIGN.md \
    file://detections/cipher_suite/DESIGN.md \
    file://detections/sni/DESIGN.md \
    file://detections/cert_access/DESIGN.md \
    file://detections/rate_sweep/DESIGN.md \
    file://detections/core/event/event_meta.hpp \
    file://detections/core/engine/dispatch.hpp \
    file://detections/core/engine/dispatch.cpp \
    file://detections/tls_version/TlsVersionDetector.hpp \
    file://detections/core/event/tls_version.hpp \
    file://detections/payload_anomaly/PayloadAnomalyDetector.hpp \
    file://detections/cert_access/CertAccessDetector.hpp \
    file://detections/rate_sweep/ConnRateEvent.hpp \
    file://detections/rate_sweep/ConnRateDetector.hpp \
    file://detections/core/sweep/ConnRateSweeper.hpp \
    file://detections/core/sweep/ConnRateSweeper.cpp \
    file://detections/rate_sweep/SlowlorisEvent.hpp \
    file://detections/rate_sweep/SlowlorisDetector.hpp \
    file://detections/rate_sweep/RenegotiationEvent.hpp \
    file://detections/rate_sweep/RenegotiationDetector.hpp \
    file://detections/cipher_suite/CipherSuiteDetector.hpp \
    file://detections/cipher_suite/weak_cipher_suites.hpp \
    file://detections/sni/SniDetector.hpp \
    file://actions/CMakeLists.txt \
    file://actions/core/main.cpp \
    file://actions/core/ActionLoop.hpp \
    file://actions/core/ActionLoop.cpp \
    file://actions/log/async_mutex.hpp \
    file://actions/log/LogAction.hpp \
    file://actions/log/LogAction.cpp \
    file://actions/log/redfish_event_message.hpp \
    file://actions/blocklist/Blocklist.hpp \
    file://actions/blocklist/Blocklist.cpp \
    file://actions/blocklist/blocklist.bpf.h \
    file://actions/blocklist/BlocklistAction.hpp \
    file://actions/blocklist/BlocklistAction.cpp \
    file://actions/tcp/TcpDestroyer.hpp \
    file://actions/tcp/TcpDestroyer.cpp \
    file://actions/tcp/BlockTcpAction.hpp \
    file://actions/tcp/BlockTcpAction.cpp \
    file://tests/CMakeLists.txt \
    file://tests/test_detectors.cpp \
    file://tests/test_uprobe_parsing.cpp \
    file://tests/test_client_hello_parsing.cpp \
    file://tests/detectloop/detectloop_harness.cpp \
    file://tests/detectloop/README.md \
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
"

# Note: We intentionally do NOT set HTTPS_GUARD_BPF_SYSROOT_INCLUDE here.
# The gen_ssl_offset host tool needs HOST OpenSSL headers, not target sysroot headers.
# When cross-compiling, passing the target sysroot causes compilation failures
# because the sysroot contains target-specific glibc headers (e.g. gnu/stubs-soft.h).
# The BPF compilation (clang -target bpf) gets its includes from the BPF_SYSROOT
# directly via the BPF_SYSROOT_INCLUDE flag in CMakeLists.txt when needed.

do_configure[depends] += "virtual/kernel:do_compile"

# Userspace struct access (ssl_st) does NOT use CO-RE — see the note in
# https_guard.bpf.c and CMakeLists.txt for the rationale.
do_configure:prepend() {
    if [ "${HTTPS_GUARD_BUILD_BPF}" != "ON" ]; then
        return 0
    fi

    target_vmlinux=""

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

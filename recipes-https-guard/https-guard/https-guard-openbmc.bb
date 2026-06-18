SUMMARY = "HTTPS-Guard OpenBMC event bridge service"
DESCRIPTION = "Bridges HTTPS-Guard anomaly signals to OpenBMC DBus Logging and Journal for Redfish EventService dispatch"
LICENSE = "MIT"
LIC_FILES_CHKSUM = "file://${COMMON_LICENSE_DIR}/MIT;md5=0835ade698e0bcf8506ecda2f7b4f302"


DEPENDS += "libbpf pkgconfig clang-native bpftool-native nlohmann-json boost"
inherit systemd
inherit cmake
inherit pkgconfig

# =============================================================================
# PACKAGECONFIG: choose which systemd services are auto-enabled
#
#   "simulation" (default)  — enable the synthetic event generator for QEMU
#                             testing without real eBPF hardware support.
#                             Disables the real daemon.
#
#   "daemon"                — enable the real eBPF-based https-guardd daemon.
#                             Requires a kernel with eBPF/XDP and a TAP/bridge
#                             network on the host. Disables the simulator.
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
PACKAGECONFIG ??= "simulation event-both"

PACKAGECONFIG[simulation] = ""
PACKAGECONFIG[daemon] = ""
PACKAGECONFIG[both] = ""
PACKAGECONFIG[dbus-only] = ""
PACKAGECONFIG[journal-only] = ""
PACKAGECONFIG[event-both] = ""

SRC_URI = " \
    file://https-guard-event-bridge.sh \
    file://https-guard-event-bridge.service \
    file://https-guard-daemon.sh \
    file://https-guard-daemon.service \
    file://simulated-event-generator.service \
    file://simulated-event-generator.sh \
    file://https-guard.conf \
    file://CMakeLists.txt \
    file://https_guard/events.h \
    file://https_guard/https_guard.bpf.c \
    file://https_guard/redfish_event_message.hpp \
    file://https_guard/pattern_detector.hpp \
    file://https_guard/tls_version.hpp \
    file://https_guard/main.cpp \
    file://https_guard/https_guard_program.hpp \
    file://https_guard/https_guard_program.cpp \
    file://ebpf/bpf_program.hpp \
    file://ebpf/bpf_program.cpp \
    file://actions/core/main.cpp \
    file://actions/core/ActionLoop.hpp \
    file://actions/core/ActionLoop.cpp \
    file://actions/log/async_mutex.hpp \
    file://actions/log/LogAction.hpp \
    file://actions/log/LogAction.cpp \
    file://actions/blocklist/Blocklist.hpp \
    file://actions/blocklist/Blocklist.cpp \
    file://actions/blocklist/blocklist.bpf.h \
    file://actions/blocklist/BlocklistAction.hpp \
    file://actions/blocklist/BlocklistAction.cpp \
    file://actions/tcp/TcpDestroyer.hpp \
    file://actions/tcp/TcpDestroyer.cpp \
    file://actions/tcp/BlockTcpAction.hpp \
    file://actions/tcp/BlockTcpAction.cpp \
"

S = "${UNPACKDIR}"

RDEPENDS:${PN} += "bash systemd"

EXTRA_OECMAKE += " \
    -DHTTPS_GUARD_BUILD_BPF=${HTTPS_GUARD_BUILD_BPF} \
    -DHTTPS_GUARD_BPF_CLANG_EXECUTABLE=${STAGING_BINDIR_NATIVE}/clang \
    -DHTTPS_GUARD_BPFTOOL_EXECUTABLE=${STAGING_SBINDIR_NATIVE}/bpftool \
    -DHTTPS_GUARD_TARGET_VMLINUX=${WORKDIR}/target-kernel-vmlinux \
    -DHTTPS_GUARD_BPF_SYSROOT_INCLUDE=${RECIPE_SYSROOT}/usr/include \
    -DHTTPS_GUARD_BPF_SOURCE_PREFIX_MAP=${S}=/usr/src/debug/${PN}/${PV} \
    -DHTTPS_GUARD_BPF_BINARY_PREFIX_MAP=${B}=/usr/src/debug/${PN}/${PV} \
    -DHTTPS_GUARD_BPF_SYSROOT_PREFIX_MAP=${RECIPE_SYSROOT}= \
    -DHTTPS_GUARD_BPF_SYSROOT_NATIVE_PREFIX_MAP=${RECIPE_SYSROOT_NATIVE}= \
"

do_configure[depends] += "virtual/kernel:do_compile"

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
    install -m 0755 ${S}/https-guard-event-bridge.sh   ${D}${sbindir}/https-guard-event-bridge
    install -m 0755 ${S}/simulated-event-generator.sh ${D}${sbindir}/simulated-event-generator
    install -m 0755 ${S}/https-guard-daemon.sh          ${D}${sbindir}/https-guard-daemon

    # install compiled daemon if present
    if [ -x "${B}/https_guardd" ]; then
        install -m 0755 ${B}/https_guardd ${D}${sbindir}/https-guardd
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
    install -m 0644 ${S}/https-guard-event-bridge.service   ${D}${systemd_system_unitdir}/
    install -m 0644 ${S}/simulated-event-generator.service ${D}${systemd_system_unitdir}/
    install -m 0644 ${S}/https-guard-daemon.service          ${D}${systemd_system_unitdir}/

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

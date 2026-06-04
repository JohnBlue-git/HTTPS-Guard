SUMMARY = "HTTPS-Guard OpenBMC event bridge service"
DESCRIPTION = "Bridges HTTPS-Guard anomaly signals to OpenBMC DBus Logging and Journal for Redfish EventService dispatch"
LICENSE = "MIT"
LIC_FILES_CHKSUM = "file://${COMMON_LICENSE_DIR}/MIT;md5=0835ade698e0bcf8506ecda2f7b4f302"


DEPENDS += "libbpf pkgconfig clang-native"
inherit systemd
inherit cmake
inherit pkgconfig

SRC_URI = " \
    file://https-guard-event-bridge.sh \
    file://https-guard-event-bridge.service \
    file://https-guard-event-generator.service \
    file://https-guard-event-generator.sh \
    file://https-guard.conf \
    file://CMakeLists.txt \
    file://src/main.cpp \
    file://src/pattern_detector.cpp \
    file://src/redfish_formatter.cpp \
    file://src/pattern_detector.hpp \
    file://src/redfish_formatter.hpp \
    file://include/https_guard/events.h \
    file://ebpf/https_guard.bpf.c \
"

S = "${UNPACKDIR}"

RDEPENDS:${PN} += "bash systemd"

SYSTEMD_SERVICE:${PN} = "https-guard-event-bridge.service https-guard-event-generator.service"
SYSTEMD_AUTO_ENABLE:${PN} = "enable"

do_compile:append() {
    # try to build eBPF object with clang (clang-native is a DEPENDS)
    if command -v clang >/dev/null 2>&1; then
        clang -target bpf -D__TARGET_ARCH_x86 -O2 -g -I${S}/include -I/usr/include -c ${S}/ebpf/https_guard.bpf.c -o ${B}/https_guard.bpf.o || true
    fi
}

do_install() {
    install -d ${D}${sbindir}
    install -m 0755 ${S}/https-guard-event-bridge.sh ${D}${sbindir}/https-guard-event-bridge
    install -m 0755 ${S}/https-guard-event-generator.sh ${D}${sbindir}/https-guard-event-generator

    # install compiled daemon if present
    if [ -x "${B}/https_guardd" ]; then
        install -m 0755 ${B}/https_guardd ${D}${sbindir}/https-guardd
    fi

    # install BPF object if built
    if [ -f "${B}/https_guard.bpf.o" ]; then
        install -d ${D}${datadir}/https-guard
        install -m 0644 ${B}/https_guard.bpf.o ${D}${datadir}/https-guard/https_guard.bpf.o
    fi

    install -d ${D}${systemd_system_unitdir}
    install -m 0644 ${S}/https-guard-event-bridge.service ${D}${systemd_system_unitdir}/
    install -m 0644 ${S}/https-guard-event-generator.service ${D}${systemd_system_unitdir}/

    install -d ${D}${sysconfdir}/default
    install -m 0644 ${S}/https-guard.conf ${D}${sysconfdir}/default/https-guard
}

FILES:${PN} += " \
    ${sbindir}/https-guard-event-bridge \
    ${sbindir}/https-guard-event-generator \
    ${systemd_system_unitdir}/https-guard-event-bridge.service \
    ${systemd_system_unitdir}/https-guard-event-generator.service \
    ${sysconfdir}/default/https-guard \
"

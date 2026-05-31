SUMMARY = "HTTPS-Guard OpenBMC event bridge service"
DESCRIPTION = "Bridges HTTPS-Guard anomaly signals to OpenBMC DBus Logging and Journal for Redfish EventService dispatch"
LICENSE = "MIT"
LIC_FILES_CHKSUM = "file://${COMMON_LICENSE_DIR}/MIT;md5=0835c914d5b42b5b9f5d7f3f7a9f0f4f"


DEPENDS += "libbpf pkgconfig clang-native"
inherit systemd
inherit cmake

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

S = "${WORKDIR}"

RDEPENDS:${PN} += "bash systemd"

SYSTEMD_SERVICE:${PN} = "https-guard-event-bridge.service https-guard-event-generator.service"
SYSTEMD_AUTO_ENABLE:${PN} = "enable"

do_compile_append() {
    mkdir -p ${WORKDIR}/build
    # try to build eBPF object with clang (clang-native is a DEPENDS)
    if command -v clang >/dev/null 2>&1; then
        clang -target bpf -D__TARGET_ARCH_x86 -O2 -g -I${WORKDIR}/include -I/usr/include -c ${WORKDIR}/ebpf/https_guard.bpf.c -o ${WORKDIR}/build/https_guard.bpf.o || true
    fi
}

do_install() {
    install -d ${D}${sbindir}
    install -m 0755 ${WORKDIR}/https-guard-event-bridge.sh ${D}${sbindir}/https-guard-event-bridge
    install -m 0755 ${WORKDIR}/https-guard-event-generator.sh ${D}${sbindir}/https-guard-event-generator

    # install compiled daemon if present
    if [ -x "${WORKDIR}/build/https_guardd" ]; then
        install -m 0755 ${WORKDIR}/build/https_guardd ${D}${sbindir}/https-guardd
    fi

    # install BPF object if built
    install -d ${D}${datadir}/https-guard || true
    if [ -f "${WORKDIR}/build/https_guard.bpf.o" ]; then
        install -m 0644 ${WORKDIR}/build/https_guard.bpf.o ${D}${datadir}/https-guard/https_guard.bpf.o
    fi

    install -d ${D}${systemd_system_unitdir}
    install -m 0644 ${WORKDIR}/https-guard-event-bridge.service ${D}${systemd_system_unitdir}/
    install -m 0644 ${WORKDIR}/https-guard-event-generator.service ${D}${systemd_system_unitdir}/

    install -d ${D}${sysconfdir}/default
    install -m 0644 ${WORKDIR}/https-guard.conf ${D}${sysconfdir}/default/https-guard
}

FILES:${PN} += " \
    ${sbindir}/https-guard-event-bridge \
    ${sbindir}/https-guard-event-generator \
    ${systemd_system_unitdir}/https-guard-event-bridge.service \
    ${systemd_system_unitdir}/https-guard-event-generator.service \
    ${sysconfdir}/default/https-guard \
"

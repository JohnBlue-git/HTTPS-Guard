SUMMARY = "HTTPS-Guard OpenBMC event bridge service"
DESCRIPTION = "Bridges HTTPS-Guard anomaly signals to OpenBMC DBus Logging and Journal for Redfish EventService dispatch"
LICENSE = "MIT"
LIC_FILES_CHKSUM = "file://${COMMON_LICENSE_DIR}/MIT;md5=0835c914d5b42b5b9f5d7f3f7a9f0f4f"

inherit systemd

SRC_URI = " \
    file://https-guard-event-bridge.sh \
    file://https-guard-event-bridge.service \
    file://https-guard-event-generator.service \
    file://https-guard-event-generator.sh \
    file://https-guard.conf \
"

S = "${WORKDIR}"

RDEPENDS:${PN} += "bash systemd"

SYSTEMD_SERVICE:${PN} = "https-guard-event-bridge.service https-guard-event-generator.service"
SYSTEMD_AUTO_ENABLE:${PN} = "enable"

do_install() {
    install -d ${D}${sbindir}
    install -m 0755 ${WORKDIR}/https-guard-event-bridge.sh ${D}${sbindir}/https-guard-event-bridge
    install -m 0755 ${WORKDIR}/https-guard-event-generator.sh ${D}${sbindir}/https-guard-event-generator

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

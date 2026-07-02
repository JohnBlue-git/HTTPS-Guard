# Keep EventService enabled and ensure bmcweb is present in image composition.
# Most OpenBMC defaults already ship EventService; this append is intentionally minimal.
RDEPENDS:${PN}:append = " phosphor-logging"
EXTRA_OEMESON:append = " -Dbmcweb-logging=debug"

# Compiles in a real OemSecurityEvent message registry (registries_selector.hpp
# + a new registries/oem_security_event_message_registry.hpp) so bmcweb's
# FilesystemLogWatcher can resolve HTTPS-Guard MessageIds to their real
# severities/text instead of the borrowed OpenBMC.0.5.GeneralFirmwareSecurityViolation
# (always Critical) that https-guard-event-bridge.sh used previously.
FILESEXTRAPATHS:prepend := "${THISDIR}/files:"
SRC_URI:append = " \
    file://OemSecurityEvent.1.0.0.json \
    file://0001-add-oem-security-event-message-registry.patch \
"

# Install the OEM Redfish Message Registry for HTTPS-Guard events
# so bmcweb can serve it via /redfish/v1/Registries/.
do_install:append() {
    install -d ${D}${datadir}/www/redfish/v1/Registries/OemSecurityEvent.1.0.0/
    install -m 0644 ${WORKDIR}/sources/OemSecurityEvent.1.0.0.json ${D}${datadir}/www/redfish/v1/Registries/OemSecurityEvent.1.0.0/
}

FILES:${PN}:append = " \
    ${datadir}/www/redfish/v1/Registries/OemSecurityEvent.1.0.0/OemSecurityEvent.1.0.0.json \
"

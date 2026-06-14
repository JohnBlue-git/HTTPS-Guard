# Keep EventService enabled and ensure bmcweb is present in image composition.
# Most OpenBMC defaults already ship EventService; this append is intentionally minimal.
RDEPENDS:${PN}:append = " phosphor-logging"
EXTRA_OEMESON:append = " -Dbmcweb-logging=debug"

# Fix: getUniqueEntryID() was passing the full log line to dateStringToEpoch(),
# which rejects strings with trailing content. Extract the timestamp token first.
FILESEXTRAPATHS:prepend := "${THISDIR}/files:"
SRC_URI:append = " \
    file://0001-fix-event-log-unique-entry-id-parse-timestamp-only.patch \
    file://OemSecurityEvent.1.0.0.json \
"

# Install the OEM Redfish Message Registry for HTTPS-Guard events
# so bmcweb can serve it via /redfish/v1/Registries/.
do_install:append() {
    install -d ${D}${datadir}/www/redfish/v1/Registries/OemSecurityEvent.1.0.0/
    install -m 0644 ${S}/OemSecurityEvent.1.0.0.json \
        ${D}${datadir}/www/redfish/v1/Registries/OemSecurityEvent.1.0.0/
}

FILES:${PN}:append = " \
    ${datadir}/www/redfish/v1/Registries/OemSecurityEvent.1.0.0/OemSecurityEvent.1.0.0.json \
"

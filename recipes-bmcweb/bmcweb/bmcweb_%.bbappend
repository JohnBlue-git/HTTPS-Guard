# Keep EventService enabled and ensure bmcweb is present in image composition.
# Most OpenBMC defaults already ship EventService; this append is intentionally minimal.
RDEPENDS:${PN}:append = " phosphor-logging"

# Classify layer: pure, synchronous detection rules behind the IDetector
# interface. Header-only today (no .cpp — every rule is small enough to
# stay inline, matching the project's existing convention for small
# value-type classes), so this is an INTERFACE library: nothing to
# compile, just include paths to propagate to whatever links it.

add_library(detectors_lib INTERFACE)

target_include_directories(detectors_lib
    INTERFACE
    ${CMAKE_CURRENT_SOURCE_DIR}/core
    ${CMAKE_CURRENT_SOURCE_DIR}/tls_version
    ${CMAKE_CURRENT_SOURCE_DIR}/payload_anomaly
    ${CMAKE_CURRENT_SOURCE_DIR}/cert_access
)

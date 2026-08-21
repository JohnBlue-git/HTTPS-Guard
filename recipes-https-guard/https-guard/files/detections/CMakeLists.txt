# Classify layer: the detection rules behind IDetector, the shared pipeline
# vocabulary they and the hooks both speak (hg_event, Verdict,
# hg_event_source, IHookModule, IPeerResolver), and DetectLoop -- the engine
# that drives parse -> classify -> dispatch on its own Boost.Asio loop.
#
# DetectLoop lives here rather than under programs/ because it belongs to the
# detection concern, not to any hook: it holds the detector registry, decides
# verdicts, and hands the results to actions/. The hooks are plugins it calls
# through IHookModule, which is why that interface lives here too.
#
# DEPENDENCY DIRECTION (keep it this way):
#
#     actions_lib  <--  detections_lib  <--  programs_lib
#
# detections_lib links actions_lib because DetectLoop dispatches actions.
# programs_lib links detections_lib because the hooks implement IHookModule
# and the orchestrator feeds DetectLoop. Nothing points back the other way.
#
# Note IHookModule.hpp forward-declares bpf_object/bpf_link instead of
# including <bpf/libbpf.h>, deliberately: this library must stay free of
# libbpf so classification can be built and unit-tested without a kernel.

add_library(detections_lib OBJECT
    core/DetectLoop.cpp
    conn_rate/ConnRateSweeper.cpp
)

target_include_directories(detections_lib
    PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/core
    # Every classification rule lives here, one directory per rule family,
    # whether or not a given rule happens to apply to only one hook today.
    # Placement does not depend on which hook feeds it -- see CLAUDE.md.
    ${CMAKE_CURRENT_SOURCE_DIR}/tls_version
    ${CMAKE_CURRENT_SOURCE_DIR}/payload_anomaly
    ${CMAKE_CURRENT_SOURCE_DIR}/cipher_suite
    ${CMAKE_CURRENT_SOURCE_DIR}/sni
    ${CMAKE_CURRENT_SOURCE_DIR}/cert_access
    ${CMAKE_CURRENT_SOURCE_DIR}/conn_rate
    ${CMAKE_CURRENT_SOURCE_DIR}/slowloris
    ${CMAKE_CURRENT_SOURCE_DIR}/renegotiation
    # ConnRateSweeper reads the BPF counter map directly, and the map's
    # layout header lives with the BPF program that maintains it.
    ${CMAKE_SOURCE_DIR}/programs/xdp_tls/ebpf
    ${LIBBPF_INCLUDE_DIRS}
    ${nlohmann_json_INCLUDE_DIRS}
    ${BOOST_INCLUDE_DIR}
)

# DetectLoop.cpp constructs LogAction/BlockTcpAction/BlocklistAddAction and
# formats Redfish messages, so it needs actions/'s headers and objects.
target_link_libraries(detections_lib PUBLIC actions_lib)
target_compile_definitions(detections_lib PUBLIC BOOST_ERROR_CODE_HEADER_ONLY)

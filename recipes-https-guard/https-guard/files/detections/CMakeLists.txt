# Classify layer: the detection rules behind IDetector, the shared pipeline
# vocabulary they and the hooks both speak (hg_event, Verdict,
# hg_event_source, IPeerResolver), and DetectLoop -- the engine that drives
# parse -> classify -> dispatch on its own Boost.Asio loop.
#
# DetectLoop lives here rather than under programs/ because it belongs to the
# detection concern, not to any hook: it holds the detector registry, decides
# verdicts, and hands the results to actions/. It never names a hook type --
# the composition root hands it parsing as a plain callable, which is what
# keeps this library free of libbpf.
#
# DEPENDENCY DIRECTION (keep it this way):
#
#     actions_lib  <--  detections_lib  <--  programs_lib
#
# detections_lib links actions_lib because DetectLoop dispatches actions.
# programs_lib links detections_lib because a hook's default ring-buffer
# handler submits to DetectLoop. Nothing points back the other way.
#
# This library must stay free of libbpf so classification can be built and
# unit-tested without a kernel. Nothing here may include <bpf/libbpf.h> or name
# a type from programs/ except the plain-C raw event structs (the wire format).
# IDetection exists precisely so it doesn't have to.

add_library(detections_lib OBJECT
    core/engine/DetectLoop.cpp
    core/engine/dispatch.cpp
    conn_rate/ConnRateSweeper.cpp
    conn_rate/rate_sources.cpp
)

target_include_directories(detections_lib
    PUBLIC
    # core/ is grouped by duty. Three directories, and the split is the point:
    #   contract/  what a detection must provide  (IDetection, Verdict, traits)
    #   event/     the vocabulary they all speak  (EventMeta, the envelope parse)
    #   engine/    what drives the pipeline       (DetectLoop, dispatch)
    # Includes stay unqualified, matching the rest of the tree, so moving a file
    # between them does not touch a single #include.
    ${CMAKE_CURRENT_SOURCE_DIR}/core/contract
    ${CMAKE_CURRENT_SOURCE_DIR}/core/event
    ${CMAKE_CURRENT_SOURCE_DIR}/core/engine
    ${CMAKE_CURRENT_SOURCE_DIR}/traffic_observed
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
    # The raw <hook>_event.h structs are the BPF<->userspace WIRE FORMAT, not
    # code: plain C, no libbpf, compiled by both sides. Parsing them is part of
    # deciding what an event means, so it lives here -- which means these paths
    # do too. ConnRateSweeper reads the counter map's layout header the same way.
    ${CMAKE_SOURCE_DIR}/programs/ssl_uprobe/ebpf
    ${CMAKE_SOURCE_DIR}/programs/xdp_tls/ebpf
    ${CMAKE_SOURCE_DIR}/programs/lsm_cert_guard/ebpf
    # boundedString(): turning a fixed-size char[] into a std::string.
    ${CMAKE_SOURCE_DIR}/programs/utils
    ${LIBBPF_INCLUDE_DIRS}
    ${nlohmann_json_INCLUDE_DIRS}
    ${BOOST_INCLUDE_DIR}
)

# DetectLoop.cpp constructs LogAction/BlockTcpAction/BlocklistAddAction and
# formats Redfish messages, so it needs actions/'s headers and objects.
target_link_libraries(detections_lib PUBLIC actions_lib)
target_compile_definitions(detections_lib PUBLIC BOOST_ERROR_CODE_HEADER_ONLY)

# detect_runner is the counterpart to actions/'s action_runner: a manual
# smoke-test binary that starts the detection pipeline on its own, with no
# kernel, BPF object or root. Same output-directory override for the same
# reason -- see files/CLAUDE.md's note about a target's default output path
# following its source subdirectory rather than the build root.
add_executable(detect_runner core/main.cpp)
target_link_libraries(detect_runner PRIVATE detections_lib actions_lib)
set_target_properties(detect_runner PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})

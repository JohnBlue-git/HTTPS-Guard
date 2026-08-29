# Dispatch layer: single-responsibility, asynchronously-dispatched
# enforcement actions (log, blocklist, TCP teardown) plus the ActionLoop
# that runs them. See DESIGN.md's "Dispatch" stage.

add_library(actions_lib OBJECT
    core/ActionLoop.cpp
    log/LogAction.cpp
    blocklist/Blocklist.cpp
    blocklist/BlocklistAction.cpp
    tcp/BlockTcpAction.cpp
    tcp/TcpDestroyer.cpp
)

target_include_directories(actions_lib
    PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/core
    ${CMAKE_CURRENT_SOURCE_DIR}/blocklist
    ${CMAKE_CURRENT_SOURCE_DIR}/tcp
    ${CMAKE_CURRENT_SOURCE_DIR}/log
    ${LIBBPF_INCLUDE_DIRS}
    ${BOOST_INCLUDE_DIR}
)
target_compile_definitions(actions_lib PUBLIC BOOST_ERROR_CODE_HEADER_ONLY)

# action_runner is a manual smoke-test/demo binary for ActionLoop, kept
# alongside the library it exercises. The recipe's do_install() looks for
# it directly under ${B} (the top-level build dir), so its output can't
# be left to default to CMAKE_CURRENT_BINARY_DIR (<build>/actions/) now
# that this CMakeLists.txt lives in a subdirectory.
add_executable(action_runner core/main.cpp)
target_link_libraries(action_runner PRIVATE actions_lib)
set_target_properties(action_runner PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})

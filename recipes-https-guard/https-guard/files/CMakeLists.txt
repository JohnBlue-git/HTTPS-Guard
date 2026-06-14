cmake_minimum_required(VERSION 3.20)
project(https_guard LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

include(FetchContent)

find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBBPF REQUIRED libbpf)

find_package(nlohmann_json REQUIRED)
find_package(Boost 1.74 QUIET)

if(Boost_FOUND)
    set(BOOST_INCLUDE_DIR ${Boost_INCLUDE_DIRS})
    message(STATUS "Using system Boost includes: ${BOOST_INCLUDE_DIR}")
else()
    message(STATUS "Boost headers not found; fetching Boost 1.86 headers via CMake FetchContent")
    FetchContent_Declare(
        boost_headers
        URL https://downloads.sourceforge.net/project/boost/boost/1.86.0/boost_1_86_0.tar.gz
        DOWNLOAD_EXTRACT_TIMESTAMP TRUE
    )
    FetchContent_MakeAvailable(boost_headers)
    set(BOOST_INCLUDE_DIR ${boost_headers_SOURCE_DIR})
    add_compile_definitions(BOOST_ERROR_CODE_HEADER_ONLY)
    message(STATUS "Using fetched Boost headers: ${BOOST_INCLUDE_DIR}")
endif()

add_executable(https_guardd
    https_guard/main.cpp
    https_guard/https_guard_program.cpp
    actions/ActionLoop.cpp
    actions/LogAction.cpp
    ebpf/bpf_program.cpp
)

add_executable(action_runner
    actions/main.cpp
    actions/ActionLoop.cpp
)

foreach(target IN ITEMS https_guardd action_runner)
    target_include_directories(${target}
        PRIVATE
        https_guard
        actions
        ebpf
        ${LIBBPF_INCLUDE_DIRS}
        ${nlohmann_json_INCLUDE_DIRS}
        ${BOOST_INCLUDE_DIR}
    )

    target_link_directories(${target} PRIVATE ${LIBBPF_LIBRARY_DIRS})
    target_link_libraries(${target} PRIVATE ${LIBBPF_LIBRARIES} nlohmann_json::nlohmann_json)
    target_compile_definitions(${target} PRIVATE BOOST_ERROR_CODE_HEADER_ONLY)
    target_compile_options(${target} PRIVATE ${LIBBPF_CFLAGS_OTHER})
endforeach()

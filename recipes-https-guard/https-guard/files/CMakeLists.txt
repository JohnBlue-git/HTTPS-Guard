cmake_minimum_required(VERSION 3.20)
project(https_guard LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBBPF REQUIRED libbpf)

find_package(nlohmann_json REQUIRED)

add_executable(https_guardd
    src/main.cpp
)

target_include_directories(https_guardd
    PRIVATE
    include
    ${LIBBPF_INCLUDE_DIRS}
    ${nlohmann_json_INCLUDE_DIRS}
)

target_link_directories(https_guardd PRIVATE ${LIBBPF_LIBRARY_DIRS})
target_link_libraries(https_guardd PRIVATE ${LIBBPF_LIBRARIES} nlohmann_json::nlohmann_json)
target_compile_options(https_guardd PRIVATE ${LIBBPF_CFLAGS_OTHER})

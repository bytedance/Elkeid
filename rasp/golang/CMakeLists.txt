cmake_minimum_required(VERSION 3.17)
project(go-probe)

set(CMAKE_CXX_STANDARD 17)

include_directories(${CMAKE_SOURCE_DIR})

option(STATIC_BUILD "enable static build" OFF)

set(CMAKE_POSITION_INDEPENDENT_CODE TRUE)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/bin)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/lib)

find_package(aio CONFIG REQUIRED)
find_package(c-runtime CONFIG REQUIRED)
find_package(elf-loader CONFIG REQUIRED)
find_package(go-symbol CONFIG REQUIRED)
find_package(mimalloc CONFIG REQUIRED)
find_package(tiny-regex-c CONFIG REQUIRED)
find_package(trap CONFIG REQUIRED)

add_library(
        go_base
        STATIC
        asm/api_hook.cpp
        client/smith_client.cpp
        client/smith_message.cpp
        go/type/stringify.cpp
)

target_link_libraries(
        go_base
        PUBLIC
        aio::aio
        go::go_symbol
        runtime::c_runtime
        mimalloc-static
        regex::tiny-regex-c
        trap::trap
)

add_executable(go_probe main.cpp client/smith_probe.cpp)
target_link_libraries(go_probe PRIVATE go_base $<$<BOOL:${STATIC_BUILD}>:-static-pie>)

add_executable(go_loader loader/main.cpp client/smith_probe.cpp)
target_link_libraries(go_loader PRIVATE go_base elf::elf_loader $<$<BOOL:${STATIC_BUILD}>:-static-pie>)
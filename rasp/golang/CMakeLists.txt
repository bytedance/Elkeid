cmake_minimum_required(VERSION 3.17)
project(go_probe)

set(CMAKE_CXX_STANDARD 14)

include_directories(${CMAKE_SOURCE_DIR})

option(STATIC_BUILD "enable static build" OFF)

set(CMAKE_POSITION_INDEPENDENT_CODE TRUE)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/bin)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/lib)

set(EVENT__DISABLE_TESTS ON CACHE BOOL "disable event tests")
set(EVENT__DISABLE_SAMPLES ON CACHE BOOL "disable event samples")
set(EVENT__DISABLE_OPENSSL ON CACHE BOOL "disable event openssl")
set(EVENT__DISABLE_BENCHMARK ON CACHE BOOL "disable event benchmark")

set(JSON_BuildTests OFF CACHE BOOL "disable json library tests")

set(ZYDIS_BUILD_TOOLS OFF CACHE BOOL "disable disassembler tools")
set(ZYDIS_BUILD_EXAMPLES OFF CACHE BOOL "disable disassembler examples")

include(cmake/ELFIO.cmake)
include(cmake/zydis.cmake)
include(cmake/json.cmake)
include(cmake/libevent.cmake)

add_subdirectory(zero)
add_subdirectory(c-runtime)
add_subdirectory(sample/go)

add_library(
        go_base
        STATIC
        asm/api_hook.cpp
        asm/inline_hook.cpp
        client/smith_client.cpp
        client/smith_message.cpp
        go/symbol/func.cpp
        go/symbol/build_info.cpp
        go/symbol/line_table.cpp
        go/symbol/interface_table.cpp
        go/stack/smith_trace.cpp
        tiny-regex-c/re.c
)

add_executable(go_sample sample/main.cpp client/smith_probe.cpp go/api/api.cpp heap/memory.cpp)
add_executable(go_loader loader/main.cpp loader/elf/loader.cpp client/smith_probe.cpp go/api/api.cpp heap/memory.cpp)
add_executable(go_probe main.cpp client/smith_probe.cpp go/api/api.cpp heap/memory.cpp)

target_link_libraries(go_sample go_base ${CMAKE_DL_LIBS})
target_link_libraries(go_loader go_base $<$<BOOL:${STATIC_BUILD}>:-static-pie>)
target_link_libraries(go_probe go_base $<$<BOOL:${STATIC_BUILD}>:-static-pie>)
target_link_libraries(go_base zero c_runtime elfio Zydis nlohmann_json event_core_static event_pthreads_static)
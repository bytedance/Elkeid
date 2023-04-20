cmake_minimum_required(VERSION 3.17)
project(go_probe)

set(CMAKE_CXX_STANDARD 17)

include_directories(${CMAKE_SOURCE_DIR})

option(STATIC_BUILD "enable static build" OFF)

set(CMAKE_POSITION_INDEPENDENT_CODE TRUE)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/bin)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/lib)

set(EVENT__LIBRARY_TYPE STATIC CACHE STRING "disable shared library")
set(EVENT__DISABLE_TESTS ON CACHE BOOL "disable event tests")
set(EVENT__DISABLE_SAMPLES ON CACHE BOOL "disable event samples")
set(EVENT__DISABLE_OPENSSL ON CACHE BOOL "disable event openssl")
set(EVENT__DISABLE_BENCHMARK ON CACHE BOOL "disable event benchmark")

set(ZYDIS_BUILD_TOOLS OFF CACHE BOOL "disable disassembler tools")
set(ZYDIS_BUILD_EXAMPLES OFF CACHE BOOL "disable disassembler examples")

set(JSON_BuildTests OFF CACHE BOOL "disable json library tests")

include(FetchContent)

FetchContent_Declare(
        ELFIO
        GIT_REPOSITORY https://github.com/serge1/ELFIO
        GIT_TAG Release_3.9
)

FetchContent_MakeAvailable(ELFIO)

FetchContent_Declare(
        json
        GIT_REPOSITORY https://github.com/nlohmann/json
        GIT_TAG v3.9.1
)

FetchContent_MakeAvailable(json)

FetchContent_Declare(
        libevent
        GIT_REPOSITORY https://github.com/libevent/libevent
        GIT_TAG release-2.1.12-stable
)

FetchContent_MakeAvailable(libevent)

FetchContent_Declare(
        c-runtime
        GIT_REPOSITORY https://github.com/Hackerl/c-runtime
        GIT_TAG 77e47318432a39b4920b8d06610aea0b43138b23
)

FetchContent_MakeAvailable(c-runtime)

FetchContent_Declare(
        zydis
        GIT_REPOSITORY    https://github.com/zyantific/zydis
        GIT_TAG           v3.1.0
)

FetchContent_MakeAvailable(zydis)

FetchContent_Declare(
        zero
        GIT_REPOSITORY https://github.com/Hackerl/zero
        GIT_TAG d6c7172b537918bd130686b2cc2e06dcccb71344
)

FetchContent_MakeAvailable(zero)

FetchContent_Declare(
        elf-loader
        GIT_REPOSITORY https://github.com/Hackerl/elf-loader
        GIT_TAG 9a44c8dceafb940f6fab45898167243fee59b1b9
)

FetchContent_MakeAvailable(elf-loader)

add_library(
        go_base
        STATIC
        asm/trap.cpp
        asm/api_hook.cpp
        client/smith_client.cpp
        client/smith_message.cpp
        go/symbol/func.cpp
        go/symbol/build_info.cpp
        go/symbol/line_table.cpp
        go/symbol/interface_table.cpp
        tiny-regex-c/re.c
)

add_executable(go_loader loader/main.cpp client/smith_probe.cpp go/api/api.cpp heap/memory.cpp)
add_executable(go_probe main.cpp client/smith_probe.cpp go/api/api.cpp heap/memory.cpp)

target_link_libraries(go_loader go_base elf_loader $<$<BOOL:${STATIC_BUILD}>:-static-pie>)
target_link_libraries(go_probe go_base $<$<BOOL:${STATIC_BUILD}>:-static-pie>)
target_link_libraries(go_base zero c_runtime Zydis elfio nlohmann_json event_core_static event_pthreads_static)
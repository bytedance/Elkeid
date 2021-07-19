cmake_minimum_required(VERSION 3.17)
project(go_probe)

set(CMAKE_CXX_STANDARD 14)

include_directories(include)
include_directories(${CMAKE_SOURCE_DIR})

set(CMAKE_POSITION_INDEPENDENT_CODE TRUE)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/bin)

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

add_subdirectory(sample/go)

add_executable(go_sample sample/main.cpp asm/inline_hook.cpp asm/api_hook.cpp futex/mutex.cpp
        futex/futex.cpp futex/condition.cpp client/smith_client.cpp client/smith_probe.cpp
        client/smith_message.cpp go/stack/smith_trace.cpp go/symbol/build_info.cpp
        go/symbol/line_table.cpp go/symbol/func.cpp go/registry/api_registry.cpp
        go/api/workspace.cpp go/api/api.cpp go/stack/printf/printf.c)

add_executable(go_loader loader/main.cpp asm/inline_hook.cpp asm/api_hook.cpp futex/mutex.cpp
        futex/futex.cpp futex/condition.cpp client/smith_client.cpp client/smith_probe.cpp
        client/smith_message.cpp go/stack/smith_trace.cpp go/symbol/build_info.cpp
        go/symbol/line_table.cpp go/symbol/func.cpp go/registry/api_registry.cpp
        go/api/workspace.cpp go/api/api.cpp go/stack/printf/printf.c loader/elf/loader.cpp)

add_executable(go_probe main.cpp asm/inline_hook.cpp asm/api_hook.cpp futex/mutex.cpp
        futex/futex.cpp futex/condition.cpp client/smith_client.cpp client/smith_probe.cpp
        client/smith_message.cpp go/stack/smith_trace.cpp go/symbol/build_info.cpp
        go/symbol/line_table.cpp go/symbol/func.cpp go/registry/api_registry.cpp
        go/api/workspace.cpp go/api/api.cpp go/stack/printf/printf.c)

target_link_libraries(go_probe elfio Zydis nlohmann_json event_core_static event_pthreads_static)
target_link_libraries(go_loader elfio Zydis nlohmann_json event_core_static event_pthreads_static)
target_link_libraries(go_sample elfio Zydis nlohmann_json event_core_static event_pthreads_static ${CMAKE_DL_LIBS})
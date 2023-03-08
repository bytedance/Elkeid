cmake_minimum_required(VERSION 3.17)
project(go_probe_ebpf)

set(CMAKE_CXX_STANDARD 17)

include_directories(${CMAKE_SOURCE_DIR}/ebpf/libbpf/include/uapi)

option(STATIC_BUILD "enable static build" OFF)

set(CMAKE_POSITION_INDEPENDENT_CODE TRUE)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/bin)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/lib)

set(ZYDIS_BUILD_TOOLS OFF CACHE BOOL "disable disassembler tools")
set(ZYDIS_BUILD_EXAMPLES OFF CACHE BOOL "disable disassembler examples")

include(FetchContent)

FetchContent_Declare(
        aio
        GIT_REPOSITORY https://github.com/Hackerl/aio
        GIT_TAG 894d5ebbd2deed820cefe66360a3f568e920ba9d
)

FetchContent_MakeAvailable(aio)

FetchContent_Declare(
        go-symbol
        GIT_REPOSITORY https://github.com/Hackerl/go-symbol
        GIT_TAG fd727a0d44d98c16fb397e9b750440d71d2dd341
)

FetchContent_MakeAvailable(go-symbol)

FetchContent_Declare(
        zydis
        GIT_REPOSITORY https://github.com/zyantific/zydis
        GIT_TAG v4.0.0
)

FetchContent_MakeAvailable(zydis)

find_package(PkgConfig)

pkg_check_modules(zlib REQUIRED IMPORTED_TARGET zlib)
pkg_check_modules(libelf REQUIRED IMPORTED_TARGET libelf)
pkg_check_modules(libbpf REQUIRED IMPORTED_TARGET libbpf)

add_executable(
        go_probe_ebpf
        main.cpp
        client/smith_message.cpp
        client/smith_client.cpp
)

target_link_libraries(
        go_probe_ebpf
        go_symbol
        aio
        Zydis
        PkgConfig::libbpf
        PkgConfig::zlib
        PkgConfig::libelf
        $<$<BOOL:${STATIC_BUILD}>:-static-pie>
)
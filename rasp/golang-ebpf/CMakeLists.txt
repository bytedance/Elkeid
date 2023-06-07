cmake_minimum_required(VERSION 3.17)
project(go-probe-ebpf)

set(CMAKE_CXX_STANDARD 17)

include_directories(${CMAKE_SOURCE_DIR}/ebpf/libbpf/include/uapi)

option(STATIC_BUILD "enable static build" OFF)

set(CMAKE_POSITION_INDEPENDENT_CODE TRUE)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/bin)

find_package(aio CONFIG REQUIRED)
find_package(go-symbol CONFIG REQUIRED)
find_package(zydis CONFIG REQUIRED)

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
        PRIVATE
        aio::aio
        go::go_symbol
        Zydis::Zydis
        PkgConfig::libbpf
        PkgConfig::zlib
        PkgConfig::libelf
        $<$<BOOL:${STATIC_BUILD}>:-static-pie>
)
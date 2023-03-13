cmake_minimum_required(VERSION 3.17)
project(php_probe)

set(CMAKE_CXX_STANDARD 17)

include_directories(${CMAKE_SOURCE_DIR})

option(STATIC_BUILD "enable static build" OFF)

set(CMAKE_POSITION_INDEPENDENT_CODE TRUE)

set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/lib)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/lib)

set(AIO_DISABLE_SSL ON CACHE BOOL "disable aio openssl")

if (NOT DEFINED PHP_EXTENSIONS_INCLUDE_DIR)
    find_package(PHP 5.3.0 REQUIRED)
endif ()

include_directories(
        ${PHP_EXTENSIONS_INCLUDE_DIR}
        ${PHP_EXTENSIONS_INCLUDE_DIR}/main
        ${PHP_EXTENSIONS_INCLUDE_DIR}/Zend
        ${PHP_EXTENSIONS_INCLUDE_DIR}/TSRM
        ${PHP_EXTENSIONS_INCLUDE_DIR}/ext
        ${PHP_EXTENSIONS_INCLUDE_DIR}/sapi
)

include(FetchContent)

FetchContent_Declare(
        aio
        GIT_REPOSITORY https://github.com/Hackerl/aio
        GIT_TAG 5281f6f3b6ed31311d5296b4a7f3d5d149e11859
)

FetchContent_MakeAvailable(aio)

FetchContent_Declare(
        c-runtime
        GIT_REPOSITORY https://github.com/Hackerl/c-runtime
        GIT_TAG 77e47318432a39b4920b8d06610aea0b43138b23
)

FetchContent_MakeAvailable(c-runtime)

add_library(
        php_probe
        SHARED
        library.cpp
        php/api.cpp
        php/hash.cpp
        client/smith_client.cpp
        client/smith_message.cpp
        client/smith_probe.cpp
        tiny-regex-c/re.c
)

set_target_properties(php_probe PROPERTIES C_VISIBILITY_PRESET hidden)
set_target_properties(php_probe PROPERTIES CXX_VISIBILITY_PRESET hidden)

target_link_libraries(
        php_probe
        aio
        c_runtime
        $<$<BOOL:${STATIC_BUILD}>:-static-libgcc>
        $<$<BOOL:${STATIC_BUILD}>:-static-libstdc++>
        -Wl,--exclude-libs,ALL
)

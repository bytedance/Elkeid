cmake_minimum_required(VERSION 3.17)
project(php_probe)

set(CMAKE_CXX_STANDARD 17)

include_directories(${CMAKE_SOURCE_DIR})

option(STATIC_BUILD "enable static build" OFF)

set(CMAKE_POSITION_INDEPENDENT_CODE TRUE)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/lib)

find_package(aio CONFIG REQUIRED)
find_package(c-runtime CONFIG REQUIRED)
find_package(tiny-regex-c CONFIG REQUIRED)

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

add_library(
        php_probe
        SHARED
        library.cpp
        php/api.cpp
        php/hash.cpp
        client/smith_client.cpp
        client/smith_message.cpp
        client/smith_probe.cpp
)

set_target_properties(php_probe PROPERTIES C_VISIBILITY_PRESET hidden)
set_target_properties(php_probe PROPERTIES CXX_VISIBILITY_PRESET hidden)

target_link_libraries(
        php_probe
        PRIVATE
        aio::aio
        runtime::c_runtime
        $<$<BOOL:${STATIC_BUILD}>:-static-libgcc>
        $<$<BOOL:${STATIC_BUILD}>:-static-libstdc++>
        -Wl,--exclude-libs,ALL
)

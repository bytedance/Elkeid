cmake_minimum_required(VERSION 3.17)
project(python_probe)

set(CMAKE_CXX_STANDARD 17)

include_directories(${CMAKE_SOURCE_DIR})

option(STATIC_BUILD "enable static build" OFF)

set(CMAKE_POSITION_INDEPENDENT_CODE TRUE)

set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/lib)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/lib)

set(EVENT__LIBRARY_TYPE STATIC CACHE STRING "disable shared library")
set(EVENT__DISABLE_TESTS ON CACHE BOOL "disable event tests")
set(EVENT__DISABLE_SAMPLES ON CACHE BOOL "disable event samples")
set(EVENT__DISABLE_OPENSSL ON CACHE BOOL "disable event openssl")
set(EVENT__DISABLE_BENCHMARK ON CACHE BOOL "disable event benchmark")

set(JSON_BuildTests OFF CACHE BOOL "disable json library tests")

if (NOT DEFINED Python_INCLUDE_DIRS)
    find_package(Python 2.7.0 REQUIRED COMPONENTS Development)
endif ()

include_directories(${Python_INCLUDE_DIRS})

include(FetchContent)

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
        zero
        GIT_REPOSITORY https://github.com/Hackerl/zero
        GIT_TAG d6c7172b537918bd130686b2cc2e06dcccb71344
)

FetchContent_MakeAvailable(zero)

FetchContent_Declare(
        c-runtime
        GIT_REPOSITORY https://github.com/Hackerl/c-runtime
        GIT_TAG 77e47318432a39b4920b8d06610aea0b43138b23
)

FetchContent_MakeAvailable(c-runtime)

add_library(
        python_probe
        SHARED
        library.cpp
        client/smith_client.cpp
        client/smith_message.cpp
        client/smith_probe.cpp
        tiny-regex-c/re.c
)

set_target_properties(python_probe PROPERTIES C_VISIBILITY_PRESET hidden)
set_target_properties(python_probe PROPERTIES CXX_VISIBILITY_PRESET hidden)

target_link_libraries(
        python_probe
        zero
        c_runtime
        nlohmann_json
        event_core_static
        event_pthreads_static
        $<$<BOOL:${STATIC_BUILD}>:-static-libgcc>
        $<$<BOOL:${STATIC_BUILD}>:-static-libstdc++>
        -Wl,--exclude-libs,ALL
)
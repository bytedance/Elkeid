cmake_minimum_required(VERSION 3.17)
project(python-probe)

set(CMAKE_CXX_STANDARD 17)

include_directories(${CMAKE_SOURCE_DIR})

option(STATIC_BUILD "enable static build" OFF)

set(CMAKE_POSITION_INDEPENDENT_CODE TRUE)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/lib)

find_package(aio CONFIG REQUIRED)
find_package(c-runtime CONFIG REQUIRED)
find_package(tiny-regex-c CONFIG REQUIRED)

if (NOT DEFINED Python_INCLUDE_DIRS)
    find_package(Python REQUIRED COMPONENTS Development)
endif ()

include_directories(${Python_INCLUDE_DIRS})

add_library(
        python_probe
        SHARED
        library.cpp
        client/smith_client.cpp
        client/smith_message.cpp
        client/smith_probe.cpp
)

set_target_properties(python_probe PROPERTIES C_VISIBILITY_PRESET hidden)
set_target_properties(python_probe PROPERTIES CXX_VISIBILITY_PRESET hidden)

target_link_libraries(
        python_probe
        PRIVATE
        aio::aio
        runtime::c_runtime
        $<$<BOOL:${STATIC_BUILD}>:-static-libgcc>
        $<$<BOOL:${STATIC_BUILD}>:-static-libstdc++>
        -Wl,--exclude-libs,ALL
)
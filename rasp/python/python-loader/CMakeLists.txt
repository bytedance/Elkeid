cmake_minimum_required(VERSION 3.17)
project(python_loader)

set(CMAKE_CXX_STANDARD 14)

option(STATIC_BUILD "enable static build" OFF)

set(CMAKE_POSITION_INDEPENDENT_CODE TRUE)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/bin)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/lib)

set(ZYDIS_BUILD_TOOLS OFF CACHE BOOL "disable disassembler tools")
set(ZYDIS_BUILD_EXAMPLES OFF CACHE BOOL "disable disassembler examples")

set(C_RUNTIME_HEAP_CACHE OFF CACHE BOOL "disable heap memory cache")

include(FetchContent)

FetchContent_Declare(
        ELFIO
        GIT_REPOSITORY https://github.com/serge1/ELFIO
        GIT_TAG Release_3.10
)

FetchContent_MakeAvailable(ELFIO)

FetchContent_Declare(
        trap
        GIT_REPOSITORY https://github.com/Hackerl/trap
        GIT_TAG ccb0acc39faf8584c490d3ba34d788f4014f653e
)

FetchContent_MakeAvailable(trap)

FetchContent_Declare(
        c-runtime
        GIT_REPOSITORY https://github.com/Hackerl/c-runtime
        GIT_TAG 77e47318432a39b4920b8d06610aea0b43138b23
)

FetchContent_MakeAvailable(c-runtime)

add_executable(python_loader main.cpp heap/memory.cpp)
target_link_libraries(python_loader trap c_runtime elfio $<$<BOOL:${STATIC_BUILD}>:-static-pie>)
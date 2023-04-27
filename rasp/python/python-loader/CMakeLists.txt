cmake_minimum_required(VERSION 3.17)
project(python_loader)

set(CMAKE_CXX_STANDARD 17)

option(STATIC_BUILD "enable static build" OFF)

set(CMAKE_POSITION_INDEPENDENT_CODE TRUE)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/bin)

find_package(zero CONFIG REQUIRED)
find_package(elf-cpp CONFIG REQUIRED)
find_package(mimalloc CONFIG REQUIRED)
find_package(trap CONFIG REQUIRED)

add_executable(python_loader main.cpp)

target_link_libraries(
        python_loader
        PUBLIC
        zero::zero
        elf::elf_cpp
        trap::trap
        mimalloc-static
        $<$<BOOL:${STATIC_BUILD}>:-static-pie>
)
cmake_minimum_required(VERSION 3.17)
project(NSMount)

set(CMAKE_CXX_STANDARD 17)

option(STATIC_BUILD "enable static build" OFF)

set(CMAKE_POSITION_INDEPENDENT_CODE TRUE)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/bin)

find_package(Threads REQUIRED)
find_package(zero CONFIG REQUIRED)

add_executable(NSMount main.cpp)
target_link_libraries(NSMount PRIVATE zero::zero Threads::Threads $<$<BOOL:${STATIC_BUILD}>:-static-pie>)
cmake_minimum_required(VERSION 3.17)
project(python_client)

set(CMAKE_CXX_STANDARD 14)

include_directories(include)

set(CMAKE_POSITION_INDEPENDENT_CODE TRUE)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/bin)

set(CXX_VISIBILITY_PRESET hidden)

set(EVENT__DISABLE_TESTS ON CACHE BOOL "disable event tests")
set(EVENT__DISABLE_SAMPLES ON CACHE BOOL "disable event samples")
set(EVENT__DISABLE_OPENSSL ON CACHE BOOL "disable event openssl")
set(EVENT__DISABLE_BENCHMARK ON CACHE BOOL "disable event benchmark")

include(cmake/libevent.cmake)

add_library(python_client SHARED client/smith_client.cpp library.cpp)
target_link_libraries(python_client event_core event_pthreads)

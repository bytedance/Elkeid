cmake_minimum_required(VERSION 3.17)
project(python_inject)

set(CMAKE_CXX_STANDARD 14)

include_directories(include)

set(CMAKE_POSITION_INDEPENDENT_CODE TRUE)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/bin)

include(cmake/ELFIO.cmake)

add_executable(python_inject main.cpp)
target_link_libraries(python_inject elfio)

cmake_minimum_required(VERSION 3.17)
project(go_sample_library)

set(GO_SAMPLE_SOURCE main.go)
set(GO_SAMPLE_LIBRARY go_sample.so)
set(GO_SAMPLE_BUILD go build -o ${GO_SAMPLE_LIBRARY} -buildmode=c-shared ${CMAKE_CURRENT_SOURCE_DIR}/${GO_SAMPLE_SOURCE})

add_custom_command(OUTPUT "${GO_SAMPLE_LIBRARY}"
        COMMAND ${GO_SAMPLE_BUILD}
        WORKING_DIRECTORY "${CMAKE_RUNTIME_OUTPUT_DIRECTORY}"
        DEPENDS ${GO_SAMPLE_SOURCE} VERBATIM)

add_custom_target(go_sample_library ALL DEPENDS ${GO_SAMPLE_LIBRARY})
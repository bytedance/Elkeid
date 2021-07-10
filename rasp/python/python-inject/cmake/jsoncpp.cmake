include(FetchContent)

FetchContent_Declare(
        jsoncpp
        GIT_REPOSITORY    https://github.com/open-source-parsers/jsoncpp
        GIT_TAG           1.9.4
)

FetchContent_MakeAvailable(jsoncpp)
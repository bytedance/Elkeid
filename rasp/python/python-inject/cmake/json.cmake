include(FetchContent)

FetchContent_Declare(
        json
        GIT_REPOSITORY    https://github.com/nlohmann/json
        GIT_TAG           v3.9.1
)

FetchContent_MakeAvailable(json)
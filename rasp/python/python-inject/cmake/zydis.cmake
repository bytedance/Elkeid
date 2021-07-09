include(FetchContent)

FetchContent_Declare(
        zydis
        GIT_REPOSITORY    https://github.com/zyantific/zydis
        GIT_TAG           v3.1.0
)

FetchContent_MakeAvailable(zydis)
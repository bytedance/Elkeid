include(FetchContent)

FetchContent_Declare(
        libevent
        GIT_REPOSITORY    https://github.com/libevent/libevent
        GIT_TAG           release-2.1.12-stable
)

FetchContent_MakeAvailable(libevent)
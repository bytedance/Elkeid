include(FetchContent)

FetchContent_Declare(
        ELFIO
        GIT_REPOSITORY    https://github.com/serge1/ELFIO
        GIT_TAG           Release_3.8
)

FetchContent_MakeAvailable(ELFIO)
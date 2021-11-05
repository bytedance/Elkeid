#include <dlfcn.h>
#include <zero/log.h>
#include <zero/filesystem/path.h>
#include <go/symbol/build_info.h>
#include <go/symbol/line_table.h>
#include <asm/api_hook.h>
#include <go/api/api.h>

using GOStartPtr = void (*)();
using GetFirstModuleDataPtr = void *(*)();

int main() {
    INIT_CONSOLE_LOG(zero::INFO);

    std::string path = zero::filesystem::path::join(
            zero::filesystem::path::getApplicationDirectory(),
            "go_sample.so"
    );

    void* handle = dlopen(path.c_str(), RTLD_LAZY);

    if (!handle)
        return -1;

    auto pfnGOStart = (GOStartPtr)dlsym(handle, "GOStart");

    if (!pfnGOStart)
        return -1;

    auto pfnGetFirstModuleData = (GetFirstModuleDataPtr)dlsym(handle, "GetFirstModuleData");

    if (!pfnGetFirstModuleData)
        return -1;

    if (gBuildInfo->load(path)) {
        LOG_INFO("go version: %s", gBuildInfo->mVersion.c_str());
    }

    gSmithProbe->start();

    auto firstModule = pfnGetFirstModuleData();
    auto lineTable = *(char **)firstModule;

    if (!gLineTable->load(lineTable)) {
        LOG_ERROR("line table load failed");
        return -1;
    }

    for (const auto &api : GOLANG_API) {
        for (unsigned int i = 0; i < gLineTable->mFuncNum; i++) {
            CFunc func = {};

            if (!gLineTable->getFunc(i, func))
                break;

            const char *name = func.getName();
            void *entry = (void *)func.getEntry();

            if ((api.ignoreCase ? strcasecmp(api.name, name) : strcmp(api.name, name)) == 0) {
                LOG_INFO("hook %s: %p", name, entry);

                if (!gAPIHook->hook(entry, (void *)api.metadata.entry, api.metadata.origin)) {
                    LOG_WARNING("hook %s failed", name);
                    break;
                }

                break;
            }
        }
    }

    pfnGOStart();

    return 0;
}
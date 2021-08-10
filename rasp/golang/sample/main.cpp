#include <dlfcn.h>
#include <common/utils/path.h>
#include <go/symbol/build_info.h>
#include <common/log.h>
#include <go/symbol/line_table.h>
#include <asm/api_hook.h>
#include <go/api/api.h>

typedef void(*PFN_GOStart)();
typedef void*(*PFN_GetFirstModuleData)();

int main() {
    INIT_CONSOLE_LOG(INFO);

    std::string path = CPath::join(CPath::getAPPDir(), "go_sample.so");

    void* DLHandle = dlopen(path.c_str(), RTLD_LAZY);

    if (!DLHandle)
        return -1;

    auto pfnGOStart = (PFN_GOStart)dlsym(DLHandle, "GOStart");

    if (!pfnGOStart)
        return -1;

    auto pfnGetFirstModuleData = (PFN_GetFirstModuleData)dlsym(DLHandle, "GetFirstModuleData");

    if (!pfnGetFirstModuleData)
        return -1;

    if (gBuildInfo->load(path)) {
        LOG_INFO("go version: %s", gBuildInfo->mVersion.c_str());
    }

    if (!gWorkspace->init()) {
        LOG_ERROR("workspace init failed");
        return -1;
    }

    gSmithProbe->start();

    auto firstModule = pfnGetFirstModuleData();
    auto lineTable = *(char **)firstModule;

    if (!gLineTable->load(lineTable)) {
        LOG_ERROR("line table load failed");
        return -1;
    }

    for (unsigned long i = 0; i < gLineTable->mFuncNum; i++) {
        CFunction func = {};

        if (!gLineTable->getFunc(i, func))
            break;

        const char *name = func.getName();
        void *entry = func.getEntry();

        for (const auto &r : APIRegistry) {
            if (!r.ignoreCase && strcmp(r.name, name) != 0)
                continue;

            if (r.ignoreCase && CStringHelper::tolower(r.name) != CStringHelper::tolower(name))
                continue;

            if (*r.metadata.origin != nullptr) {
                LOG_INFO("ignore %s: %p", name, entry);
                continue;
            }

            LOG_INFO("hook %s: %p", name, entry);

            if (!gAPIHook->hook(entry, (void *)r.metadata.entry, r.metadata.origin)) {
                LOG_WARNING("hook %s failed", name);
                continue;
            }
        }
    }

    pfnGOStart();

    return 0;
}
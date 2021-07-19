#include "elf/loader.h"
#include <common/log.h>
#include <csignal>
#include <go/api/workspace.h>
#include <go/symbol/build_info.h>
#include <go/symbol/line_table.h>
#include <client/smith_probe.h>
#include <go/registry/api_registry.h>
#include <asm/api_hook.h>

int main(int argc, char **argv, char **env) {
    INIT_FILE_LOG(INFO, "go-loader");

    if (argc < 2) {
        LOG_ERROR("require input file");
        return -1;
    }

    ELFLoader loader;

    if (!loader.load(argv[1]))
        return -1;

    sigset_t mask = {};
    sigset_t origin_mask = {};

    sigfillset(&mask);

    if (pthread_sigmask(SIG_SETMASK, &mask, &origin_mask) != 0) {
        LOG_ERROR("set signal mask failed");
        return -1;
    }

    if (gBuildInfo->load(argv[1], loader.mProgramBase)) {
        LOG_INFO("go version: %s", gBuildInfo->mVersion.c_str());
    }

    if (!gLineTable->load(argv[1], loader.mProgramBase)) {
        LOG_ERROR("line table load failed");
        return -1;
    }

    if (!gWorkspace->init()) {
        LOG_ERROR("workspace init failed");
        return -1;
    }

    gSmithProbe->start();

    for (unsigned long i = 0; i < gLineTable->mFuncNum; i++) {
        CFunction func = {};

        if (!gLineTable->getFunc(i, func))
            break;

        auto name = func.getName();
        auto entry = func.getEntry();

        CAPIRegister apiRegister = {};

        if (!gAPIRegistry->find(name, apiRegister))
            continue;

        LOG_INFO("hook %s: %p", name, entry);

        if (!gAPIHook->hook(entry, apiRegister.entry, apiRegister.origin)) {
            LOG_WARNING("hook %s failed", name);
            continue;
        }
    }

    pthread_sigmask(SIG_SETMASK, &origin_mask, nullptr);
    loader.jump(argc - 1, argv + 1, env);

    return 0;
}

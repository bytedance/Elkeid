#include "elf/loader.h"
#include <common/log.h>
#include <csignal>
#include <go/symbol/build_info.h>
#include <go/symbol/line_table.h>
#include <go/api/api.h>
#include <asm/api_hook.h>

int main(int argc, char **argv, char **env) {
    INIT_CONSOLE_LOG(INFO);

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

    pthread_sigmask(SIG_SETMASK, &origin_mask, nullptr);
    loader.jump(argc - 1, argv + 1, env);

    return 0;
}

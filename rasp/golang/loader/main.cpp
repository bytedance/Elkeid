#include "elf/loader.h"
#include <zero/log.h>
#include <csignal>
#include <go/symbol/build_info.h>
#include <go/symbol/line_table.h>
#include <go/symbol/interface_table.h>
#include <go/api/api.h>
#include <asm/api_hook.h>

int main(int argc, char **argv, char **env) {
    INIT_CONSOLE_LOG(zero::INFO);

    if (argc < 2) {
        LOG_ERROR("require input file");
        return -1;
    }

    CELFLoader loader;

    if (!loader.load(argv[1]))
        return -1;

    sigset_t mask = {};
    sigset_t origin_mask = {};

    sigfillset(&mask);

    if (pthread_sigmask(SIG_SETMASK, &mask, &origin_mask) != 0) {
        LOG_ERROR("set signal mask failed");
        return -1;
    }

    if (!gLineTable->load(argv[1], loader.mProgramBase)) {
        LOG_ERROR("line table load failed");
        return -1;
    }

    if (gBuildInfo->load(argv[1], loader.mProgramBase)) {
        LOG_INFO("go version: %s", gBuildInfo->mVersion.c_str());

        CInterfaceTable table = {};

        if (!table.load(argv[1], loader.mProgramBase)) {
            LOG_ERROR("interface table load failed");
            return -1;
        }

        table.findByFuncName("errors.(*errorString).Error", (go::interface_item **)CAPIBase::errorInterface());
    }

    gSmithProbe->start();

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

    pthread_sigmask(SIG_SETMASK, &origin_mask, nullptr);
    loader.jump(argc - 1, argv + 1, env);

    return 0;
}

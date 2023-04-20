#include "go/symbol/build_info.h"
#include "go/symbol/line_table.h"
#include "go/symbol/interface_table.h"
#include "go/api/api.h"
#include <zero/log.h>
#include <csignal>
#include <asm/api_hook.h>
#include <z_syscall.h>

void quit(int status) {
    char *env = getenv("QUIT");

    if (!env) {
        LOG_WARNING("can't found quit env variable");
        z_exit_group(-1);
    }

    std::optional<uintptr_t> address = zero::strings::toNumber<uintptr_t>(env, 16);

    if (!address) {
        LOG_ERROR("invalid quit function address");
        z_exit_group(-1);
    }

    ((decltype(quit) *)*address)(status);
}

int main() {
    sigset_t mask = {};
    sigset_t origin_mask = {};

    sigfillset(&mask);

    if (pthread_sigmask(SIG_SETMASK, &mask, &origin_mask) != 0)
        quit(-1);

    INIT_FILE_LOG(zero::INFO, "go-probe");

    if (!gLineTable->load()) {
        LOG_ERROR("line table load failed");
        pthread_sigmask(SIG_SETMASK, &origin_mask, nullptr);
        quit(-1);
    }

    if (gBuildInfo->load()) {
        LOG_INFO("go version: %s", gBuildInfo->mVersion.c_str());

        InterfaceTable table = {};

        if (!table.load()) {
            LOG_ERROR("interface table load failed");
            pthread_sigmask(SIG_SETMASK, &origin_mask, nullptr);
            quit(-1);
        }

        table.findByFuncName("errors.(*errorString).Error", (go::interface_item **)APIBase::errorInterface());
    }

    gSmithProbe->start();

    for (const auto &api : GOLANG_API) {
        for (unsigned int i = 0; i < gLineTable->mFuncNum; i++) {
            Func func = {};

            if (!gLineTable->getFunc(i, func))
                break;

            const char *name = func.getName();
            void *entry = (void *)func.getEntry();

            if ((api.ignoreCase ? strcasecmp(api.name, name) : strcmp(api.name, name)) == 0) {
                LOG_INFO("hook %s: %p", name, entry);

                if (hookAPI(entry, (void *)api.metadata.entry, api.metadata.origin) < 0) {
                    LOG_WARNING("hook %s failed", name);
                    break;
                }

                break;
            }
        }
    }

    pthread_sigmask(SIG_SETMASK, &origin_mask, nullptr);
    quit(0);

    return 0;
}

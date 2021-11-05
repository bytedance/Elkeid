#include "go/symbol/build_info.h"
#include "go/symbol/line_table.h"
#include "go/symbol/interface_table.h"
#include "go/api/api.h"
#include <zero/log.h>
#include <csignal>
#include <asm/api_hook.h>
#include <z_syscall.h>

int main() {
    INIT_FILE_LOG(zero::INFO, "go-probe");

    sigset_t mask = {};
    sigset_t origin_mask = {};

    sigfillset(&mask);

    if (pthread_sigmask(SIG_SETMASK, &mask, &origin_mask) != 0) {
        LOG_ERROR("set signal mask failed");
        return -1;
    }

    if (!gLineTable->load()) {
        LOG_ERROR("line table load failed");
        return -1;
    }

    if (gBuildInfo->load()) {
        LOG_INFO("go version: %s", gBuildInfo->mVersion.c_str());

        CInterfaceTable table = {};

        if (!table.load()) {
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
    z_exit(0);

    return 0;
}

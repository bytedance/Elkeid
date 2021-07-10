#include "go/symbol/build_info.h"
#include "go/symbol/line_table.h"
#include "go/registry/api_registry.h"
#include "syscall/do_syscall.h"
#include "client/smith_probe.h"
#include "go/api/workspace.h"
#include <common/log.h>
#include <csignal>
#include <syscall.h>
#include <asm/api_hook.h>

int main() {
    INIT_FILE_LOG(INFO, "go-probe");

    sigset_t mask = {};
    sigset_t origin_mask = {};

    sigfillset(&mask);

    if (pthread_sigmask(SIG_SETMASK, &mask, &origin_mask) != 0) {
        LOG_ERROR("set signal mask failed");
        return 0;
    }

    if (gBuildInfo->load()) {
        LOG_INFO("go version: %s", gBuildInfo->mVersion.c_str());
    }

    if (!gLineTable->load()) {
        LOG_ERROR("line table load failed");
        return 0;
    }

    if (!gWorkspace->init()) {
        LOG_ERROR("workspace init failed");
        return 0;
    }

    gSmithClient->start();
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
    do_syscall(SYS_exit, 0);

    return 0;
}

#include "go/api/api.h"
#include "asm/api_hook.h"
#include <go/symbol/reader.h>
#include <zero/log.h>
#include <zero/os/procfs.h>
#include <csignal>
#include <z_syscall.h>

constexpr auto LATEST_VERSION = go::Version{1, 20};

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

    ((decltype(quit) *) *address)(status);
}

int main() {
    sigset_t mask = {};
    sigset_t origin_mask = {};

    sigfillset(&mask);

    if (pthread_sigmask(SIG_SETMASK, &mask, &origin_mask) != 0)
        quit(-1);

    INIT_FILE_LOG(zero::INFO_LEVEL, "go-probe");

    std::optional<go::symbol::Reader> reader = go::symbol::openFile("/proc/self/exe");

    if (!reader) {
        LOG_ERROR("load golang binary failed");
        pthread_sigmask(SIG_SETMASK, &origin_mask, nullptr);
        quit(-1);
    }

    std::optional<go::Version> version = reader->version();

    if (!version) {
        LOG_ERROR("get golang version failed");
        pthread_sigmask(SIG_SETMASK, &origin_mask, nullptr);
        quit(-1);
    }

    LOG_INFO("golang version: %d.%d", version->major, version->minor);

    if (*version > LATEST_VERSION) {
        LOG_ERROR("unsupported golang version");
        pthread_sigmask(SIG_SETMASK, &origin_mask, nullptr);
        quit(-1);
    }

    std::optional<zero::os::procfs::Process> process = zero::os::procfs::openProcess(getpid());

    if (!process) {
        LOG_ERROR("open self process failed");
        pthread_sigmask(SIG_SETMASK, &origin_mask, nullptr);
        quit(-1);
    }

    std::optional<zero::os::procfs::MemoryMapping> memoryMapping = process->getImageBase(process->exe()->string());

    if (!memoryMapping) {
        LOG_ERROR("get image base failed");
        pthread_sigmask(SIG_SETMASK, &origin_mask, nullptr);
        quit(-1);
    }

    std::optional<go::symbol::InterfaceTable> interfaceTable = reader->interfaces(memoryMapping->start);

    if (interfaceTable) {
        auto it = std::find_if(interfaceTable->begin(), interfaceTable->end(), [](const auto &interface) {
            return interface.name() == "*errors.errorString";
        });

        if (it != interfaceTable->end()) {
            *go::errors::ErrorString::errorTab() = (void *) it.operator*().address();
        }
    }

    std::optional<go::symbol::SymbolTable> symbolTable = reader->symbols(go::symbol::Attached, memoryMapping->start);

    if (!symbolTable) {
        LOG_ERROR("get symbol table failed");
        pthread_sigmask(SIG_SETMASK, &origin_mask, nullptr);
        quit(-1);
    }

    for (const auto &api: GOLANG_API) {
        for (const auto &symbolEntry: *symbolTable) {
            go::symbol::Symbol symbol = symbolEntry.symbol();

            const char *name = symbol.name();
            void *entry = (void *) symbol.entry();

            if ((api.ignoreCase ? strcasecmp(api.name, name) : strcmp(api.name, name)) == 0) {
                LOG_INFO("hook %s: %p", name, entry);

                if (hookAPI(entry, (void *) api.metadata.entry, api.metadata.origin) < 0) {
                    LOG_WARNING("hook %s failed", name);
                    break;
                }

                break;
            }
        }
    }

    gTarget->version = *version;
    gTarget->symbolTable = std::make_unique<go::symbol::SymbolTable>(std::move(*symbolTable));

    std::thread(startProbe).detach();

    pthread_sigmask(SIG_SETMASK, &origin_mask, nullptr);
    quit(0);

    return 0;
}

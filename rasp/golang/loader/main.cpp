#include <zero/log.h>
#include <csignal>
#include <go/api/api.h>
#include <go/symbol/reader.h>
#include <asm/api_hook.h>
#include <elf/loader.h>

constexpr auto TASK_COMM_LEN = 16;
constexpr auto LATEST_VERSION = go::Version{1, 20};

int main(int argc, char *argv[], char *envp[]) {
    INIT_CONSOLE_LOG(zero::INFO_LEVEL);

    if (argc < 2) {
        LOG_ERROR("require input file");
        return -1;
    }

    elf_context_t ctx[2] = {};

    if (load_elf_file(argv[1], ctx) < 0)
        return -1;

    sigset_t mask = {};
    sigset_t origin_mask = {};

    sigfillset(&mask);

    if (pthread_sigmask(SIG_SETMASK, &mask, &origin_mask) != 0) {
        LOG_ERROR("set signal mask failed");
        return -1;
    }

    std::optional<go::symbol::Reader> reader = go::symbol::openFile(argv[1]);

    if (!reader) {
        LOG_ERROR("load golang binary failed");
        return -1;
    }

    std::optional<go::Version> version = reader->version();

    if (!version) {
        LOG_ERROR("get golang version failed");
        return -1;
    }

    LOG_INFO("golang version: %d.%d", version->major, version->minor);

    if (*version > LATEST_VERSION) {
        LOG_ERROR("unsupported golang version");
        return -1;
    }

    std::optional<go::symbol::InterfaceTable> interfaceTable = reader->interfaces(ctx[0].base);

    if (interfaceTable) {
        auto it = std::find_if(interfaceTable->begin(), interfaceTable->end(), [](const auto &interface) {
            return interface.name() == "*errors.errorString";
        });

        if (it != interfaceTable->end()) {
            *go::errors::ErrorString::errorTab() = (void *) it.operator*().address();
        }
    }

    std::optional<go::symbol::SymbolTable> symbolTable = reader->symbols(go::symbol::FileMapping, ctx[0].base);

    if (!symbolTable) {
        LOG_ERROR("get symbol table failed");
        return -1;
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
    pthread_setname_np(
            pthread_self(),
            std::filesystem::path(argv[1]).filename().string().substr(0, TASK_COMM_LEN - 1).c_str()
    );

    jump_to_entry(ctx, argc - 1, argv + 1, envp);

    return 0;
}

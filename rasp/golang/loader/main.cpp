#include <elf/loader.h>
#include <zero/log.h>
#include <csignal>
#include <go/symbol/build_info.h>
#include <go/symbol/line_table.h>
#include <go/symbol/interface_table.h>
#include <go/api/api.h>
#include <asm/api_hook.h>

/*
 * Usually elf loader does not need to perform relocation work, but we need to hook golang runtime in advance.
 * So we manually resolve relocation entry, just for "R_X86_64_RELATIVE" type.
 * */

constexpr auto TASK_COMM_LEN = 16;

int main(int argc, char **argv, char **envp) {
    INIT_CONSOLE_LOG(zero::INFO);

    if (argc < 2) {
        LOG_ERROR("require input file");
        return -1;
    }

    elf_context_t ctx[2] = {};

    if (load_elf(argv[1], ctx) < 0)
        return -1;

    sigset_t mask = {};
    sigset_t origin_mask = {};

    sigfillset(&mask);

    if (pthread_sigmask(SIG_SETMASK, &mask, &origin_mask) != 0) {
        LOG_ERROR("set signal mask failed");
        return -1;
    }

    if (!gLineTable->load(argv[1], ctx[0].base)) {
        LOG_ERROR("line table load failed");
        return -1;
    }

    if (gBuildInfo->load(argv[1], ctx[0].base)) {
        LOG_INFO("go version: %s", gBuildInfo->mVersion.c_str());

        InterfaceTable table = {};

        if (!table.load(argv[1], ctx[0].base)) {
            LOG_ERROR("interface table load failed");
            return -1;
        }

        table.findByFuncName("errors.(*errorString).Error", (go::interface_item **) APIBase::errorInterface());
    }

    gSmithProbe->start();

    for (const auto &api: GOLANG_API) {
        for (unsigned int i = 0; i < gLineTable->mFuncNum; i++) {
            Func func = {};

            if (!gLineTable->getFunc(i, func))
                break;

            const char *name = func.getName();
            void *entry = (void *) func.getEntry();

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

    pthread_sigmask(SIG_SETMASK, &origin_mask, nullptr);
    pthread_setname_np(
            pthread_self(),
            std::filesystem::path(argv[1]).filename().string().substr(0, TASK_COMM_LEN - 1).c_str()
    );

    ELFIO::elfio reader;

    if (!reader.load(argv[1]))
        return -1;

    if (reader.get_type() != ET_DYN) {
        jump_to_entry(ctx, argc - 1, argv + 1, envp);
        return 0;
    }

    std::vector<ELFIO::segment *> loads;

    std::copy_if(
            reader.segments.begin(),
            reader.segments.end(),
            std::back_inserter(loads),
            [](const auto &i) {
                return i->get_type() == PT_LOAD;
            });

    uintptr_t minVA = std::min_element(
            loads.begin(),
            loads.end(),
            [](const auto &i, const auto &j) {
                return i->get_virtual_address() < j->get_virtual_address();
            }).operator*()->get_virtual_address() & ~(PAGE_SIZE - 1);

    for (const auto &section: reader.sections) {
        if (section->get_type() != SHT_RELA)
            continue;

        ELFIO::relocation_section_accessor relocations(reader, section);

        for (ELFIO::Elf_Xword i = 0; i < relocations.get_entries_num(); i++) {
            ELFIO::Elf64_Addr offset = 0;
            ELFIO::Elf64_Addr symbolValue = 0;
            std::string symbolName;
            ELFIO::Elf_Word type = 0;
            ELFIO::Elf_Sxword addend = 0;
            ELFIO::Elf_Sxword calcValue = 0;

            if (!relocations.get_entry(i, offset, symbolValue, symbolName, type, addend, calcValue)) {
                LOG_ERROR("get relocation entry %lu failed", i);
                return -1;
            }

            if (type != R_X86_64_RELATIVE)
                continue;

            *(size_t *) (ctx[0].base + offset - minVA) = (ctx[0].base + calcValue - minVA);
        }
    }

    jump_to_entry(ctx, argc - 1, argv + 1, envp);

    return 0;
}

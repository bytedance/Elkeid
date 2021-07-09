#include <common/log.h>
#include <common/cmdline.h>
#include <common/utils/process.h>
#include <elfio/elfio.hpp>

typedef int (*PFN_RUN)(const char *command);
typedef int (*PFN_ENSURE)();
typedef void (*PFN_RELEASE)(int);

constexpr auto PYTHON = "bin/python";
constexpr auto PYTHON_LIBRARY = "libpython";
constexpr auto UWSGI = "uwsgi";
constexpr auto PYTHON_CALLER = "python_caller";

int main(int argc, char ** argv) {
    cmdline::parser parse;

    parse.add<int>("pid", 'p', "pid", true, 0);
    parse.add<std::string>("source", 's', "python source file", true, "");
    parse.add<std::string>("pangolin", '\0', "pangolin path", true, "");
    parse.add("file", '\0', "pass source by file");

    parse.parse_check(argc, argv);

    int pid = parse.get<int>("pid");

    CProcessMap processMap;

    if (
            !CProcess::getFileMemoryBase(pid, PYTHON_LIBRARY, processMap) &&
            !CProcess::getFileMemoryBase(pid, PYTHON, processMap) &&
            !CProcess::getFileMemoryBase(pid, UWSGI, processMap)
            ) {
        LOG_ERROR("find target failed");
        return -1;
    }

    LOG_INFO("find target: 0x%lx -> %s", processMap.start, processMap.file.c_str());

    std::string path = CPath::join("/proc", std::to_string(pid), "root", processMap.file);

    ELFIO::elfio reader;

    if (!reader.load(path)) {
        LOG_ERROR("open elf failed: %s", path.c_str());
        return -1;
    }

    auto it = std::find_if(
            reader.sections.begin(),
            reader.sections.end(),
            [](const auto& s) {
                return s->get_type() == SHT_DYNSYM;
            });

    if (it == reader.sections.end()) {
        LOG_ERROR("can't find symbol section");
        return -1;
    }

    unsigned long baseAddress = 0;

    if (reader.get_type() != ET_EXEC) {
        auto sit = std::find_if(
                reader.segments.begin(),
                reader.segments.end(),
                [](const auto& s) {
                    return s->get_type() == PT_LOAD;
                });

        if (sit == reader.segments.end()) {
            LOG_ERROR("can't find load segment");
            return -1;
        }

        baseAddress = processMap.start - (*sit)->get_virtual_address();
    }

    PFN_ENSURE pfnEnsure = nullptr;
    PFN_RUN pfnRun = nullptr;
    PFN_RELEASE pfnRelease = nullptr;

    ELFIO::symbol_section_accessor symbols(reader, *it);

    for (ELFIO::Elf_Xword i = 0; i < symbols.get_symbols_num(); i++) {
        std::string name;
        ELFIO::Elf64_Addr value = 0;
        ELFIO::Elf_Xword size = 0;
        unsigned char bind = 0;
        unsigned char type = 0;
        ELFIO::Elf_Half section = 0;
        unsigned char other = 0;

        if (!symbols.get_symbol(i, name, value, size, bind, type, section, other)) {
            LOG_ERROR("get symbol %lu failed", i);
            return -1;
        }

        if (name == "PyGILState_Ensure")
            pfnEnsure = (PFN_ENSURE)(baseAddress + value);
        else if (name == "PyRun_SimpleString")
            pfnRun = (PFN_RUN)(baseAddress + value);
        else if (name == "PyGILState_Release")
            pfnRelease = (PFN_RELEASE)(baseAddress + value);
    }

    if (!pfnEnsure || !pfnRun || !pfnRelease) {
        LOG_ERROR("can't find python symbols");
        return -1;
    }

    LOG_INFO("ensure func: %p run func: %p release func: %p", pfnEnsure, pfnRun, pfnRelease);

    std::string source = parse.get<std::string>("source");
    std::string pangolin = parse.get<std::string>("pangolin");
    std::string caller = CPath::join(CPath::getAPPDir(), PYTHON_CALLER);

    char callerCommand[1024] = {};

    snprintf(
            callerCommand, sizeof(callerCommand),
            "%s %s %d %p %p %p",
            caller.c_str(), source.c_str(), parse.exist("file"),
            pfnEnsure, pfnRun, pfnRelease
            );

    int err = execl(
            pangolin.c_str(), pangolin.c_str(),
            "-c", callerCommand,
            "-p", std::to_string(pid).c_str(),
            nullptr
            );

    if (err < 0) {
        LOG_ERROR("exec pangolin failed: %s", strerror(errno));
        return -1;
    }

    return 0;
}

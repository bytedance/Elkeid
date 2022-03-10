#include <unistd.h>
#include <zero/log.h>
#include <zero/cmdline.h>
#include <zero/proc/process.h>
#include <elfio/elfio.hpp>
#include <sys/user.h>
#include <elf.h>
#include <trap/trap.h>

using EvalFramePtr = void *(*)(void *, void *, void *);
using EvalStringPtr = int (*)(const char *);

constexpr auto UWSGI_IMAGE = "uwsgi";
constexpr auto PYTHON_IMAGE = "bin/python";
constexpr auto PYTHON_LIBRARY_IMAGE = "libpython";

constexpr auto EVAL_STRING_SYMBOL = "PyRun_SimpleString";
constexpr auto EVAL_FRAME_SYMBOL = "PyEval_EvalFrameEx";
constexpr auto EVAL_FRAME_DEFAULT_SYMBOL = "_PyEval_EvalFrameDefault";

static EvalFramePtr origin = nullptr;
static EvalStringPtr eval = nullptr;

static int guard = 0;
static char code[10240] = {};

void *entry(void *x, void *y, void *z) {
    if (!guard && __sync_bool_compare_and_swap(&guard, 0, 1))
        eval(code);

    return origin(x, y, z);
}

int main(int argc, char ** argv) {
    INIT_CONSOLE_LOG(zero::ERROR);

    zero::CCmdline cmdline;

    cmdline.add({"script", "python script", zero::value<std::string>()});
    cmdline.addOptional({"file", 'f', "load script from file", zero::value<bool>(), true});

    cmdline.parse(argc, argv);

    bool file = cmdline.getOptional<bool>("file");
    std::string script = cmdline.get<std::string>("script");

    if (file) {
        std::ifstream stream(script);

        if (!stream.is_open()) {
            LOG_ERROR("script does not exist");
            return -1;
        }

        script = {std::istreambuf_iterator<char>(stream), std::istreambuf_iterator<char>()};
    }

    if (script.length() >= sizeof(code)) {
        LOG_ERROR("script length limit");
        return -1;
    }

    strcpy(code, script.data());

    pid_t pid = getpid();
    zero::proc::CProcessMapping processMapping;

    if (
            !zero::proc::getImageBase(pid, PYTHON_LIBRARY_IMAGE, processMapping) &&
            !zero::proc::getImageBase(pid, PYTHON_IMAGE, processMapping) &&
            !zero::proc::getImageBase(pid, UWSGI_IMAGE, processMapping)
            ) {
        LOG_ERROR("can't find python image base");
        return -1;
    }

    LOG_INFO("python image base: 0x%lx", processMapping.start);

    std::string path = zero::filesystem::path::join("/proc/self/root", processMapping.pathname);

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

    unsigned long base = 0;

    if (reader.get_type() != ET_EXEC) {
        std::vector<ELFIO::segment *> loads;

        std::copy_if(
                reader.segments.begin(),
                reader.segments.end(),
                std::back_inserter(loads),
                [](const auto &i){
                    return i->get_type() == PT_LOAD;
                });

        auto minElement = std::min_element(
                loads.begin(),
                loads.end(),
                [](const auto &i, const auto &j) {
                    return i->get_virtual_address() < j->get_virtual_address();
                });

        base = processMapping.start - ((*minElement)->get_virtual_address() & ~(PAGE_SIZE - 1));
    }

    ELFIO::symbol_section_accessor symbols(reader, *it);

    ELFIO::Elf64_Addr value = 0;
    ELFIO::Elf_Xword size = 0;
    unsigned char bind = 0;
    unsigned char type = 0;
    ELFIO::Elf_Half section = 0;
    unsigned char other = 0;

    if (!symbols.get_symbol(EVAL_STRING_SYMBOL, value, size, bind, type, section, other)) {
        LOG_ERROR("find eval string symbol failed");
        return -1;
    }

    eval = (EvalStringPtr)(base + value);

    if (!symbols.get_symbol(EVAL_FRAME_DEFAULT_SYMBOL, value, size, bind, type, section, other) &&
        !symbols.get_symbol(EVAL_FRAME_SYMBOL, value, size, bind, type, section, other)) {
        LOG_ERROR("find eval frame symbol failed");
        return -1;
    }

    LOG_INFO("eval frame address: 0x%lx", base + value);

    if (hook((void *)(base + value), (void *)entry, (void **)&origin) < 0) {
        LOG_ERROR("hook eval frame failed");
        return -1;
    }

    return 0;
}

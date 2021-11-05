#include "loader.h"
#include <unistd.h>
#include <sys/mman.h>
#include <zero/log.h>
#include <elf.h>

/*
 * Usually elf loader does not need to perform relocation work, but we need to hook golang runtime in advance.
 * So we manually resolve relocation entry, just for "R_X86_64_RELATIVE" type.
 * */

constexpr auto STACK_ALIGN = 16;
constexpr auto AV_PATH = "/proc/self/auxv";

CELFLoader::CELFLoader() {
    mPagesize = sysconf(_SC_PAGESIZE);
}

bool CELFLoader::load(const std::string &file) {
    ELFIO::elfio reader;

    if (!reader.load(file))
        return false;

    auto it = std::find_if(
            reader.segments.begin(),
            reader.segments.end(),
            [](const auto& s) {
                return s->get_type() == PT_INTERP;
            });

    if (it != reader.segments.end()) {
        const char * interpreter = (*it)->get_data();

        if (!loadInterpreter(interpreter)) {
            LOG_ERROR("load interpreter failed: %s", interpreter);
            return false;
        }
    }

    LOG_INFO("load program: %s", file.c_str());

    CELFImage image = {};

    if (!loadSegments(reader, image))
        return false;

    mProgramBase = image.base;
    mProgramEntry = image.base + reader.get_entry() - image.minVA;
    mProgramHeader = mProgramBase + reader.get_segments_offset();
    mProgramHeaderNum = reader.segments.size();
    mProgramHeaderSize = reader.get_segment_entry_size();

    if (reader.get_type() != ET_DYN)
        return true;

    for (const auto &section : reader.sections) {
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

            *(unsigned long *)((unsigned long)image.base + offset - image.minVA) = ((unsigned long)image.base + calcValue - image.minVA);
        }
    }

    return true;
}

unsigned long CELFLoader::roundPage(unsigned long address) const {
    return (address + mPagesize - 1) & ~(mPagesize - 1);
}

unsigned long CELFLoader::truncatePage(unsigned long address) const {
    return address & ~(mPagesize - 1);
}

bool CELFLoader::loadInterpreter(const char *interpreter) {
    LOG_INFO("load interpreter: %s", interpreter);

    ELFIO::elfio reader;

    if (!reader.load(interpreter))
        return false;

    CELFImage image = {};

    if (!loadSegments(reader, image))
        return false;

    mInterpreterBase = image.base;
    mInterpreterEntry = image.base + reader.get_entry() - image.minVA;

    return true;
}

bool CELFLoader::loadSegments(const ELFIO::elfio &reader, CELFImage &image) {
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

    auto maxElement = std::max_element(
            loads.begin(),
            loads.end(),
            [](const auto &i, const auto &j) {
                return i->get_virtual_address() < j->get_virtual_address();
            });

    bool dyn = reader.get_type() == ET_DYN;

    unsigned long minVA = truncatePage((*minElement)->get_virtual_address());
    unsigned long maxVA = roundPage((*maxElement)->get_virtual_address() + (*maxElement)->get_memory_size());

    void *base = mmap(
            dyn ? nullptr : (void *)minVA,
            maxVA - minVA,
            PROT_NONE,
            (dyn ? 0 : MAP_FIXED) | MAP_PRIVATE | MAP_ANONYMOUS,
            -1,
            0);

    if (base == MAP_FAILED) {
        LOG_ERROR("mmap failed: %s", strerror(errno));
        return false;
    }

    munmap(base, maxVA - minVA);

    LOG_INFO("segment base: %p[0x%lx]", base, maxVA - minVA);

    for (const auto &segment : loads) {
        unsigned long offset = segment->get_virtual_address() & (mPagesize - 1);
        unsigned long start = (unsigned long)base + truncatePage(segment->get_virtual_address()) - minVA;
        unsigned long size = roundPage(segment->get_memory_size() + offset);

        LOG_INFO("segment: 0x%lx[0x%lx]", start, size);

        void *p = mmap(
                (void *)start,
                size,
                PROT_WRITE,
                MAP_FIXED | MAP_ANONYMOUS | MAP_PRIVATE,
                -1,
                0);

        if (p == MAP_FAILED) {
            LOG_ERROR("mmap failed: %s", strerror(errno));

            munmap(base, maxVA - minVA);
            return false;
        }

        memcpy((unsigned char *)p + offset, segment->get_data(), segment->get_file_size());

        unsigned int flags = segment->get_flags();
        int protection = (flags & PF_R ? PROT_READ : 0) | (flags & PF_W ? PROT_WRITE : 0) | (flags & PF_X ? PROT_EXEC : 0);

        if (mprotect(p, size, protection) == -1) {
            LOG_ERROR("change memory protection failed: %s", strerror(errno));

            munmap(base, maxVA - minVA);
            return false;
        }
    }

    image = {
            (unsigned long)base,
            minVA,
            maxVA
    };

    return true;
}

void CELFLoader::jump(int argc, char **argv, char **env) {
    std::ifstream stream = std::ifstream(AV_PATH);
    std::vector<char> av((std::istreambuf_iterator<char>(stream)), std::istreambuf_iterator<char>());

    for (auto *i = (Elf64_auxv_t *)av.data(); i->a_type != AT_NULL; i++) {
        switch (i->a_type) {
            case AT_PHDR:
                i->a_un.a_val = mProgramHeader;
                break;

            case AT_PHENT:
                i->a_un.a_val = mProgramHeaderSize;
                break;

            case AT_PHNUM:
                i->a_un.a_val = mProgramHeaderNum;
                break;

            case AT_BASE:
                i->a_un.a_val = mInterpreterBase ? mInterpreterBase : 0;
                break;

            case AT_ENTRY:
                i->a_un.a_val = mProgramEntry;
                break;

            case AT_EXECFN:
                i->a_un.a_val = (unsigned long)argv[0];
                break;
        }
    }

    unsigned char buffer[4096] = {};
    unsigned long entry = mInterpreterEntry ? mInterpreterEntry : mProgramEntry;

    auto stack = (unsigned char *)(((unsigned long)buffer + STACK_ALIGN - 1) & ~(STACK_ALIGN - 1));
    auto p = (unsigned long *)stack;

    *(int *)p++ = argc;

    for (int i = 0; i < argc; i++)
        *(char **)p++ = argv[i];

    *(char **)p++ = nullptr;

    for (char ** i = env; *i; i++)
        *(char **)p++ = *i;

    *(char **)p++ = nullptr;

    memcpy(p, av.data(), av.size());

#ifdef __i386__
    asm volatile("mov %0, %%esp; xor %%edx, %%edx; jmp *%1;" :: "r"(stack), "a"(entry));
#elif __x86_64__
    asm volatile("mov %0, %%rsp; xor %%rdx, %%rdx; jmp *%1;" :: "r"(stack), "a"(entry));
#elif __arm__
    asm volatile("mov %%sp, %0; mov %%r0, #0; bx %[func];" :: "r"(stack), [func] "r"(entry));
#elif __aarch64__
    asm volatile("mov sp, %[stack]; mov w0, #0; br %[func];" :: [stack] "r"(stack), [func] "r"(entry));
#else
#error "unknown arch"
#endif
}

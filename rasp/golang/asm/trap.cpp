#include "trap.h"
#include <Zydis/Zydis.h>
#include <zero/log.h>
#include <sys/mman.h>

#ifndef PAGE_SIZE
#define PAGE_SIZE       0x1000
#endif

#define ROUND_PG(x)     (((x) + (PAGE_SIZE - 1)) & ~(PAGE_SIZE - 1))
#define TRUNC_PG(x)     ((x) & ~(PAGE_SIZE - 1))

/*
 * jump template:
 *      jmp *0(%rip)
 *      .dq address
 * */

constexpr unsigned char JUMP_TEMPLATE[] = {
        0xFF, 0x25, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

constexpr auto GUIDE = 6;
constexpr auto JUMP_SIZE = sizeof(JUMP_TEMPLATE);

static int setProtection(void *address, size_t length, int protection) {
    uintptr_t start = TRUNC_PG((uintptr_t)address);
    uintptr_t end = ROUND_PG((uintptr_t)address + length);

    if (mprotect((void *)start, end - start, protection) < 0) {
        LOG_ERROR("change memory protection failed: %s", strerror(errno));
        return -1;
    }

    return 0;
}

int hook(void *address, void *replace, void **backup) {
    ZydisDecoder decoder = {};

    if (!ZYAN_SUCCESS(ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_ADDRESS_WIDTH_64))) {
        LOG_ERROR("init decoder failed");
        return -1;
    }

    ZydisDecodedInstruction instruction = {};
    ZyanUSize length = ZYDIS_MAX_INSTRUCTION_LENGTH + JUMP_SIZE;

    unsigned int tail = 0;

    do {
        if (!ZYAN_SUCCESS(ZydisDecoderDecodeBuffer(&decoder, (char *)address + tail, length - tail, &instruction))) {
            LOG_ERROR("decode buffer failed");
            return -1;
        }

        if (instruction.attributes & ZYDIS_ATTRIB_IS_RELATIVE) {
            LOG_ERROR("position relative instruction: %p", (char *)address + tail);
            return -1;
        }

        tail += instruction.length;
    } while (tail < JUMP_SIZE);

    std::unique_ptr<char> escape(new char[tail + JUMP_SIZE]());

    if (setProtection(escape.get(), tail + JUMP_SIZE, PROT_READ | PROT_WRITE | PROT_EXEC) < 0)
        return -1;

    memcpy(escape.get(), address, tail);
    memcpy(escape.get() + tail, JUMP_TEMPLATE, JUMP_SIZE);

    *(void **)(escape.get() + tail + GUIDE) = (char *)address + tail;

    if (setProtection(address, JUMP_SIZE, PROT_READ | PROT_WRITE | PROT_EXEC) < 0)
        return -1;

    memcpy(address, JUMP_TEMPLATE, JUMP_SIZE);
    *(void **)((char *)address + GUIDE) = replace;

    if (setProtection(address, JUMP_SIZE, PROT_READ | PROT_EXEC) < 0)
        return -1;

    *backup = escape.release();

    return 0;
}

int unhook(void *address, void *backup) {
    if (memcmp(address, JUMP_TEMPLATE, GUIDE) != 0) {
        LOG_ERROR("invalid trap magic");
        return -1;
    }

    if (setProtection(address, JUMP_SIZE, PROT_READ | PROT_WRITE | PROT_EXEC) < 0)
        return -1;

    memcpy(address, backup, JUMP_SIZE);
    delete [](char *)backup;

    if (setProtection(address, JUMP_SIZE, PROT_READ | PROT_EXEC) < 0)
        return -1;

    return 0;
}
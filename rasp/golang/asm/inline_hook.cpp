#include "inline_hook.h"
#include <zero/log.h>
#include <sys/mman.h>
#include <unistd.h>

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

CInlineHook::CInlineHook() {
    mPagesize = sysconf(_SC_PAGESIZE);
    ZydisDecoderInit(&mDecoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_ADDRESS_WIDTH_64);
}

unsigned long CInlineHook::getCodeTail(void *address) {
    ZydisDecodedInstruction instruction = {};
    ZyanUSize length = ZYDIS_MAX_INSTRUCTION_LENGTH + JUMP_SIZE;

    unsigned long tail = 0;

    do {
        if (!ZYAN_SUCCESS(ZydisDecoderDecodeBuffer(&mDecoder, (char *)address + tail, length - tail, &instruction))) {
            LOG_ERROR("decode failed");
            return 0;
        }

        if (instruction.attributes & ZYDIS_ATTRIB_IS_RELATIVE) {
            LOG_ERROR("position relative instruction: %p", (char *)address + tail);
            return 0;
        }

        tail += instruction.length;

    } while (tail < JUMP_SIZE);

    return tail;
}

bool CInlineHook::hook(void *address, void *replace, void **backup) {
    unsigned long tail = getCodeTail(address);

    if (tail == 0) {
        LOG_ERROR("get code tail failed");
        return false;
    }

    std::unique_ptr<char> escape(new char[tail + JUMP_SIZE]());

    if (!setCodeWriteable(escape.get(), tail + JUMP_SIZE))
        return false;

    memcpy(escape.get(), address, tail);
    memcpy(escape.get() + tail, JUMP_TEMPLATE, JUMP_SIZE);

    *(void **)(escape.get() + tail + GUIDE) = (char *)address + tail;

    if (!setCodeWriteable(address, JUMP_SIZE))
        return false;

    memcpy(address, JUMP_TEMPLATE, JUMP_SIZE);
    *(void **)((char *)address + GUIDE) = replace;

    *backup = escape.release();

    return true;
}

bool CInlineHook::unhook(void *address, void *backup) {
    if (memcmp(address, JUMP_TEMPLATE, GUIDE) != 0) {
        LOG_ERROR("trap magic error");
        return false;
    }

    if (!setCodeWriteable(address, JUMP_SIZE))
        return false;

    memcpy(address, backup, JUMP_SIZE);

    delete [](char*)backup;

    return true;
}

bool CInlineHook::setCodeReadonly(void *address, unsigned long size) const {
    unsigned long start = (unsigned long)address & ~(mPagesize - 1);
    unsigned long end = ((unsigned long)address + size + mPagesize) & ~(mPagesize - 1);

    if (mprotect((void *)start, end - start, PROT_READ | PROT_EXEC) < 0) {
        LOG_ERROR("set code page readonly attr failed");
        return false;
    }

    return true;
}

bool CInlineHook::setCodeWriteable(void *address, unsigned long size) const {
    unsigned long start = (unsigned long)address & ~(mPagesize - 1);
    unsigned long end = ((unsigned long)address + size + mPagesize) & ~(mPagesize - 1);

    if (mprotect((void *)start, end - start, PROT_READ | PROT_WRITE | PROT_EXEC) < 0) {
        LOG_ERROR("set code page writeable attr failed");
        return false;
    }

    return true;
}

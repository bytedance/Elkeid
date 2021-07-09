#include "api_hook.h"
#include <common/log.h>

constexpr auto MAX_OFFSET = 100;

bool CAPIHook::hook(void *address, void *replace, void **backup) {
    void *exactAddress = getExactAddress(address);

    if (!exactAddress) {
        LOG_ERROR("get exact address failed");
        return false;
    }

    return CInlineHook::hook(exactAddress, replace, backup);
}

bool CAPIHook::unhook(void *address, void *backup) {
    void *exactAddress = getExactAddress(address);

    if (!exactAddress) {
        LOG_ERROR("get exact address failed");
        return false;
    }

    return CInlineHook::unhook(exactAddress, backup);
}

void *CAPIHook::getExactAddress(void *address) {
    ZydisDecodedInstruction instruction = {};

    unsigned long offset = 0;

    while (true) {
        if (!ZYAN_SUCCESS(ZydisDecoderDecodeBuffer(&mDecoder, (char *)address + offset, ZYDIS_MAX_INSTRUCTION_LENGTH, &instruction))) {
            LOG_ERROR("decode failed");
            return nullptr;
        }

        if (instruction.mnemonic == ZYDIS_MNEMONIC_SUB)
            break;

        offset += instruction.length;

        if (offset > MAX_OFFSET) {
            LOG_ERROR("max offset limit");
            return nullptr;
        }
    }

    return (char *)address + offset;
}

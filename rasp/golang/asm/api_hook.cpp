#include "api_hook.h"
#include "trap.h"
#include <zero/log.h>
#include <Zydis/Zydis.h>

constexpr auto MAX_OFFSET = 100;

int hookAPI(void *address, void *replace, void **backup) {
    ZydisDecoder decoder = {};

    if (!ZYAN_SUCCESS(ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_ADDRESS_WIDTH_64))) {
        LOG_ERROR("init decoder failed");
        return -1;
    }

    ZydisDecodedInstruction instruction = {};

    int offset = 0;

    while (true) {
        if (!ZYAN_SUCCESS(ZydisDecoderDecodeBuffer(&decoder, (char *)address + offset, ZYDIS_MAX_INSTRUCTION_LENGTH, &instruction))) {
            LOG_ERROR("decode failed");
            return -1;
        }

        if ((instruction.mnemonic == ZYDIS_MNEMONIC_SUB || instruction.mnemonic == ZYDIS_MNEMONIC_ADD) && instruction.operands[0].reg.value == ZYDIS_REGISTER_RSP)
            break;

        offset += instruction.length;

        if (offset > MAX_OFFSET) {
            LOG_ERROR("max offset limit");
            return -1;
        }
    }

    return hook((char *)address + offset, replace, backup);
}

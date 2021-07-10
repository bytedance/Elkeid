#include "func.h"
#include "line_table.h"
#include <cstring>
#include <algorithm>

constexpr auto STACK_TOP_FUNCTION = {
        "runtime.mstart",
        "runtime.rt0_go",
        "runtime.mcall",
        "runtime.morestack",
        "runtime.lessstack",
        "runtime.asmcgocall",
        "runtime.externalthreadhandler",
        "runtime.goexit"
};

const char *CFunction::getName() const {
    return &mLineTable->mFuncNameTable[mFuncInfo->name_offset];
}

void *CFunction::getEntry() const {
    return (void *)mFuncInfo->entry;
}

int CFunction::getFrameSize(void *pc) const {
    if (mFuncInfo->pc_sp == 0)
        return 0;

    int x = getPCValue(mFuncInfo->pc_sp, pc);

    if (x == -1)
        return 0;

    if ((x & (mLineTable->mPtrSize - 1)) != 0)
        return 0;

    return x;
}

int CFunction::getSourceLine(void *pc) const {
    return getPCValue(mFuncInfo->pc_line, pc);
}

const char *CFunction::getSourceFile(void *pc) const {
    int fileNo = getPCValue(mFuncInfo->pc_file, pc);

    if (fileNo == -1 || fileNo > mLineTable->mFileNum)
        return "";

    if (mLineTable->mVersion == emVersion12)
        return &mLineTable->mFuncData[*(int *)&mLineTable->mFileTable[fileNo * 4]];

    auto cuOffset = ((go::func_info_v116*)mFuncInfo)->cu_offset;
    auto fnOffset = *(int *)&mLineTable->mCuTable[(cuOffset + fileNo) * 4];

    return &mLineTable->mFileTable[fnOffset];
}

bool CFunction::isStackTop() const {
    auto name = getName();

    return std::any_of(STACK_TOP_FUNCTION.begin(), STACK_TOP_FUNCTION.end(), [=](const auto& f) {
        return strcmp(f, name) == 0;
    });
}

unsigned int CFunction::readVarInt(const unsigned char **pp) {
    unsigned int v = 0;
    unsigned int shift = 0;

    const unsigned char *p = *pp;

    while (true) {
        unsigned int b = *p++;
        v |= (b & 0x7F) << shift;

        if ((b & 0x80) == 0)
            break;

        shift += 7;
    }

    *pp = p;

    return v;
}

bool CFunction::step(const unsigned char **p, unsigned long *pc, int *val, bool first) const {
    auto uv_delta = readVarInt(p);

    if (uv_delta == 0 && !first)
        return false;

    if ((uv_delta & 1) != 0) {
        uv_delta = ~(uv_delta >> 1);
    } else {
        uv_delta >>= 1;
    }

    auto v_delta = (int)uv_delta;
    unsigned long pc_delta = readVarInt(p) * mLineTable->mQuantum;

    *pc += pc_delta;
    *val += v_delta;

    return true;
}

int CFunction::getPCValue(int offset, void *targetPC) const {
    const unsigned char *p = (unsigned char *)&mLineTable->mPCTable[offset];

    int val = -1;
    auto entry = mFuncInfo->entry;
    auto pc = entry;

    while (step(&p, &pc, &val, pc == entry)) {
        if ((unsigned long)targetPC < pc) {
            return val;
        }
    }

    return -1;
}

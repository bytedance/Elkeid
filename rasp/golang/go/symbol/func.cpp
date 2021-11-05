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

CFuncTablePtr::CFuncTablePtr(const char *table, unsigned int size) {
    mTable = table;
    mSize = size;
}

CFuncTablePtr &CFuncTablePtr::operator++() {
    mTable += 2 * mSize;
    return *this;
}

CFuncTablePtr CFuncTablePtr::operator+(unsigned int offset) {
    return CFuncTablePtr(mTable + offset * 2 * mSize, mSize);
}

CFuncTablePtr CFuncTablePtr::operator-(unsigned int offset) {
    return CFuncTablePtr(mTable - offset * 2 * mSize, mSize);
}

const CFuncEntry &CFuncTablePtr::operator*() {
    auto peek = [&](const char *address) -> uint64_t {
        if (mSize == 4)
            return *(uint32_t *)address;

        return *(uint64_t *)address;
    };

    mEntry.entry = (uintptr_t)peek(mTable);
    mEntry.offset = (unsigned long)peek(mTable + mSize);

    return mEntry;
}

const CFuncEntry *CFuncTablePtr::operator->() {
    return &operator*();
}

CFuncEntry CFuncTablePtr::operator[](unsigned int index) {
    return *operator+(index);
}

bool CFuncTablePtr::operator==(const CFuncTablePtr &ptr) {
    return mTable == ptr.mTable;
}

bool CFuncTablePtr::operator!=(const CFuncTablePtr &ptr) {
    return mTable != ptr.mTable;
}

uintptr_t CFunc::getEntry() const {
    if (mLineTable->mVersion < VERSION118)
        return *(uintptr_t *)mFuncData;

    return mLineTable->mTextStart + *(unsigned int *)mFuncData;
}

const char *CFunc::getName() const {
    return &mLineTable->mFuncNameTable[getNameOffset()];
}

int CFunc::getFrameSize(uintptr_t pc) const {
    unsigned int sp = getPCSp();

    if (sp == 0)
        return 0;

    int x = mLineTable->getPCValue(sp, getEntry(), pc);

    if (x == -1)
        return 0;

    if ((x & (mLineTable->mPtrSize - 1)) != 0)
        return 0;

    return x;
}

int CFunc::getSourceLine(uintptr_t pc) const {
    return mLineTable->getPCValue(getPCLine(), getEntry(), pc);
}

const char *CFunc::getSourceFile(uintptr_t pc) const {
    int n = mLineTable->getPCValue(getPCFile(), getEntry(), pc);

    if (n == -1 || n > mLineTable->mFileNum)
        return "";

    if (mLineTable->mVersion == VERSION12)
        return &mLineTable->mFuncData[*(int *)&mLineTable->mFileTable[n * 4]];

    unsigned int offset = *(unsigned int *)&mLineTable->mCuTable[(getCuOffset() + n) * 4];

    if (!offset)
        return "";

    return &mLineTable->mFileTable[offset];

}

bool CFunc::isStackTop() const {
    const char *name = getName();

    return std::any_of(STACK_TOP_FUNCTION.begin(), STACK_TOP_FUNCTION.end(), [=](const auto& f) {
        return strcmp(f, name) == 0;
    });
}

unsigned int CFunc::field(unsigned int n) const {
    unsigned int size = mLineTable->mVersion >= VERSION118 ? 4 : mLineTable->mPtrSize;
    return *(unsigned int *)&mFuncData[size + (n - 1) * 4];
}

unsigned int CFunc::getNameOffset() const {
    return field(1);
}

unsigned int CFunc::getPCSp() const {
    return field(4);
}

unsigned int CFunc::getPCFile() const {
    return field(5);
}

unsigned int CFunc::getPCLine() const {
    return field(6);
}

unsigned int CFunc::getCuOffset() const {
    return field(8);
}

#include "line_table.h"
#include <common/log.h>
#include <common/utils/path.h>
#include <common/utils/process.h>
#include <elfio/elfio.hpp>

constexpr auto GO_LINE_TABLE = "gopclntab";

constexpr auto LINE_TABLE_MAGIC_12 = 0xFFFFFFFB;
constexpr auto LINE_TABLE_MAGIC_116 = 0xFFFFFFFA;

bool CLineTable::load(const char *lineTable) {
    mQuantum = (unsigned char)lineTable[6];
    mPtrSize = (unsigned char)lineTable[7];

    auto magic = *(unsigned int *)lineTable;

    switch (magic) {
        case LINE_TABLE_MAGIC_12: {
            mVersion = emVersion12;

            mFuncNum = peek(&lineTable[8]);
            mFuncData = lineTable;
            mFuncNameTable = lineTable;
            mFuncTable = &lineTable[8 + mPtrSize];
            mPCTable = lineTable;

            unsigned long funcTableSize = mFuncNum * 2 * mPtrSize + mPtrSize;
            unsigned long fileOffset = *(unsigned int *)&mFuncTable[funcTableSize];

            mFileTable = &lineTable[fileOffset];
            mFileNum = *(unsigned int *)mFileTable;

            break;
        }

        case LINE_TABLE_MAGIC_116: {
            mVersion = emVersion116;

            mFuncNum = peek(&lineTable[8]);
            mFileNum = peek(&lineTable[8 + mPtrSize]);

            mFuncNameTable = &lineTable[peek(&lineTable[8 + 2 * mPtrSize])];
            mCuTable = &lineTable[peek(&lineTable[8 + 3 * mPtrSize])];
            mFileTable = &lineTable[peek(&lineTable[8 + 4 * mPtrSize])];
            mPCTable = &lineTable[peek(&lineTable[8 + 5 * mPtrSize])];
            mFuncData = &lineTable[peek(&lineTable[8 + 6 * mPtrSize])];
            mFuncTable = &lineTable[peek(&lineTable[8 + 6 * mPtrSize])];

            break;
        }

        default:
            return false;
    }

    return true;
}

unsigned long CLineTable::peek(const char *address) const {
    if (mPtrSize == 4) {
        return *(unsigned int *)address;
    }

    return *(unsigned long *)address;
}

bool CLineTable::load() {
    return load(CPath::getAPPPath());
}

bool CLineTable::load(const std::string &file) {
    ELFIO::elfio reader;

    if (!reader.load(file))
        return false;

    auto it = std::find_if(
            reader.sections.begin(),
            reader.sections.end(),
            [](const auto& s) {
                return CStringHelper::findStringIC(s->get_name(), GO_LINE_TABLE);
            });

    if (it == reader.sections.end()) {
        LOG_ERROR("can't find line table section");
        return false;
    }

    if (reader.get_type() == ET_EXEC)
        return load((char *)(*it)->get_address());

    CProcessMap processMap;

    if (!CProcess::getFileMemoryBase(getpid(), file, processMap))
        return false;

    auto sit = std::find_if(
            reader.segments.begin(),
            reader.segments.end(),
            [](const auto& s) {
                return s->get_type() == PT_LOAD;
            });

    if (sit == reader.segments.end())
        return false;

    return load((char *)processMap.start - (*sit)->get_virtual_address() + (*it)->get_address());
}

const go::func_item *CLineTable::getFuncItem(unsigned long index) const {
    return &((go::func_item *)mFuncTable)[index];
}

const go::func_info *CLineTable::getFuncInfo(unsigned long index) const {
    return (go::func_info *)&mFuncData[getFuncItem(index)->func_offset];
}

bool CLineTable::findFunc(void *pc, CFunction &func) {
    auto address = (unsigned long)pc;

    auto begin = getFuncItem(0);
    auto back = getFuncItem(mFuncNum);
    auto end = back + 1;

    if (address < begin->entry || address >= back->entry)
        return false;

    auto it = std::upper_bound(begin, end, address, [](auto addr, const auto& i) {
       return addr < i.entry;
    });

    if (it == end)
        return false;

    func.mLineTable = this;
    func.mFuncInfo = (go::func_info *)&mFuncData[(it - 1)->func_offset];

    return true;
}

bool CLineTable::getFunc(unsigned long index, CFunction &func) {
    if (index >= mFuncNum)
        return false;

    func.mLineTable = this;
    func.mFuncInfo = getFuncInfo(index);

    return true;
}

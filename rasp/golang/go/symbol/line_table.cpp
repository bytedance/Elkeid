#include "line_table.h"
#include <common/log.h>
#include <common/utils/process.h>
#include <elfio/elfio.hpp>
#include <sys/user.h>

constexpr auto GO_LINE_TABLE = "gopclntab";

constexpr auto LINE_TABLE_MAGIC_12 = 0xFFFFFFFB;
constexpr auto LINE_TABLE_MAGIC_116 = 0xFFFFFFFA;

bool CLineTable::load(const char *table) {
    mQuantum = (unsigned char)table[6];
    mPtrSize = (unsigned char)table[7];

    auto magic = *(unsigned int *)table;

    switch (magic) {
        case LINE_TABLE_MAGIC_12: {
            mVersion = emVersion12;

            mFuncNum = peek(&table[8]);
            mFuncData = table;
            mFuncNameTable = table;
            mFuncTable = &table[8 + mPtrSize];
            mPCTable = table;

            unsigned long funcTableSize = mFuncNum * 2 * mPtrSize + mPtrSize;
            unsigned long fileOffset = *(unsigned int *)&mFuncTable[funcTableSize];

            mFileTable = &table[fileOffset];
            mFileNum = *(unsigned int *)mFileTable;

            break;
        }

        case LINE_TABLE_MAGIC_116: {
            mVersion = emVersion116;

            mFuncNum = peek(&table[8]);
            mFileNum = peek(&table[8 + mPtrSize]);

            mFuncNameTable = &table[peek(&table[8 + 2 * mPtrSize])];
            mCuTable = &table[peek(&table[8 + 3 * mPtrSize])];
            mFileTable = &table[peek(&table[8 + 4 * mPtrSize])];
            mPCTable = &table[peek(&table[8 + 5 * mPtrSize])];
            mFuncData = &table[peek(&table[8 + 6 * mPtrSize])];
            mFuncTable = &table[peek(&table[8 + 6 * mPtrSize])];

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
    CProcessMap processMap;

    if (!CProcess::getFileMemoryBase(getpid(), file, processMap))
        return false;

    return load(file, processMap.start);
}

bool CLineTable::load(const std::string &file, unsigned long base) {
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

    return load((char *)base + (*it)->get_address() - ((*minElement)->get_virtual_address() & ~(PAGE_SIZE - 1)));
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

    auto it = std::upper_bound(begin, end, address, [](auto value, const auto& i) {
       return value < i.entry;
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

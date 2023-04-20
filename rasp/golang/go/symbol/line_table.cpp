#include "line_table.h"
#include <zero/log.h>
#include <zero/proc/process.h>
#include <zero/filesystem/path.h>
#include <elfio/elfio.hpp>
#include <sys/user.h>
#include <unistd.h>

constexpr auto GO_LINE_TABLE = "gopclntab";

constexpr auto LINE_TABLE_MAGIC_12 = 0xFFFFFFFB;
constexpr auto LINE_TABLE_MAGIC_116 = 0xFFFFFFFA;
constexpr auto LINE_TABLE_MAGIC_118 = 0xFFFFFFF0;

static unsigned int readVarInt(const unsigned char **pp) {
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

bool LineTable::load(const char *table) {
    mQuantum = (unsigned char)table[6];
    mPtrSize = (unsigned char)table[7];

    auto peek = [&](const char *address) -> uint64_t {
        if (mPtrSize == 4)
            return *(uint32_t *)address;

        return *(uint64_t *)address;
    };

    unsigned int magic = *(unsigned int *)table;

    switch (magic) {
        case LINE_TABLE_MAGIC_12: {
            mVersion = VERSION12;

            mFuncNum = (unsigned int)peek(&table[8]);
            mFuncData = table;
            mFuncNameTable = table;
            mFuncTable = &table[8 + mPtrSize];
            mPCTable = table;

            unsigned int funcTableSize = mFuncNum * 2 * mPtrSize + mPtrSize;
            unsigned int fileOffset = *(unsigned int *)&mFuncTable[funcTableSize];

            mFileTable = &table[fileOffset];
            mFileNum = *(unsigned int *)mFileTable;

            break;
        }

        case LINE_TABLE_MAGIC_116: {
            mVersion = VERSION116;

            mFuncNum = (unsigned int)peek(&table[8]);
            mFileNum = (unsigned int)peek(&table[8 + mPtrSize]);

            mFuncNameTable = &table[peek(&table[8 + 2 * mPtrSize])];
            mCuTable = &table[peek(&table[8 + 3 * mPtrSize])];
            mFileTable = &table[peek(&table[8 + 4 * mPtrSize])];
            mPCTable = &table[peek(&table[8 + 5 * mPtrSize])];
            mFuncData = &table[peek(&table[8 + 6 * mPtrSize])];
            mFuncTable = &table[peek(&table[8 + 6 * mPtrSize])];

            break;
        }

        case LINE_TABLE_MAGIC_118: {
            mVersion = VERSION118;

            mFuncNum = (unsigned int)peek(&table[8]);
            mFileNum = (unsigned int)peek(&table[8 + mPtrSize]);
            mTextStart = (uintptr_t)peek(&table[8 + 2 * mPtrSize]);

            mFuncNameTable = &table[peek(&table[8 + 3 * mPtrSize])];
            mCuTable = &table[peek(&table[8 + 4 * mPtrSize])];
            mFileTable = &table[peek(&table[8 + 5 * mPtrSize])];
            mPCTable = &table[peek(&table[8 + 6 * mPtrSize])];
            mFuncData = &table[peek(&table[8 + 7 * mPtrSize])];
            mFuncTable = &table[peek(&table[8 + 7 * mPtrSize])];

            break;
        }

        default:
            return false;
    }

    return true;
}

bool LineTable::load() {
    return load(zero::filesystem::getApplicationPath());
}

bool LineTable::load(const std::string &file) {
    std::optional<zero::proc::ProcessMapping> processMapping = zero::proc::getImageBase(getpid(), file);

    if (!processMapping)
        return false;

    return load(file, processMapping->start);
}

bool LineTable::load(const std::string &file, unsigned long base) {
    ELFIO::elfio reader;

    if (!reader.load(file))
        return false;

    auto it = std::find_if(
            reader.sections.begin(),
            reader.sections.end(),
            [](const auto& s) {
                return zero::strings::containsIC(s->get_name(), GO_LINE_TABLE);
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

    uintptr_t minVA = std::min_element(
            loads.begin(),
            loads.end(),
            [](const auto &i, const auto &j) {
                return i->get_virtual_address() < j->get_virtual_address();
            }).operator*()->get_virtual_address() & ~(PAGE_SIZE - 1);

    return load((char *)base + (*it)->get_address() - minVA);
}

FuncTablePtr LineTable::getFuncTable() const {
    return FuncTablePtr(mFuncTable, mVersion >= VERSION118 ? 4 : mPtrSize);
}

bool LineTable::findFunc(uintptr_t address, Func &func) {
    auto begin = getFuncTable();
    auto back = begin + mFuncNum;
    auto end = back + 1;
    auto base = mVersion >= VERSION118 ? mTextStart : 0;

    if (address < begin->entry + base || address >= back->entry + base)
        return false;

    auto it = std::upper_bound(begin, end, address, [&](auto value, const auto& i) {
        return value < i.entry + base;
    });

    if (it == end)
        return false;

    func.mLineTable = this;
    func.mFuncData = &mFuncData[(it - 1)->offset];

    return true;
}

bool LineTable::getFunc(unsigned int index, Func &func) {
    if (index >= mFuncNum)
        return false;

    func.mLineTable = this;
    func.mFuncData = &mFuncData[getFuncTable()[index].offset];

    return true;
}

int LineTable::getPCValue(unsigned int offset, uintptr_t entry, uintptr_t targetPC) const {
    const unsigned char *p = (unsigned char *)&mPCTable[offset];

    int value = -1;
    uintptr_t pc = entry;

    while (step(&p, &pc, &value, pc == entry)) {
        if (targetPC < pc)
            return value;
    }

    return -1;
}

bool LineTable::step(const unsigned char **p, uintptr_t *pc, int *value, bool first) const {
    unsigned int uv = readVarInt(p);

    if (uv == 0 && !first)
        return false;

    if ((uv & 1) != 0) {
        uv = ~(uv >> 1);
    } else {
        uv >>= 1;
    }

    *pc += readVarInt(p) * mQuantum;
    *value += (int)uv;

    return true;
}

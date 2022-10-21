#ifndef GO_PROBE_LINE_TABLE_H
#define GO_PROBE_LINE_TABLE_H

#include "func.h"
#include <go/type/basic.h>
#include <zero/singleton.h>

enum emGolangVersion {
    VERSION12,
    VERSION116,
    VERSION118
};

class LineTable {
#define gLineTable zero::Singleton<LineTable>::getInstance()
public:
    bool load();
    bool load(const std::string& file);
    bool load(const std::string& file, unsigned long base);
    bool load(const char *table);

public:
    bool getFunc(unsigned int index, Func &func);
    bool findFunc(uintptr_t address, Func &func);

public:
    int getPCValue(unsigned int offset, uintptr_t entry, uintptr_t targetPC) const;

private:
    bool step(const unsigned char **p, uintptr_t *pc, int *value, bool first) const;

private:
    FuncTablePtr getFuncTable() const;

public:
    emGolangVersion mVersion;

public:
    unsigned int mQuantum;
    unsigned int mPtrSize;
    unsigned int mFuncNum;
    unsigned int mFileNum;

public:
    uintptr_t mTextStart;

public:
    const char *mFuncNameTable;
    const char *mCuTable;
    const char *mFuncTable;
    const char *mFuncData;
    const char *mPCTable;
    const char *mFileTable;
};

#endif //GO_PROBE_LINE_TABLE_H

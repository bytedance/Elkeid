#ifndef GO_PROBE_LINE_TABLE_H
#define GO_PROBE_LINE_TABLE_H

#include "func.h"
#include <go/type/basic.h>
#include <go/type/function.h>
#include <common/singleton.h>

enum emGOVersion {
    emVersion12,
    emVersion116
};

class CLineTable {
#define gLineTable SINGLETON_(CLineTable)
public:
    bool load();
    bool load(const std::string& file);
    bool load(const std::string& file, unsigned long base);
    bool load(const char* lineTable);

private:
    unsigned long peek(const char *address) const;

public:
    bool findFunc(void *pc, CFunction& func);
    bool getFunc(unsigned long index, CFunction& func);

private:
    const go::func_item *getFuncItem(unsigned long index) const;
    const go::func_info *getFuncInfo(unsigned long index) const;

public:
    emGOVersion mVersion;
    unsigned int mQuantum;
    unsigned int mPtrSize;

public:
    unsigned long mFuncNum;
    unsigned long mFileNum;

public:
    const char *mFuncNameTable;
    const char *mCuTable;
    const char *mFuncTable;
    const char *mFuncData;
    const char *mPCTable;
    const char *mFileTable;
};

#endif //GO_PROBE_LINE_TABLE_H

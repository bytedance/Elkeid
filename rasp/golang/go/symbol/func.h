#ifndef GO_PROBE_FUNC_H
#define GO_PROBE_FUNC_H

#include <go/type/function.h>

class CLineTable;

class CFunction {
public:
    void *getEntry() const;
    const char *getName() const;

public:
    int getFrameSize(void *pc) const;
    int getSourceLine(void *pc) const;
    const char *getSourceFile(void *pc) const;

private:
    int getPCValue(int offset, void *targetPC) const;

private:
    static unsigned int readVarInt(const unsigned char **pp);
    bool step(const unsigned char **p, unsigned long *pc, int *val, bool first) const ;

public:
    bool isStackTop() const;

public:
    const CLineTable *mLineTable;
    const go::func_info *mFuncInfo;
};


#endif //GO_PROBE_FUNC_H

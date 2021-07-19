#ifndef TRAP_INLINE_HOOK_H
#define TRAP_INLINE_HOOK_H

#include <Zydis/Zydis.h>

class CInlineHook {
public:
    CInlineHook();

private:
    unsigned long getCodeTail(void *address);

public:
    virtual bool hook(void *address, void *replace, void **backup);
    virtual bool unhook(void *address, void *backup);

private:
    bool setCodeReadonly(void *address, unsigned long size) const;
    bool setCodeWriteable(void *address, unsigned long size) const;

protected:
    ZydisDecoder mDecoder{};

private:
    unsigned long mPagesize;
};


#endif //TRAP_INLINE_HOOK_H

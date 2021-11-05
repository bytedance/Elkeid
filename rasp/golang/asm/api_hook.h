#ifndef GO_PROBE_API_HOOK_H
#define GO_PROBE_API_HOOK_H

#include "inline_hook.h"
#include <zero/singleton.h>

class CAPIHook: public CInlineHook {
#define gAPIHook zero::Singleton<CAPIHook>::getInstance()
public:
    bool hook(void *address, void *replace, void **backup) override;
    bool unhook(void *address, void *backup) override;

private:
    void *getExactAddress(void *address);
};


#endif //GO_PROBE_API_HOOK_H

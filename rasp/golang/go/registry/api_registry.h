#ifndef GO_PROBE_API_REGISTRY_H
#define GO_PROBE_API_REGISTRY_H

#include <map>
#include <list>
#include <common/singleton.h>

struct CAPIRegister {
    void *entry;
    void **origin;
};

class CAPIRegistry {
#define gAPIRegistry SINGLETON_(CAPIRegistry)
public:
    CAPIRegistry();

public:
    bool find(const std::string& name, CAPIRegister& apiRegister);

private:
    void insert(const std::string& name, void *entry, void **origin);

private:
    std::list<std::string> mBlacklist;
    std::map<std::string, CAPIRegister> mRegistry;
};


#endif //GO_PROBE_API_REGISTRY_H

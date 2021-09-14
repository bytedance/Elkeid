#ifndef GO_PROBE_INTERFACE_TABLE_H
#define GO_PROBE_INTERFACE_TABLE_H

#include <string>
#include <go/type/interface.h>

class CInterfaceTable {
public:
    bool load();
    bool load(const std::string& file);
    bool load(const std::string& file, unsigned long base);

public:
    bool findByFuncName(const char *name, go::interface_item **item);

private:
    unsigned long mNumber;
    go::interface_item **mTable;
};


#endif //GO_PROBE_INTERFACE_TABLE_H

#ifndef GO_PROBE_INTERFACE_H
#define GO_PROBE_INTERFACE_H

#include "basic.h"

#pragma pack(push, 1)

namespace go {
    struct interface_item {
        Uintptr interface;
        Uintptr type;
        Uint32 hash;
        Uint8 reserved[4];
        Uintptr func[1];
    };
}

#pragma pack(pop)

#endif //GO_PROBE_INTERFACE_H

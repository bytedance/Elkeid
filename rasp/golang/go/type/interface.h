#ifndef GO_PROBE_INTERFACE_H
#define GO_PROBE_INTERFACE_H

#include "basic.h"

namespace go {
    struct interface_item {
        go::Uintptr interface;
        go::Uintptr type;
        go::Uint32 hash;
        go::Uint8 reserved[4];
        go::Uintptr func[1];
    };
}

#endif //GO_PROBE_INTERFACE_H

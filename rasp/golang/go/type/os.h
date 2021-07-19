#ifndef GO_PROBE_OS_H
#define GO_PROBE_OS_H

#include "basic.h"

#pragma pack(push, 1)

namespace go {
    struct exec_cmd {
        go::string path;
        go::slice<go::string> args;
    };

    METADATA(exec_cmd, go::string, go::slice<go::string>)
}

#pragma pack(pop)

#endif //GO_PROBE_OS_H

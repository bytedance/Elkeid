#ifndef GO_PROBE_OS_H
#define GO_PROBE_OS_H

#include "basic.h"

namespace go {
    namespace os::exec {
        struct Cmd {
            go::String path;
            go::Slice<go::String> args;
        };
    }

    METADATA(os::exec::Cmd, go::String, go::Slice<go::String>)
}

#endif //GO_PROBE_OS_H

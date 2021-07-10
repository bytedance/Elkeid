#ifndef GO_PROBE_OS_H
#define GO_PROBE_OS_H

#include "basic.h"

struct exec_cmd {
    go::string path;
    go::slice<go::string> args;
};

#endif //GO_PROBE_OS_H

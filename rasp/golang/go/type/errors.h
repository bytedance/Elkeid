#ifndef GO_PROBE_ERRORS_H
#define GO_PROBE_ERRORS_H

#include "basic.h"

namespace go {
    namespace errors {
        struct ErrorString : String {
            static void **errorTab() {
                static void *tab = nullptr;
                return &tab;
            }
        };
    }

    METADATA(errors::ErrorString, const char *, ptrdiff_t)
}

#endif //GO_PROBE_ERRORS_H

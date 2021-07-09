#ifndef GO_PROBE_FUNCTION_H
#define GO_PROBE_FUNCTION_H

#include "basic.h"

#pragma pack(push, 1)

namespace go {
    struct func_item {
        Uintptr entry;
        Uintptr func_offset;
    };

    struct func_info {
        Uintptr entry;
        Int32 name_offset;
        Int32 args;
        Uint32 defer_return;
        Int32 pc_sp;
        Int32 pc_file;
        Int32 pc_line;
        Int32 n_pc_data;
    };

    struct func_info_v116 {
        Uintptr entry;
        Int32 name_offset;
        Int32 args;
        Uint32 defer_return;
        Int32 pc_sp;
        Int32 pc_file;
        Int32 pc_line;
        Int32 n_pc_data;
        Int32 cu_offset;
        Uint8 func_id;
        Uint8 reserved[2];
        Uint8 n_func_data;
    };
}

#pragma pack(pop)

#endif //GO_PROBE_FUNCTION_H

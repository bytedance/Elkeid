/* SPDX-License-Identifier: GPL-2.0 */
#undef PRINT_EVENT_SYSTEM
#define PRINT_EVENT_SYSTEM anti_rootkit_print

#if !defined(_ANTI_ROOTKIT_PRINT_H) || defined(TRACE_HEADER_MULTI_READ)
#define _ANTI_ROOTKIT_PRINT_H

#include "trace.h"

#define RS "\x1e"
#define ANTI_ROOTKIT_UID        "-1"
#define MOD_HIDDEN     "1"

#ifdef CONFIG_X86
PRINT_EVENT_DEFINE(interrupts,

                   PE_PROTO(const char *name,
                           int interrupt_number),

                   PE_ARGS(name, interrupt_number),

                   PE_printk(ANTI_ROOTKIT_UID RS INTERRUPTS_HOOK RS "%s" RS "%d", name, interrupt_number)
);
#endif

PRINT_EVENT_DEFINE(syscall,

                   PE_PROTO(const char *name,
                           int syscall_number),

                   PE_ARGS(name, syscall_number),

                   PE_printk(ANTI_ROOTKIT_UID RS SYSCALL_HOOK RS "%s" RS "%d", name, syscall_number)
);

PRINT_EVENT_DEFINE(fops,

                   PE_PROTO(const char *name),

                   PE_ARGS(name),

                   PE_printk(ANTI_ROOTKIT_UID RS PROC_FILE_HOOK RS "%s", name)
);

PRINT_EVENT_DEFINE(mod,

                   PE_PROTO(const char *name),

                   PE_ARGS(name),

                   PE_printk(ANTI_ROOTKIT_UID RS LKM_HIDDEN RS "%s", name)
);

#endif /* _KPROBE_PRINT_H */

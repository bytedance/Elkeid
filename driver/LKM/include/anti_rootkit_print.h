/* SPDX-License-Identifier: GPL-2.0 */
#undef PRINT_EVENT_SYSTEM
#define PRINT_EVENT_SYSTEM anti_rootkit_print
#if !defined(_ANTI_ROOTKIT_PRINT_H) || defined(TRACE_HEADER_MULTI_READ)
#define _ANTI_ROOTKIT_PRINT_H

#include "trace.h"

#ifdef CONFIG_X86
PRINT_EVENT_DEFINE(interrupts,

                   PE_PROTO(const char *name,
                           int interrupt_number),

                   PE_ARGS(name, interrupt_number),

                   PE_STRUCT__entry(
                           __array(char, name, MODULE_NAME_LEN)
                           __field(int, interrupt_number)
                   ),

                   PE_fast_assign(
                           memcpy(__entry->name, name, MODULE_NAME_LEN);
                           __entry->interrupt_number = interrupt_number;
                   ),

                   PE_printk(INTERRUPTS_HOOK RS "%s" RS "%d",
                             __get_ent(name, name),
                             __get_ent(interrupt_number, interrupt_number))
)
#endif

PRINT_EVENT_DEFINE(syscall,

                   PE_PROTO(const char *name,
                           int syscall_number),

                   PE_ARGS(name, syscall_number),

                   PE_STRUCT__entry(
                           __array(char, name, MODULE_NAME_LEN)
                           __field(int, syscall_number)
                   ),

                   PE_fast_assign(
                           memcpy(__entry->name, name, MODULE_NAME_LEN);
                           __entry->syscall_number = syscall_number;
                   ),

                   PE_printk(SYSCALL_HOOK RS "%s" RS "%d",
                             __get_ent(name, name),
                             __get_ent(syscall_number, syscall_number))

)

PRINT_EVENT_DEFINE(fops,

                   PE_PROTO(const char *name),

                   PE_ARGS(name),

                   PE_STRUCT__entry(
                           __array(char, name, MODULE_NAME_LEN)
                   ),

                   PE_fast_assign(
                           memcpy(__entry->name, name, MODULE_NAME_LEN);
                   ),

                   PE_printk(PROC_FILE_HOOK RS "%s", __get_ent(name, name))

)

PRINT_EVENT_DEFINE(mod,

                   PE_PROTO(const char *name),

                   PE_ARGS(name),

                   PE_STRUCT__entry(
                           __array(char, name, MODULE_NAME_LEN)
                   ),

                   PE_fast_assign(
                           memcpy(__entry->name, name, MODULE_NAME_LEN);
                   ),

                   PE_printk(LKM_HIDDEN RS "%s", __get_ent(name, name))
)
#endif /* _KPROBE_PRINT_H */

/* This part must be outside protection */
#include "define_trace.h"

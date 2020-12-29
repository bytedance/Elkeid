/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Trace files that want to automate creation of all print event defined
 * in their file should include this file. The following are macros that the
 * trace file may define:
 *
 * PRINT_EVENT_SYSTEM defines the system the print is for
 *
 * TRACE_INCLUDE_FILE if the file name is something other than PRINT_EVENT_SYSTEM.h
 *     This macro may be defined to tell define_trace.h what file to include.
 *     Note, leave off the ".h".
 */
#ifdef CREATE_PRINT_EVENT

/* Prevent recursion */
#undef CREATE_PRINT_EVENT

#include <linux/stringify.h>

#undef TRACE_INCLUDE

#ifndef TRACE_INCLUDE_FILE
#define TRACE_INCLUDE_FILE PRINT_EVENT_SYSTEM
#define UNDEF_TRACE_INCLUDE_FILE
#endif

#define TRACE_INCLUDE(system) __stringify(system.h)

/* Let the trace headers be reread */
#define TRACE_HEADER_MULTI_READ

#include "print_event.h"

#undef TRACE_HEADER_MULTI_READ

/* Only undef what we defined in this file */
#ifdef UNDEF_TRACE_INCLUDE_FILE
#undef TRACE_INCLUDE_FILE
#undef UNDEF_TRACE_INCLUDE_FILE
#endif

/* We may be processing more files */
#define CREATE_PRINT_EVENT

#endif /* CREATE_PRINT_EVENT */

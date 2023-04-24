/* SPDX-License-Identifier: GPL-2.0 */

#ifndef _TRACE_EVENT_H
#define _TRACE_EVENT_H

#include "../include/trace_buffer.h"

#ifdef __KERNEL__

#include <linux/kernel.h>
#include <linux/kallsyms.h>
#include <linux/trace_seq.h>

#ifdef SMITH_TRACE_EVENTS
#include <linux/trace_events.h>
#else
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 2, 0)
#define SMITH_TRACE_EVENTS
#include <linux/trace_events.h>
#else
#include <linux/ftrace_event.h>
#endif
#endif

#define RS "\x1e"

#define SZ_32K				0x00008000
#define SZ_128K				0x00020000


#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
#else
#define PDE_DATA(i)  PDE(i)->data
#endif

#ifdef SMITH_TRACE_EVENTS
static inline int __trace_seq_used(struct trace_seq *s)
{
	return trace_seq_used(s);
}

static inline bool __trace_seq_has_overflowed(struct trace_seq *s)
{
	return trace_seq_has_overflowed(s);
}

/*
 * Several functions return TRACE_TYPE_PARTIAL_LINE if the trace_seq
 * overflowed, and TRACE_TYPE_HANDLED otherwise. This helper function
 * simplifies those functions and keeps them in sync.
 */
static inline enum print_line_t __trace_handle_return(struct trace_seq *s)
{
	return trace_handle_return(s);
}
#else
static inline int __trace_seq_used(struct trace_seq *s)
{
    return min(s->len, (unsigned int)(PAGE_SIZE - 1));
}
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 5, 0)
static inline bool __trace_seq_has_overflowed(struct trace_seq *s)
{
    return s->len > PAGE_SIZE - 1;
}
#else
static inline bool __trace_seq_has_overflowed(struct trace_seq *s)
{
    return s->full || s->len > PAGE_SIZE - 1;
}
#endif

/*
 * Several functions return TRACE_TYPE_PARTIAL_LINE if the trace_seq
 * overflowed, and TRACE_TYPE_HANDLED otherwise. This helper function
 * simplifies those functions and keeps them in sync.
 */
static inline enum print_line_t __trace_handle_return(struct trace_seq *s)
{
    return __trace_seq_has_overflowed(s) ?
           TRACE_TYPE_PARTIAL_LINE : TRACE_TYPE_HANDLED;
}
#endif

/*
 * The print entry - the most basic unit of tracing.
 */
struct print_event_entry {
	unsigned short	id;
};

struct print_event_class {
	unsigned short id;
	enum print_line_t (*format)(struct trace_seq *seq,
				    struct print_event_entry *entry);
	struct tb_ring *trace;
};

#define RB_BUFFER_SIZE	SZ_128K
#define PRINT_EVENT_DEFINE(name, proto, args, tstruct, assign, print)

struct print_event_class *smith_query_kprobe_event_class(int id);
struct print_event_class *smith_query_anti_rootkit_event_class(int id);
int smith_query_kprobe_events(void);
int smith_query_anti_rootkit_events(void);

#endif /* __KERNEL__ */

#define TRACE_IOCTL_STAT	(0xd00dbef0)	/* ioctl command for stat */

#endif /* _TRACE_EVENT_H */

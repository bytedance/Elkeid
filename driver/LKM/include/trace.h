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
#include <linux/ftrace_event.h>
#endif

#define SZ_32K				0x00008000
#define SZ_128K				0x00020000

#ifdef SMITH_TRACE_SEQ
#define SMITH_TRACE_SEQ_QUERY(s, e) (s)->seq.e
#else
#define SMITH_TRACE_SEQ_QUERY(s, e) (s)->e
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
#else /* !SMITH_TRACE_EVENTS */
static inline int __trace_seq_used(struct trace_seq *s)
{
    unsigned int len = SMITH_TRACE_SEQ_QUERY(s, len);
    return min(len, (unsigned int)(PAGE_SIZE - 1));
}
static inline bool __trace_seq_has_overflowed(struct trace_seq *s)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 5, 0)
	if (s->full)
		return s->full;
#endif
    return SMITH_TRACE_SEQ_QUERY(s, len) > (PAGE_SIZE - 1);
}
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
#endif /* !SMITH_TRACE_EVENTS */

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

#endif /* __KERNEL__ */

#define TRACE_IOCTL_STAT	(0xd00dbef0)	/* ioctl command for stat */

#endif /* _TRACE_EVENT_H */

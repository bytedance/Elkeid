/* SPDX-License-Identifier: GPL-2.0 */

#ifndef _TRACE_EVENT_H
#define _TRACE_EVENT_H

#include "../include/trace_buffer.h"

#ifdef __KERNEL__

#include <linux/kernel.h>
#if defined(SMITH_TRACE_EVENTS) || LINUX_VERSION_CODE >= KERNEL_VERSION(4, 2, 0)
#include <linux/trace_events.h>
#else
#include <linux/ftrace_event.h>
#endif

#define SZ_32K				0x00008000
#define SZ_128K				0x00020000

#define RB_BUFFER_SIZE		SZ_128K

extern struct tb_ring *g_trace_ring;

#else /* !__KERNEL__ */

/*
 * core routines for user mode consuming of trace-buffer
 */
int tb_init_ring(void);
void tb_fini_ring(void);
int tb_read_ring(char *msg, int len, int (*cb)(int *), int *ctx);

/*
 * statatics support routines
 */

struct ring_stat {
    uint32_t        nrings;
    uint32_t        flags;

    struct timeval  tv;
    uint64_t        npros;  /* number of messages producted */
    uint64_t        ncons;  /* number of messages consumed */
    uint64_t        ndrop;  /* dropped by producer when ring is full */
    uint64_t        ndisc;  /* discarded by producer for overwriting */
    uint64_t        nexcd;  /* total dropped messages (too long to save) */
    uint64_t        cpros;  /* bytes of produced messages */
    uint64_t        ccons;  /* bytes of consumed messages */
    uint64_t        cdrop;  /* bytes of dropped messages */
    uint64_t        cdisc;  /* bytes of discarded messages */
    uint32_t        maxsz;
};

int tb_is_elapsed(struct timeval *tv, long cycle);
int tb_query_stat_ring(struct ring_stat *stat);
void tb_show_stat_ring(struct ring_stat *s, struct ring_stat *l, struct ring_stat *n);

#endif /* !__KERNEL__ */

#define TRACE_IOCTL_STAT	(0xd00dbef0)	/* ioctl command for stat */
#define TRACE_IOCTL_FORMAT	(0xd00dbef1)	/* ioctl command for format query */

#endif /* _TRACE_EVENT_H */
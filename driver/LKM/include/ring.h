// SPDX-License-Identifier: GPL-2.0

#define SLOT_RECORD_MAX     (32768)  /* max size of slot record */
#define SLOT_RECLEN_MAX     (SLOT_RECORD_MAX - sizeof(struct slot_record)) /* max of sr_len */

#ifdef __KERNEL__

#include <linux/version.h>
#include <linux/stddef.h>
#include <linux/errno.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/syscalls.h>

#include <linux/fs.h>
#include <linux/file.h>
#include <linux/proc_fs.h>
#include <linux/anon_inodes.h>

#include <linux/random.h>
#include <linux/jiffies.h>
#include <linux/time.h>
#include <linux/delay.h>
#include <linux/hrtimer.h>

#include <linux/cpu.h>
#include <linux/percpu.h>
#include <linux/kthread.h>
#include <linux/completion.h>
#include <linux/mutex.h>

#include <linux/mm.h>
#include <linux/vmalloc.h>
#include <linux/mman.h>
#include <linux/slab.h>
#include <linux/hugetlb.h>
#include <linux/highmem.h>
#include <linux/uaccess.h>

/*
 * utilitiy routines
 */
uint64_t rs_get_seconds(void);

/*
 * core ring routines for kernel mode
 */

#define RING_MODE_FLEX   (0x00)
#define RING_MODE_FIXED  (0x01)

int rs_init_ring(int mode, int slotlen);
void rs_fini_ring(void);

int rs_read_ring(char *msg, int len, int cpu);
int rs_write_ring(void *msg, int len);
int rs_vsprint_ring(const char *fmt, ...);

#else /* !__KERNEL__ */

#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <errno.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <signal.h>
#include <time.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>

/*
 * core ring routines for user mode consuming
 */
int rs_init_ring(void);
void rs_fini_ring(void);
int rs_read_ring(char *msg, int len, int (*cb)(int *), int *ctx);

/*
 * statatics support routines
 */
struct ring_stat {
    struct timeval  tv;
    uint64_t        npros;  /* number of messages producted */
    uint64_t        ncons;  /* number of messages consumed */
    uint64_t        ndrop;  /* dropped by producer when ring is full */
    uint64_t        ndisc;  /* discarded by producer for overwriting */
    uint64_t        cpros;  /* bytes of produced messages */
    uint64_t        ccons;  /* bytes of consumed messages */
    uint64_t        cdrop;  /* bytes of dropped messages */
    uint64_t        cdisc;  /* bytes of discarded messages */
    uint32_t        nexcd;  /* total dropped messages (too long to save) */
    uint32_t        maxsz;  /* maximum length in bytes of long message */
};

int rs_is_elapsed(struct timeval *tv, long cycle);
void rs_query_stat_ring(struct ring_stat *stat);
void rs_show_stat_ring(struct ring_stat *start,
                       struct ring_stat *last,
                       struct ring_stat *now);
#endif /* !__KERNEL__ */

// SPDX-License-Identifier: GPL-2.0
/*
 * trace.c
 *
 * The ring buffer based tracing information store.
 */
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/proc_fs.h>
#include <linux/slab.h>
#include <linux/version.h>
#include "../include/trace.h"
#include "../include/kprobe.h"
#include "../include/util.h"

#define __SD_XFER_SE__
#include "../include/xfer.h"

/*
 * prototypes of event elements
 */

#define SD_TYPE_ENTRY_XID(v)    {v}}, {{SD_TYPE_U32}, {4}}

#define SD_TYPE_ENTRY_U8( n, v) {{SD_TYPE_U32}, {4}}
#define SD_TYPE_ENTRY_U16(n, v) {{SD_TYPE_U32}, {4}}
#define SD_TYPE_ENTRY_U32(n, v) {{SD_TYPE_U32}, {4}}
#define SD_TYPE_ENTRY_U64(n, v) {{SD_TYPE_U64}, {8}}
#define SD_TYPE_ENTRY_S8( n, v) {{SD_TYPE_S32}, {4}}
#define SD_TYPE_ENTRY_S16(n, v) {{SD_TYPE_S32}, {4}}
#define SD_TYPE_ENTRY_S32(n, v) {{SD_TYPE_S32}, {4}}
#define SD_TYPE_ENTRY_S64(n, v) {{SD_TYPE_S64}, {8}}

#define SD_TYPE_ENTRY_INT       SD_TYPE_ENTRY_S32
#define SD_TYPE_ENTRY_UINT      SD_TYPE_ENTRY_U32

#if BITS_PER_LONG == 32
# define SD_TYPE_ENTRY_LONG     SD_TYPE_ENTRY_S32
# define SD_TYPE_ENTRY_ULONG    SD_TYPE_ENTRY_U32
#else
# define SD_TYPE_ENTRY_LONG     SD_TYPE_ENTRY_S64
# define SD_TYPE_ENTRY_ULONG    SD_TYPE_ENTRY_U64
#endif

#define SD_TYPE_ENTRY_IP4(n, v) {{SD_TYPE_IP4}, {4}}
#define SD_TYPE_ENTRY_IP6(n, v) {{SD_TYPE_IP6}, {16}}

#define SD_TYPE_ENTRY_STR(n, v) {{SD_TYPE_STR}, {4}}
#define SD_TYPE_ENTRY_STL(...)  {{SD_TYPE_STR}, {4}}

#define SD_TYPE_POINTER_IP4     SD_TYPE_ENTRY_IP4
#define SD_TYPE_POINTER_IP6     SD_TYPE_ENTRY_IP6
#define SD_TYPE_POINTER_STR     SD_TYPE_ENTRY_STR
#define SD_TYPE_POINTER_STL     SD_TYPE_ENTRY_STL

#define SD_TYPE_I(n, ...)       SD_ENTS_N##n(n, ARG, ENT, SD_TYPE, __VA_ARGS__)
#define SD_TYPE_N(n, ...)       SD_TYPE_I(n, __VA_ARGS__)
#define SD_TYPE_D(...)          SD_TYPE_N(SD_N_ARGS(__VA_ARGS__), __VA_ARGS__)
#define SD_TYPE_XFER(...)       SD_TYPE_D(__VA_ARGS__)

#define SD_XFER_DEFINE_P(n, p, x)                               \
    SD_XFER_DEFINE_E(n, p, x);                                  \
    struct sd_item_ent SD_XFER_PROTO_##n[] = {                  \
        {{0}, {0}},                                             \
        {{sizeof(struct SD_XFER_EVENT_##n)},                    \
        SD_TYPE_##x,                                            \
        {{0}, {0}} };
#undef SD_XFER_DEFINE
#define SD_XFER_DEFINE(n, p, x) SD_XFER_DEFINE_P(n, p, x)

#include "../include/kprobe_print.h"
#include "../include/anti_rootkit_print.h"

#define SD_XFER_DEFINE_X(n, p, x) {sizeof(SD_XFER_PROTO_##n), 0, SD_XFER_PROTO_##n},
#undef SD_XFER_DEFINE
#define SD_XFER_DEFINE(n, p, x) SD_XFER_DEFINE_X(n, p, x)

struct sd_event_point {
    uint32_t  fmt;
    uint32_t  eid;
    struct sd_item_ent *ent;
};
static struct sd_event_point g_sd_events[] = {
#include "../include/kprobe_print.h"
#include "../include/anti_rootkit_print.h"
    };
#define N_SD_EVENTS (sizeof(g_sd_events)/sizeof(struct sd_event_point))

static int inline sd_init_events(void)
{
    int i;

    for (i = 0; i < N_SD_EVENTS; i++) {
        g_sd_events[i].eid = i + 1;
        g_sd_events[i].ent[0].eid = i + 1;
        g_sd_events[i].ent[0].meta = g_sd_events[i].fmt;
    }

    return 0;
}

#define PROC_ENDPOINT	"elkeid-endpoint"

struct tb_ring *g_trace_ring;
static DEFINE_MUTEX(g_trace_lock);

struct trace_instance {
    struct tb_ring *ring;
    struct tb_event *event;

    unsigned long lost_events;
    int cpu;
    u64 ts;
};

static int trace_open_pipe(struct inode *inode, struct file *filp)
{
    struct trace_instance *ti;

    ti = kzalloc(sizeof(*ti), GFP_KERNEL);
    if (!ti)
        return -ENOMEM;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 17, 0) || defined(SMITH_PROCFS_PDE_DATA)
    ti->ring = pde_data(inode);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
    ti->ring = PDE_DATA(inode);
#else
    ti->ring = PDE(inode)->data;
#endif
    filp->private_data = ti;
    nonseekable_open(inode, filp);
    __module_get(THIS_MODULE);

    return 0;
}

static int trace_is_empty(struct trace_instance *ti)
{
    int cpu;

    for_each_possible_cpu(cpu) {
        if (!tb_empty_cpu(ti->ring, cpu))
            return 0;
    }

    return 1;
}

/* Must be called with iter->mutex held. */
static int trace_wait_pipe(struct file *filp)
{
    struct trace_instance *ti = filp->private_data;
    int ret;

    while (trace_is_empty(ti)) {

        if ((filp->f_flags & O_NONBLOCK))
            return -EAGAIN;

        ret = tb_wait(ti->ring, TB_RING_ALL_CPUS, 0);
        if (ret)
            return ret;
    }

    return 0;
}

static inline int trace_next_cpu(int n, const struct cpumask *mask, int start, bool wrap)
{
	int next;

again:
	next = cpumask_next(n, mask);

	if (wrap && n < start && next >= start) {
		return nr_cpumask_bits;

	} else if (next >= nr_cpumask_bits) {
		wrap = true;
		n = -1;
		goto again;
	}

	return next;
}

static struct tb_event *trace_peek_entry(struct trace_instance *ti)
{
    struct tb_event *e = NULL;
    int cpu, start = ti->cpu;

    if (start >= nr_cpumask_bits)
        start = 0;
    else if (start < 0)
        start = 0;

    cpu = trace_next_cpu(start - 1, cpu_possible_mask, start, 0);
    while (cpu < nr_cpumask_bits) {

        if (tb_empty_cpu(ti->ring, cpu))
            goto next_cpu;

        e = tb_peek(ti->ring, cpu, &ti->ts, &ti->lost_events);
        if (e) {
            ti->event = e;
            ti->cpu = cpu;
            break;
        }
next_cpu:
        cpu = trace_next_cpu(cpu, cpu_possible_mask, start, 1);
    }

    return e;
}

static int trace_put_user(struct trace_instance *ti, char __user *ubuf,
                            size_t cnt, ssize_t *used)
{
    int len = tb_event_size(ti->event);

    if (len <= 0)
        return -EAGAIN;

    if (len + 8 + *used > cnt)
        return -EOVERFLOW;

    if (copy_to_user(ubuf + *used + 0, &ti->ts, 8))
        return -EBADF;
    if (copy_to_user(ubuf + *used + 8, tb_event_data(ti->event), len))
        return -EBADF;
    *used += len + 8;

    return len + 8;
}

static ssize_t trace_read_pipe(struct file *filp, char __user *ubuf,
                               size_t cnt, loff_t *ppos)
{
    struct trace_instance *ti;
    ssize_t rc = 0;

    /*
     * Avoid more than one consumer on a single file descriptor
     * This is just a matter of traces coherency, the ring buffer
     * itself is protected.
     */
    mutex_lock(&g_trace_lock);

    if(fatal_signal_pending(current))
        goto out;

    ti = filp->private_data;
    if (!ti) {
        rc = -EBADF;
        goto out;
    }

    if(!tb_record_is_on(ti->ring))
        goto out;

    rc = trace_wait_pipe(filp);
    if (rc)
        goto out;

    /* stop when tracing is finished */
    if (trace_is_empty(ti))
        goto out;

    while (trace_peek_entry(ti)) {

        if (trace_put_user(ti, ubuf, cnt, &rc) <= 0)
            break;
        tb_consume(ti->ring, ti->cpu, &ti->ts, &ti->lost_events);

        /*
         * try next cpu to avoid possible starving on other cores
         * read only one message for 'cpu', then move onto next
         */
        ti->cpu += 1;

        /*
         * timestamp + 32 bytes: minimized record-size
         * fops/mod: anti-rootkit records
         *   message_size + structure_size + xid + one_element
         */
        if (rc + 32 + 8 > cnt)
            break;
    }

out:
    mutex_unlock(&g_trace_lock);
    return rc;
}

static int trace_release_pipe(struct inode *inode, struct file *file)
{
    struct trace_instance *ti = file->private_data;

    if (!ti)
        return -EBADF;

    /* wake up pipe consumers in waitqueue */
    tb_wake_up(ti->ring);

    mutex_lock(&g_trace_lock);
    file->private_data = NULL;
    kfree(ti);
    mutex_unlock(&g_trace_lock);

    module_put(THIS_MODULE);

    return 0;
}

long trace_ioctl_pipe(struct file *filp, unsigned int cmd, unsigned long __user arg)
{
    struct trace_instance *ti = filp->private_data;
    long rc = -EINVAL;
    int i;

    if (cmd == TRACE_IOCTL_STAT) {
        struct tb_stat stat = {0};
        tb_stat(ti->ring, &stat);
        if (copy_to_user((void *)arg, &stat, sizeof(stat)))
            rc = -EFAULT;
        else
            rc = sizeof(stat);
    } else if (cmd == TRACE_IOCTL_FORMAT) {
        struct sd_event_format fmt = {0}, usr = {0};

        if (copy_from_user(&usr, (void *)arg, sizeof(usr)))
            goto errorout;
        if (usr.size < sizeof(fmt))
            goto errorout;
        fmt.size = sizeof(fmt);
        fmt.nids = N_SD_EVENTS;
        for (i = 0; i < N_SD_EVENTS; i++)
            fmt.size += g_sd_events[i].fmt;
        if (copy_to_user((void *)arg, &fmt, sizeof(fmt)))
            goto errorout;
        rc = sizeof(fmt);
        if (usr.size < fmt.size)
            goto errorout;
        for (i = 0; i < N_SD_EVENTS; i++) {
            if (copy_to_user((void *)arg + rc,
                             g_sd_events[i].ent,
                             g_sd_events[i].fmt))
                break;
            rc += g_sd_events[i].fmt;
        }
    }

errorout:
    return rc;
}

/* 
 * v5.6: proc_create_data API changed (file_operations to proc_ops)
 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 6, 0)
static const struct file_operations trace_pipe_fops = {
    .open = trace_open_pipe,
    .read = trace_read_pipe,
    .unlocked_ioctl = trace_ioctl_pipe,
    .release = trace_release_pipe,
};
#else
static const struct proc_ops trace_pipe_fops = {
    .proc_open = trace_open_pipe,
    .proc_read = trace_read_pipe,
    .proc_ioctl = trace_ioctl_pipe,
    .proc_release = trace_release_pipe,
};
#endif

static int __init print_event_init(void)
{
    sd_init_events();

    g_trace_ring = tb_alloc(RB_BUFFER_SIZE, TB_FL_OVERWRITE);
    if (!g_trace_ring)
        return -ENOMEM;

    if (!proc_create_data(PROC_ENDPOINT, S_IRUSR, NULL,
                          &trace_pipe_fops, g_trace_ring))
        goto errorout;

    return 0;

errorout:
    tb_free(g_trace_ring);

    return -ENOMEM;
}

static void print_event_exit(void)
{
    remove_proc_entry(PROC_ENDPOINT, NULL);
    if (g_trace_ring)
        tb_free(g_trace_ring);
}

KPROBE_INITCALL(trace, print_event_init, print_event_exit);

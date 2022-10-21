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

#define PROC_ENDPOINT	"elkeid-endpoint"

#define PRINT_EVENT_ID_MAX	\
	((1 << (sizeof(((struct print_event_entry *)0)->id) * 8)) - 1)

struct print_event_iterator {
    struct mutex mutex;
    struct tb_ring *ring;

    /* The below is zeroed out in pipe_read */
    struct trace_seq seq;
    struct print_event_entry *ent;
    unsigned long lost_events;
    int cpu;
    u64 ts;
    /* All new field here will be zeroed out in pipe_read */
};

static struct tb_ring *trace_ring;

/* Defined in linker script */
extern struct print_event_class *const __start_print_event_class[];
extern struct print_event_class *const __stop_print_event_class[];

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 17, 0)
static ssize_t(*trace_seq_to_user_sym) (struct trace_seq * s,
					char __user * ubuf, size_t cnt);
#else
#define trace_seq_to_user_sym trace_seq_to_user
#endif

static int kallsyms_lookup_symbols(void)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 17, 0)
    void *ptr = (void *)smith_kallsyms_lookup_name("trace_seq_to_user");
    if (!ptr)
        return -ENODEV;
    trace_seq_to_user_sym = ptr;
#endif

    return 0;
}

static int trace_open_pipe(struct inode *inode, struct file *filp)
{
    struct print_event_iterator *iter;

    iter = kzalloc(sizeof(*iter), GFP_KERNEL);
    if (!iter)
        return -ENOMEM;

    trace_seq_init(&iter->seq);
    mutex_init(&iter->mutex);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 17, 0) || defined(SMITH_PROCFS_PDE_DATA)
    iter->ring = pde_data(inode);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
    iter->ring = PDE_DATA(inode);
#else
    iter->ring = PDE(inode)->data;
#endif
    filp->private_data = iter;
    nonseekable_open(inode, filp);
    __module_get(THIS_MODULE);

    return 0;
}

static int is_trace_empty(struct print_event_iterator *iter)
{
    int cpu;

    for_each_possible_cpu(cpu) {
        if (!tb_empty_cpu(iter->ring, cpu))
            return 0;
    }

    return 1;
}

/* Must be called with iter->mutex held. */
static int trace_wait_pipe(struct file *filp)
{
    struct print_event_iterator *iter = filp->private_data;
    int ret;

    while (is_trace_empty(iter)) {

        if ((filp->f_flags & O_NONBLOCK))
            return -EAGAIN;

        mutex_unlock(&iter->mutex);
        ret = tb_wait(iter->ring, TB_RING_ALL_CPUS, 0);
        mutex_lock(&iter->mutex);

        if (ret)
            return ret;
    }

    return 1;
}

static struct print_event_entry *peek_next_entry(struct print_event_iterator *iter,
                                                 int cpu, u64 * ts,
                                                 unsigned long *lost_events)
{
    struct tb_event *event;

    event = tb_peek(iter->ring, cpu, ts, lost_events);
    if (event)
        return tb_event_data(event);

    return NULL;
}

static inline int __cpumask_next_wrap(int n, const struct cpumask *mask, int start, bool wrap)
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

static struct print_event_entry *__find_next_entry(struct print_event_iterator *iter,
                                                   int *ent_cpu, unsigned long *me,
                                                   u64 *ent_ts)
{
    struct tb_ring *ring = iter->ring;
    struct print_event_entry *ent = NULL;
    u64 ts;
    unsigned long lost_events = 0;
    int cpu, start = 0;

    if (ent_cpu) {
        /*
         * always loop from next of last-read cpu (specified by user)
         * to avoid possible starving on other cores, that is, reading
         * one message for 'cpu', then moving onto 'cpu' + 1
         */
        start = *ent_cpu + 1;
        if (start >= nr_cpumask_bits)
            start = 0;
        else if (start < 0)
            start = 0;
    }

    cpu = __cpumask_next_wrap(start - 1, cpu_possible_mask, start, 0);
    while (cpu < nr_cpumask_bits) {

        if (tb_empty_cpu(ring, cpu))
            goto next_cpu;

        ent = peek_next_entry(iter, cpu, &ts, &lost_events);
        if (ent) {
           if (ent_cpu)
               *ent_cpu = cpu;
           if (ent_ts)
               *ent_ts = ts;
           if (me)
               *me = lost_events;
            break;
        }
next_cpu:
        cpu = __cpumask_next_wrap(cpu, cpu_possible_mask, start, 1);
    }

    return ent;
}

/* Find the next real entry, and increment the iterator to the next entry */
static void *trace_next_entry_inc(struct print_event_iterator *iter)
{
    iter->ent = __find_next_entry(iter, &iter->cpu,
                                  &iter->lost_events, &iter->ts);

    return iter->ent ? iter : NULL;
}

static struct print_event_class *find_print_event(int id)
{
    if (likely(id < (__stop_print_event_class - __start_print_event_class)))
        return __start_print_event_class[id];

    return NULL;
}

static enum print_line_t print_trace_fmt_line(struct print_event_iterator *iter)
{
    struct trace_seq *seq = &iter->seq;
    struct print_event_entry *entry;
    struct print_event_class *class;

    entry = iter->ent;
    class = find_print_event(entry->id);

    if (__trace_seq_has_overflowed(seq))
        return TRACE_TYPE_PARTIAL_LINE;

    if (class)
        return class->format(seq, entry);

    trace_seq_printf(seq, "Unknown id %d\n", entry->id);

    return __trace_handle_return(seq);
}

static ssize_t trace_read_pipe(struct file *filp, char __user * ubuf,
                               size_t cnt, loff_t * ppos)
{
    ssize_t sret;
    struct print_event_iterator *iter = filp->private_data;
    static DEFINE_MUTEX(access_lock);

    /*
     * Avoid more than one consumer on a single file descriptor
    * This is just a matter of traces coherency, the ring buffer itself
    * is protected.
    */
    mutex_lock(&iter->mutex);

    sret = trace_seq_to_user_sym(&iter->seq, ubuf, cnt);
    if (sret != -EBUSY)
        goto out;

    trace_seq_init(&iter->seq);

waitagain:
    if(fatal_signal_pending(current))
        goto out;

    if(!tb_record_is_on(trace_ring))
        goto out;

    sret = trace_wait_pipe(filp);
    if (sret <= 0)
        goto out;

    /* stop when tracing is finished */
    if (is_trace_empty(iter)) {
        sret = 0;
        goto out;
    }

    if (cnt >= PAGE_SIZE)
        cnt = PAGE_SIZE - 1;

    memset((void *)iter + offsetof(struct print_event_iterator, seq), 0,
           sizeof(*iter) - offsetof(struct print_event_iterator, seq));

    mutex_lock(&access_lock);
    while (trace_next_entry_inc(iter) != NULL) {
        enum print_line_t ret;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 19, 0)
        int save_len = iter->seq.seq.len;
#else
        int save_len = iter->seq.len;
#endif
        ret = print_trace_fmt_line(iter);
        if (ret == TRACE_TYPE_PARTIAL_LINE) {
            /* don't print partial lines */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 19, 0)
            iter->seq.seq.len = save_len;
#else
            iter->seq.len = save_len;
#endif
            break;
        }

        if (ret != TRACE_TYPE_NO_CONSUME)
            tb_consume(iter->ring, iter->cpu, &iter->ts, &iter->lost_events);

        if (__trace_seq_used(&iter->seq) >= cnt)
            break;
    /*
    * Setting the full flag means we reached the trace_seq buffer
    * size and we should leave by partial output condition above.
    * One of the trace_seq_* functions is not used properly.
    */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 5, 0)
        WARN_ONCE(iter->seq.full, "full flag set for trace id: %d", iter->ent->id);
#endif
    }
    mutex_unlock(&access_lock);

/* Now copy what we have to the user */
    sret = trace_seq_to_user_sym(&iter->seq, ubuf, cnt);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 19, 0)
    if (iter->seq.seq.readpos >= __trace_seq_used(&iter->seq))
#else
    if (iter->seq.readpos >= __trace_seq_used(&iter->seq))
#endif
    trace_seq_init(&iter->seq);

    /*
    * If there was nothing to send to user, in spite of consuming trace
    * entries, go back to wait for more entries.
    */
    if (sret == -EBUSY)
        goto waitagain;

out:
    mutex_unlock(&iter->mutex);

    return sret;
}

static int trace_release_pipe(struct inode *inode, struct file *file)
{
    struct print_event_iterator *iter = file->private_data;

    mutex_destroy(&iter->mutex);
    kfree(iter);
    module_put(THIS_MODULE);

    return 0;
}

long trace_ioctl_pipe(struct file *filp, unsigned int cmd, unsigned long __user arg)
{
    struct print_event_iterator *iter = filp->private_data;
    long rc = -EINVAL;

    mutex_lock(&iter->mutex);
    if (cmd == TRACE_IOCTL_STAT) {
        struct tb_stat stat = {0};
        tb_stat(iter->ring, &stat);
        if (copy_to_user((void *)arg, &stat, sizeof(stat)))
            rc = -EFAULT;
        else
            rc = sizeof(stat);
    }
    mutex_unlock(&iter->mutex);

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

static inline int num_print_event_class(void)
{
    return __stop_print_event_class - __start_print_event_class;
}

static int __init print_event_init(void)
{
    int id = 0;
    int num_class = num_print_event_class();
    struct print_event_class *const *class_ptr;

    if (num_class == 0)
        return 0;

    if (num_class >= PRINT_EVENT_ID_MAX)
        return -EINVAL;

    if (kallsyms_lookup_symbols())
        return -ENODEV;

    trace_ring = tb_alloc(RB_BUFFER_SIZE, TB_FL_OVERWRITE);
    if (!trace_ring)
        return -ENOMEM;

    if (!proc_create_data(PROC_ENDPOINT, S_IRUSR, NULL,
                          &trace_pipe_fops, trace_ring))
        goto errorout;

    for (class_ptr = __start_print_event_class;
         class_ptr < __stop_print_event_class; class_ptr++) {
        struct print_event_class *class = *class_ptr;

        class->id = id++;
        class->trace = trace_ring;
    }
    pr_info("create %d print event class\n", num_class);

    return 0;

errorout:
    tb_free(trace_ring);

    return -ENOMEM;
}

static void print_event_exit(void)
{
    remove_proc_entry(PROC_ENDPOINT, NULL);
    if (trace_ring)
        tb_free(trace_ring);

    pr_info("destroy %d print event class\n", num_print_event_class());
}

KPROBE_INITCALL(print_event_init, print_event_exit);

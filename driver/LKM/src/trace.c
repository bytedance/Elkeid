// SPDX-License-Identifier: GPL-2.0
/*
 * trace.c
 *
 * Interfaces for ring-buffer based tracing
 */
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/version.h>
#include <linux/slab.h>
#include <linux/file.h>
#include <linux/anon_inodes.h>
#include <linux/utsname.h>

#include "../include/util.h"
#include "../include/trace.h"
#include "../include/kprobe.h"
#include "../include/filter.h"

/*
 * trace-buffer related
 */
#define SZ_32K              0x00008000
#define SZ_128K             0x00020000
#define RB_BUFFER_SIZE      SZ_128K
extern struct tb_ring *g_trace_ring;

/*
 * event format descriptions
 */

/* prototypes of event elements */
#define SD_XFER_META_SIZE(...)  ((SD_N_ARGS(__VA_ARGS__) + 3) * sizeof(uint32_t) * 2)
#define SD_XFER_META_XFER(...)  SD_XFER_META_SIZE(__VA_ARGS__)
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
    static struct sd_item_ent SD_XFER_PROTO_##n[] = {           \
        {{SD_XFER_META_##x}, {SD_XFER_TYPEID_##n}},             \
        {{sizeof(struct SD_XFER_EVENT_##n)},                    \
        SD_TYPE_##x,                                            \
        {{0}, {0}} };
#undef SD_XFER_DEFINE
#define SD_XFER_DEFINE(n, p, x) SD_XFER_DEFINE_P(n, p, x)

#include "../include/kprobe_print.h"
#include "../include/anti_rootkit_print.h"

#define SD_XFER_DEFINE_X(n, p, x)                               \
            { sizeof(SD_XFER_PROTO_##n), SD_XFER_TYPEID_##n,    \
              SD_XFER_PROTO_##n },
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

struct tb_ring *g_trace_ring;
static DEFINE_MUTEX(g_trace_lock);
static LIST_HEAD(trace_list);
static int trace_n_instances;

struct trace_instance {
    struct list_head next;
    struct tb_ring *ring;
    struct tb_event *event;

    /* opened instance tracking */
    char comm[TASK_COMM_LEN]; /* comm of owner process */
    char node[__NEW_UTS_LEN]; /* hostname or container name */
    pid_t owner; /* pid of the owner process */

    unsigned long lost_events;
    int cpu;
    u64 ts;
};

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 7, 0)
#define TRACE_SYMENT_ALLOC_FD
#define trace_get_unused_fd_flags(flags)  get_unused_fd_flags(flags)
#else
/* alloc_fd isn't exported until kernel 3.7.0 */
static int (*trace_alloc_fd)(unsigned start, unsigned flags);
#define TRACE_SYMENT_ALLOC_FD                           \
    { .name = "alloc_fd",                               \
      .addr = (void **)&trace_alloc_fd,                 \
      .optional = 0,                                    \
      .complete = 0},
#define trace_get_unused_fd_flags(flags) trace_alloc_fd(0, (flags))
#endif

struct _ksyms_entry {
    const char *name;
    void*      *addr;
    int         optional;
    int         complete;
} g_trace_ksyms[] = {
    TRACE_SYMENT_ALLOC_FD
    { .name = NULL,}
};

static int trace_init_ksyms(void)
{
    int i = 0;
    while (g_trace_ksyms[i].name) {
        struct _ksyms_entry *e = &g_trace_ksyms[i];
        if (e->complete && *e->addr)
            continue;
        *e->addr = (void *)smith_kallsyms_lookup_name(e->name);
        if (NULL == *e->addr && !e->optional) {
            printk("kernel symbol %s not found.\n", e->name);
            return -ENOTSUPP;
        }
        e->complete = (NULL != *e->addr);
        i++;
    }

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
        mutex_unlock(&g_trace_lock);
        ret = tb_wait(ti->ring, TB_RING_ALL_CPUS, 0);
        mutex_lock(&g_trace_lock);
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

    if (len + *used > cnt)
        return -EOVERFLOW;

    if (copy_to_user(ubuf + *used, tb_event_data(ti->event), len))
        return -EBADF;
    *used += len;

    return len;
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
        if (rc + 32 > cnt)
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
    list_del(&ti->next);
    trace_n_instances--;
    file->private_data = NULL;
    kfree(ti);
    fput(file);
    mutex_unlock(&g_trace_lock);

    module_put(THIS_MODULE);

    return 0;
}

static long trace_ioctl_pipe(struct file *filp, unsigned int cmd, unsigned long __user arg)
{
    struct trace_instance *ti = filp->private_data;
    long rc = -EINVAL;
    int i;

    if (cmd == TRACE_IOCTL_STAT) {
        struct tb_stat stat = {0};
        tb_stat(ti->ring, &stat);
        if (!smith_access_ok((void *)arg, sizeof(stat)))
            goto errorout;
        if (copy_to_user((void *)arg, &stat, sizeof(stat)))
            rc = -EFAULT;
        else
            rc = sizeof(stat);
    } else if (cmd == TRACE_IOCTL_FORMAT) {
        struct sd_event_format fmt = {0}, usr = {0};
        if (!smith_access_ok((void *)arg, sizeof(usr)))
            goto errorout;
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
    } else if ((cmd & TRACE_IOCTL_MASK) == TRACE_IOCTL_FILTER) {
        rc = g_flt_ops.ioctl(cmd, (const __user char *)arg);
    }

errorout:
    return rc;
}

static const struct file_operations trace_pipe_fops = {
    .release = trace_release_pipe,
    .read = trace_read_pipe,
    .unlocked_ioctl = trace_ioctl_pipe,
};

static int trace_init_pipe(void)
{
    struct trace_instance *ti;
    struct file *filp;
    int fd;

    ti = kzalloc(sizeof(*ti), GFP_KERNEL);
    if (!ti)
        return -ENOMEM;
    ti->ring = g_trace_ring;

    filp = anon_inode_getfile("trace_pipe", &trace_pipe_fops,
                              ti, O_RDWR | O_CLOEXEC);
    if (!filp) {
        kfree(ti);
        return -ENOMEM;
    }

    filp->f_mode |= FMODE_READ;
    fd = trace_get_unused_fd_flags(O_RDWR | O_CLOEXEC);
    if (fd < 0) {
        fput(filp);
        kfree(ti);
        return -ENOMEM;
    }

    /* tracing current task for this opened instance */
    ti->owner = current->pid;
    memcpy(ti->comm, current->comm, TASK_COMM_LEN);
    memcpy(ti->node, current->nsproxy->uts_ns->name.nodename, __NEW_UTS_LEN),

    mutex_lock(&g_trace_lock);
    trace_n_instances++;
    list_add_tail(&ti->next, &trace_list);
    mutex_unlock(&g_trace_lock);

    fd_install(fd, filp);
    __module_get(THIS_MODULE);
    return fd;
}

static int trace_show_instances(void)
{
    struct trace_instance *ti;
    int niters = 0;

    mutex_lock(&g_trace_lock);
    printk("trace proc_entry opened %d times:\n", trace_n_instances);
    list_for_each_entry(ti, &trace_list, next) {
        niters++;
        printk("%6d: %u %16s %s\n", niters, ti->owner, ti->comm, ti->node);
    }
    if (niters != trace_n_instances)
        printk("inconsistent values: %d %d\n", niters, trace_n_instances);
    mutex_unlock(&g_trace_lock);

    return 0;
}

static int __init print_event_init(void)
{
    if (trace_init_ksyms())
        return -ENOTSUPP;

    g_trace_ring = tb_alloc(RB_BUFFER_SIZE, TB_FL_OVERWRITE);
    if (!g_trace_ring)
        return -ENOMEM;

    return 0;
}

static void print_event_exit(void)
{
    if (g_trace_ring)
        tb_free(g_trace_ring);
}

KPROBE_INITCALL(trace, print_event_init, print_event_exit);

static char g_control_trace[64] = SMITH_VERSION;

#if defined(module_param_cb)
# define K_PARAM_CONST const
#else
# define K_PARAM_CONST
#endif

static int trace_get_control(char *val, K_PARAM_CONST struct kernel_param *kp)
{
    /*
     * Here we only use task->comm as a simple filtering for both security
     * enhancement and a workaround for LTP proc01 testcase. We would not
     * bother to use full-path comparison since root privilege is required
     * to access /proc/elkeid-endpoint.
     *
     * permitted progams:
     * 1, driver: agent plugin, can be one of the followings:
     *    - /etc/sysop/mongoosev3-agent/plugin/driver/driver
     *    - /etc/elkeid/plugin/driver/driver
     *    - /opt/proxima/plugin/driver/driver
     * 2, rst: the diagnostic program to show kernel events
     *    - .../LKM/test/rst
     *    - renamed to elkeid-'arch' for v1.9
     */
    char *agents[] = {"driver", "rst", NULL};
    int rc = 0, fd = -1;

    if (strcmp(kp->name, "control_trace"))
        return rc;

    if (smith_is_trusted_agent(agents)) {
        fd = trace_init_pipe();
        rc = scnprintf(val, PAGE_SIZE, "KMOD: " SMITH_VERSION " PIPE: %d\n", fd);
    } else {
        rc = scnprintf(val, PAGE_SIZE, "%s\n", g_control_trace);
    }

    return rc;
}

/* module prameters set callback */
static int trace_cmd_handler(const char *buf, int len)
{
    int rc = -EINVAL, cmd, i;

    /* remove spaces in prefix or suffix */
    for (i = 0; i < len; i++) {
        if (!isspace(buf[i]))
            break;
    }
    if (i >= len)
        return rc;
    cmd = buf[i];
    if (cmd <= 0)
        return rc;

    buf = buf + i + 1;
    if (cmd == OPEN_INSTANCES_LIST_ALL)
        rc = trace_show_instances();

    return rc;
}


static int trace_set_control(const char *val, K_PARAM_CONST struct kernel_param *kp) 
{
    if (0 == strcmp(kp->name, "control_trace"))
        if (trace_cmd_handler(val, PAGE_SIZE))
            return g_flt_ops.store(val, PAGE_SIZE);
    return 0;
}

#if defined(module_param_cb)
const struct kernel_param_ops trace_control_ops = {
    .set = trace_set_control,
    .get = trace_get_control,
};
module_param_cb(control_trace, &trace_control_ops, &g_control_trace, 0600);
#elif defined(module_param_call)
module_param_call(control_trace, trace_set_control, trace_get_control, &g_control_trace, 0600);
#else
# warning "moudle_param_cb or module_param_call are not supported by target kernel"
#endif
MODULE_PARM_DESC(control_trace, "control for tracing and filtering");

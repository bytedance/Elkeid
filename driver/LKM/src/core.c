// SPDX-License-Identifier: GPL-2.0

#include "ring.h"
#include "slot.h"
#include "util.h"

struct ring_slot        g_rs_ring;
uint32_t                g_rs_dbg = D_ERR;

#define RS_USE_VMALLOC  (1)
/*
 * wrapper for ktime_get_real_seconds
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 11, 0)
uint64_t rs_get_seconds(void)
{
    return ktime_get_real_seconds();
}
#define RS_SYMENT_KTIME_GET_REAL_SECONDS
#else /* < 5.11.0 */
static uint64_t (*rs_ktime_get_real_seconds)(void);
uint64_t rs_get_seconds(void)
{
    if (rs_ktime_get_real_seconds)
        return rs_ktime_get_real_seconds();
    else
        return get_seconds();
}
#define RS_SYMENT_KTIME_GET_REAL_SECONDS                \
    { .name = "ktime_get_real_seconds",                 \
      .addr = (void **)&rs_ktime_get_real_seconds,      \
      .optional = 1,                                    \
      .complete = 0},
#endif /* >= 5.11.0 */

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 7, 0)
#define RS_SYMENT_ALLOC_FD
#define rs_get_unused_fd_flags(flags)  get_unused_fd_flags(flags)
#else
/* alloc_fd isn't exported until kernel 3.7.0 */
static int (*rs_alloc_fd)(unsigned start, unsigned flags);
#define RS_SYMENT_ALLOC_FD                              \
    { .name = "alloc_fd",                               \
      .addr = (void **)&rs_alloc_fd,                    \
      .optional = 1,                                    \
      .complete = 0},
#define rs_get_unused_fd_flags(flags) rs_alloc_fd(0, (flags))
#endif

struct _func_entry {
    const char *name;
    void*      *addr;
    int         optional;
    int         complete;
} g_rs_kern_syms[] = {
    RS_SYMENT_KTIME_GET_REAL_SECONDS
    RS_SYMENT_ALLOC_FD
    { .name = NULL,}
};

unsigned long smith_kallsyms_lookup_name(const char *name);
int rs_init_kern_syms(void)
{
    int i = 0;
    while (g_rs_kern_syms[i].name) {
        struct _func_entry *e = &g_rs_kern_syms[i];
        if (e->complete && *e->addr)
            continue;
        *e->addr = (void *)smith_kallsyms_lookup_name(e->name);
        if (NULL == *e->addr && !e->optional) {
            RSERROR("kernel symbol %s not found.\n", e->name);
            return -ENOTSUPP;
        }
        e->complete = (NULL != *e->addr);
        i++;
    }

    return 0;
}

/*
 * file_operations of the anonymous memory-mapped file
 */
static int rs_cc_close(struct inode *inode, struct file *filp)
{
    struct ring_slot *rs = filp->private_data;
    int    rc = 0;

    RSDEBUG(D_INFO, "rs_cc_close called for task %s (%px).\n",
                    current->comm, current);
    /* private data shouldn't be NULL, do checking anyway */
    RS_BUG(!rs);
    if (!rs) {
        RSERROR("rs_cc_close: invalid rs.\n");
        GOTO(rc = -EINVAL);
    }

    mutex_lock(&rs->rs_kern.rk_mutex);
    /* do cleaning up anyway */
    rs->rs_kern.rk_task = NULL;
    rs->rs_head.rh_mmap_fd = -ENOENT;
    if (rs->rs_kern.rk_filp) {
        fput(rs->rs_kern.rk_filp);
        rs->rs_kern.rk_filp = NULL;
    }
    mutex_unlock(&rs->rs_kern.rk_mutex);

    /* prepare filp for recycling */
	filp->private_data = NULL;

errorout:
	return rc;
}

static ssize_t rs_cc_write(struct file *filp, const char __user *buf,
                           size_t len, loff_t * off)
{
    RSDEBUG(D_FUNC, "rs_cc_write called.\n");
    return -ENOTSUPP;
}

/*
 * wrapper of copy_to_user
 */
static ssize_t rs_copy_to_user(__user char *to, void *from, int len)
{
    int size = 0;

    do {
        size += len - size - copy_to_user(to + size, from + size, len - size);
    } while (size < len);

    return size;
}

#define rs_delta(p1, p2)    ((uint32_t)(long)((char *)(p1) - (char *)(p2)))

static ssize_t rs_copy_work(struct ring_slot *rs, __user char *buf)
{
    ssize_t rc = 0;
    int i;

    for (i = 0; i < rs->rs_head.rh_cpus_num; i++) {

        struct slot_work *sw = &rs->rs_works[i];
        struct comm_work cw;

        /* actual values */
        cw.cw_start = sw->sw_start; 
        cw.cw_realsz = sw->sw_realsz;
        cw.cw_size = sw->sw_size;
        cw.cw_mask = sw->sw_mask;
        cw.cw_cpuid = sw->sw_cpuid;

        /* offset from cw_start */
        cw.cw_ents = rs_delta(sw->sw_ents, rs->rs_mmap);
        cw.cw_used = rs_delta(sw->sw_used, rs->rs_mmap);
        cw.cw_data = rs_delta(sw->sw_data, rs->rs_mmap);
        cw.cw_head = rs_delta(sw->sw_head, rs->rs_mmap);
        cw.cw_tail = rs_delta(sw->sw_tail, rs->rs_mmap);
        cw.cw_waits = rs_delta(sw->sw_waits, rs->rs_mmap);
        cw.cw_flags = rs_delta(sw->sw_flags, rs->rs_mmap);
        cw.cw_npros = rs_delta(sw->sw_npros, rs->rs_mmap);
        cw.cw_ncons = rs_delta(sw->sw_ncons, rs->rs_mmap);
        cw.cw_ndrop = rs_delta(sw->sw_ndrop, rs->rs_mmap);
        cw.cw_ndisc = rs_delta(sw->sw_ndisc, rs->rs_mmap);
        cw.cw_cpros = rs_delta(sw->sw_cpros, rs->rs_mmap);
        cw.cw_ccons = rs_delta(sw->sw_ccons, rs->rs_mmap);
        cw.cw_cdrop = rs_delta(sw->sw_cdrop, rs->rs_mmap);
        cw.cw_cdisc = rs_delta(sw->sw_cdisc, rs->rs_mmap);
        cw.cw_nexcd = rs_delta(sw->sw_nexcd, rs->rs_mmap);
        cw.cw_maxsz = rs_delta(sw->sw_maxsz, rs->rs_mmap);

        /* copy to user buffer */
        rc += rs_copy_to_user(buf + rc, &cw, sizeof(cw));
    }

    return rc;
}

static ssize_t rs_copy_mmap(struct ring_slot *rs, __user char *buf)
{
    struct ring_mmap *rm = rs->rs_mmap;
    struct comm_mmap  cm = {0};

    cm.cm_cpus_map = rs_delta(rs->rs_cpus_map, rm);
    cm.cm_cpus_num = rs_delta(rs->rs_cpus_num, rm);
    cm.cm_eflags = rs_delta(rs->rs_eflags, rm);
    cm.cm_waits = rs_delta(rs->rs_waits, rm);
    cm.cm_cores = rs_delta(rm->rm_cores, rm);

    return rs_copy_to_user(buf, &cm, sizeof(cm));
}

static ssize_t rs_copy_core(struct ring_slot *rs, __user char *buf)
{
    ssize_t rc = 0;

    rc += rs_copy_mmap(rs, buf);
    if (rc < sizeof(struct comm_mmap))
        return 0;

    return (rc + rs_copy_work(rs, buf + rc));
}

static int rs_setup_mmap(struct ring_slot *rs);
static int rs_setup_fd(struct ring_slot *rs)
{
    int fd = rs_get_unused_fd_flags(O_RDWR | O_CLOEXEC);
    if (fd < 0) {
        RSERROR("rs_setup_fd: task %px failed to get fd.\n", current);
        return fd;
    }
    RSDEBUG(D_INFO, "rs_setup_fd: task %s(%px) got fd:%d for filp:%px\n",
                    current->comm, current, fd, rs->rs_kern.rk_filp);
    fd_install(fd, rs->rs_kern.rk_filp);
    return (int)(rs->rs_head.rh_mmap_fd = fd);
}

static ssize_t rs_copy_head(struct ring_slot *rs, __user char *buf)
{
    struct ring_head head;

    mutex_lock(&rs->rs_kern.rk_mutex);
    if (rs->rs_kern.rk_task) {
        rs_memcpy(&head, rs, sizeof(head));
        /* return zero fd for processes other than HIDS agent */
        if (current != rs->rs_kern.rk_task)
            head.rh_mmap_fd = -ENOENT;
        RSDEBUG(D_INFO, "rs_copy_head_fd: task %s (%px) got fd:%d.\n",
                        current->comm, current, head.rh_mmap_fd);
    } else {
        /* TODO: only HIDS agent proces permitted */
        /* create the anonymous memory-mapped virtual file */
        if (0 == rs_setup_mmap(rs)) {
            /* user process must be HIDS agent */
            /* TODO: verify process name etc */
            if (rs_setup_fd(rs) >= 0) {
                rs->rs_kern.rk_task = current;
            } else {
                /* got error when allocating fd */
                fput(rs->rs_kern.rk_filp);
                rs->rs_kern.rk_filp = NULL;
            }
        }
        rs_memcpy(&head, rs, sizeof(head));
        RSDEBUG(D_INFO, "rs_copy_head_fd: task %s (%px) got new fd:%d.\n",
                         current->comm, current, head.rh_mmap_fd);
    }
    mutex_unlock(&rs->rs_kern.rk_mutex);

    return rs_copy_to_user(buf, &head, sizeof(head));
}


static uint32_t rs_query_used(struct ring_slot *rs)
{
    struct slot_work *work;
    uint32_t used = 0;
    int cpu;

    for (cpu = 0; cpu < rs->rs_head.rh_cpus_num; cpu++) {
        work = &rs->rs_works[cpu];
        used += *work->sw_used;
    }

    return used;
}

static int rs_poll_cond(struct ring_slot *rs)
{
	return ((rs_query_used(rs) << 1) >= rs->rs_head.rh_core_mask);
}

static int rs_wake_ring(struct ring_slot *rs)
{
    if (!rs_poll_cond(rs))
        return 0;
    wake_up(&rs->rs_waitq);
    return 1;
}

static int rs_poll_ring(struct ring_slot *rs)
{
    int rc;

    RSDEBUG(D_INFO, "tasks %s going to sleep ...\n", current->comm);
    /* pending current task as interruptible, timeout set as 100ms */
    rc = wait_event_interruptible_timeout(rs->rs_waitq, rs_poll_cond(rs),  HZ / 10);
    RSDEBUG(D_INFO, "tasks %s waked up.\n", current->comm);
    return rc;
}

static ssize_t rs_cc_read(struct file *filp, char __user *buf,
                          size_t len, loff_t * off)
{
    struct ring_slot *rs = filp->private_data;
    ssize_t rc = 0;

    /* private data shouldn't be NULL, do checking anyway */
    RS_BUG(!rs);

    if (!off || !RS_IS_VALID_RING(rs))
        return -EINVAL;

    /* ring polling */
    if (4 == len && *off == rs->rs_head.rh_cpus_mmap +
        rs_delta(rs->rs_waits, rs->rs_mmap)) {
        rc = rs_poll_ring(rs);
        goto errorout;
    }

    /* user mode process is initialzing ... */
    if (*off != 0)
        return -EINVAL;
    if (rs->rs_head.rh_size > len)
        return -EOVERFLOW;

    rc += rs_copy_head(rs, buf);
    if (rc < rs->rs_head.rh_size)
        goto errorout;

    if (len >= RING_MMAP_BASE(rs->rs_head.rh_cpus_num))
        rc += rs_copy_core(rs, buf + rs->rs_head.rh_size);
errorout:
    return rc;
}

static void *rs_cc_query_mmap(struct file *filp, loff_t off, size_t *len)
{
    struct ring_slot *rs = filp->private_data;
    struct ring_head *rh = &rs->rs_head;
    void *ptr = NULL;

    if (len)
        *len = 0;

    /* fits the cpu work zone ? */
    if (off >= rh->rh_cpus_mmap && 
        off < rh->rh_cpus_mmap + rh->rh_cpus_size) {
        ptr = (void *)rs->rs_mmap + off - rh->rh_cpus_mmap;
        if (len)
            *len = rh->rh_cpus_mmap + rh->rh_cpus_size - off;
    } else {
        int i;
        for (i = 0; i < rs->rs_head.rh_cpus_num; i++) {
            struct slot_work *work = &rs->rs_works[i];
            if (off >= work->sw_start &&
                off < work->sw_start + work->sw_realsz) {
                ptr = work->sw_slot + off - work->sw_start;
                if (len)
                    *len = (size_t)(work->sw_start + work->sw_realsz - off);
                break;
            }
        }
    }

    return ptr;
}

static int rs_cc_mmap(struct file *filp, struct vm_area_struct *vma)
{
    size_t size = vma->vm_end - vma->vm_start, start = 0, remain;
    loff_t off = (loff_t)vma->vm_pgoff << PAGE_SHIFT;
    int rc = 0;

    while (start < size) {
        struct page *page = NULL;
    	void *ptr;

        /* vm_pgoff is the actual offset (by pages) in mmap file */
        ptr = rs_cc_query_mmap(filp, off + start, &remain);
        if (ptr)
#if RS_USE_VMALLOC
            page = vmalloc_to_page(ptr);
#else
            page = virt_to_page(ptr);
#endif
        
        if (page) {
            rc = remap_pfn_range(vma, vma->vm_start + start,
                                 page_to_pfn(page),
                                 rs_page_size(page),
                                 vma->vm_page_prot);
            if (rc)
                RSERROR("rs_cc_mmap: failed to remap page: %px\n", ptr);
            else
                RSDEBUG(D_INFO, "rs_cc_mmap: %px mapped to %px off: %xh\n",
                        ptr, (void *)vma->vm_start + start,
                        (uint32_t)(off + start));
            if (rs_page_size(page) > remain)
                start += remain;
            else
                start += rs_page_size(page);
        } else {
            start += PAGE_SIZE;
        }
    }

    return 0;
}

static const struct file_operations rs_cc_fops = {
        .owner = THIS_MODULE,
      	.release = rs_cc_close,
        .read = rs_cc_read,
        .write = rs_cc_write,
        .mmap = rs_cc_mmap,
};

static int rs_setup_mmap(struct ring_slot *rs)
{
	struct file *filp;

    if (rs->rs_kern.rk_filp)
        return 0;

    filp = anon_inode_getfile("ringslot", &rs_cc_fops, rs, O_RDWR | O_CLOEXEC);
    rs->rs_kern.rk_filp = filp;
    if (filp) {
        filp->f_mode |= FMODE_PREAD;
        RSDEBUG(D_INFO, "rs_setup_mmap: task %px got filp %px\n", current, filp);
        return 0;
    } else {
        RSDEBUG(D_ERR, "rs_setup_mmap: task %px failed to getfile.\n", current);
        return -ENOENT;
    }
}

/*
 * per-cpu core management structures
 * 
 * percpu slot buffer never deallocated, since it may come online
 */

static int rs_is_core_ready(struct ring_slot *rs, int cpu)
{
    if (cpu >= RS_NR_CPUS || !rs->rs_mmap)
        return 0;
    return test_bit(cpu, (void *)rs->rs_cpus_map);
}

static void rs_mark_core_ready(struct ring_slot *rs, int cpu)
{
    if (cpu < RS_NR_CPUS && rs->rs_mmap)
        set_bit(cpu, (void *)rs->rs_cpus_map);
}

static void rs_mark_core_invalid(struct ring_slot *rs, int cpu)
{
    if (cpu < RS_NR_CPUS && rs->rs_cpus_map)
        clear_bit(cpu, (void *)rs->rs_cpus_map);
}

static void *rs_alloc_memory(unsigned long size, int nid)
{
#if RS_USE_VMALLOC
    return vmalloc_node(size, nid);
#else
    return kmalloc_node(size, GFP_KERNEL, nid);
#endif
}

static void rs_free_memory(void *ptr, unsigned long size)
{
    if (ptr)
#if RS_USE_VMALLOC
        vfree(ptr);
#else
        kfree(ptr);
#endif
}

static void *rs_alloc_pages(unsigned long size, int nid)
{
    struct page *pg;
    size = size >> PAGE_SHIFT;
    if (!size)
        size = 1;
    pg = alloc_pages_node(nid, GFP_KERNEL, ilog2(size));
    if (!pg)
        return NULL;
    return (void *)page_address(pg);
}

static void rs_free_pages(void *p, unsigned long size)
{
    size = size >> PAGE_SHIFT;
    if (!size)
        size = 1;

    if (p)
        free_pages((unsigned long)p, ilog2(size));
}

static int rs_init_core_slot(struct ring_slot *rs, int cpu)
{
    struct ring_head *head;
    struct slot_core *core;
    struct slot_work *work;
    int rc = 0;

    if (cpu >= RS_NR_CPUS)
        GOTO(rc = -1);

    head = &rs->rs_head;
    core = &rs->rs_mmap->rm_cores[cpu];
    work = &rs->rs_works[cpu];

    /* allocate ring_slot for current cpu */
    if (rs_is_ring_flex(rs))
        work->sw_slot = rs_alloc_memory(head->rh_core_size,
                                        cpu_to_node(cpu));
    else
        work->sw_slot = rs_alloc_pages(head->rh_core_size,
                                       cpu_to_node(cpu));
    if (!work->sw_slot)
        GOTO(rc = -ENOMEM);
    rs_memset(work->sw_slot, 0, head->rh_core_size);

    /* initialize the ring work item */
    work->sw_realsz = head->rh_core_size;
    work->sw_size = head->rh_core_mask + 1;
    work->sw_mask = head->rh_core_mask;
    work->sw_start = CORE_MMAP_START(rs, work, cpu);
    work->sw_ents = &core->sc_ents;
    work->sw_head = &core->sc_head;
    work->sw_tail = &core->sc_tail;
    work->sw_used = &core->sc_used;
    work->sw_data = &core->sc_data;
    work->sw_npros = &core->sc_npros;
    work->sw_ncons = &core->sc_ncons;
    work->sw_ndrop = &core->sc_ndrop;
    work->sw_ndisc = &core->sc_ndisc;
    work->sw_cpros = &core->sc_cpros;
    work->sw_ccons = &core->sc_ccons;
    work->sw_cdrop = &core->sc_cdrop;
    work->sw_cdisc = &core->sc_cdisc;
    work->sw_flags = &core->sc_flags;
    work->sw_waits = &core->sc_waits;
    work->sw_maxsz = &core->sc_maxsz;
    work->sw_nexcd = &core->sc_nexcd;
    work->sw_cpuid = cpu + 1;

    /* verity the overflow case */
    core->sc_head = core->sc_tail = (uint32_t)0 - work->sw_size;

    RSDEBUG(D_INFO, "core %d inited with slot: %px (%u bytes)\n",
                    cpu, work->sw_slot, head->rh_core_size);
    rs_mark_core_ready(rs, cpu);

errorout:
    return rc;
}

static void rs_fini_core_slot(struct ring_slot *rs, int cpu)
{
    struct slot_work *sw = &rs->rs_works[cpu];

    if (!rs_is_core_ready(rs, cpu))
        return;

    if (sw->sw_slot) {
        if (rs_is_ring_flex(rs))
            rs_free_memory(sw->sw_slot, sw->sw_realsz);
        else
            rs_free_pages(sw->sw_slot, sw->sw_realsz);
        sw->sw_slot = NULL;
        sw->sw_size = sw->sw_mask = 0;
    }
    rs_mark_core_invalid(rs, cpu);
}

static ssize_t rs_ep_read(struct file *filp, char __user *buf,
                          size_t len, loff_t *off)
{
    struct ring_slot *rs = NULL;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
    rs = (struct ring_slot *)(PDE_DATA(filp->f_inode));
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3, 9, 0)
    rs = (struct ring_slot *)(PDE(filp->f_inode)->data);
#else
    if (filp->f_path.dentry && filp->f_path.dentry->d_inode)
        rs = (struct ring_slot *)(PDE(filp->f_path.dentry->d_inode)->data);
#endif

    if (*off != 0 || !RS_IS_VALID_RING(rs))
        return -EINVAL;
    if (rs->rs_head.rh_size > len)
        return -EOVERFLOW;

    return rs_copy_head(rs, buf);
}

static ssize_t rs_ep_write(struct file *filp, const char __user *buf,
                           size_t len, loff_t * off)
{
    return -ENOTSUPP;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 6, 0)
static const struct proc_ops rs_ep_fops = {
    .proc_read = rs_ep_read,
    .proc_write = rs_ep_write,
};
#else
static const struct file_operations rs_ep_fops = {
    .owner = THIS_MODULE,
    .read = rs_ep_read,
    .write = rs_ep_write,
};
#endif

static int rs_init_kern_ring(struct ring_slot *rs)
{
    struct proc_dir_entry *de = NULL;
    int rc = 0;

    /* initialize the kpart of the rs structure */
    spin_lock_init(&rs->rs_kern.rk_lock);
    mutex_init(&rs->rs_kern.rk_mutex);

    /* create proc entry for user communication */
    de = proc_create_data(RS_EP_NODE, 0600, 0, &rs_ep_fops, rs);
    if (!de)
        GOTO(rc = -ENOMEM);
    rs->rs_kern.rk_proc = de;
    init_waitqueue_head(&rs->rs_waitq);

errorout:
    return rc;
}

static void rs_fini_kern_ring(struct ring_slot *rs)
{
    /* destroy proc entry of HIDS EndPoint */
    if (rs->rs_kern.rk_proc) {
        remove_proc_entry(RS_EP_NODE, NULL);
        /* proc_remove(rs->rs_kern.rk_proc); */
        rs->rs_kern.rk_proc = NULL;
    }

    /* cleanup the anonymous mmap file */
    if (rs->rs_kern.rk_filp) {
        fput(rs->rs_kern.rk_filp);
        rs->rs_kern.rk_filp = NULL;

        wake_up_all(&rs->rs_waitq);
    }
}

static inline int rs_query_cores(void)
{
    return num_present_cpus();
}

static int rs_init_work_ring(struct ring_slot *rs)
{
    struct ring_mmap *rm = NULL;
    int    rc = 0, i;

    /* allocate cpu bitmap & slots */
    rm = rs_alloc_memory(RING_MMAP_SIZE, numa_node_id());
    if (!rm)
        GOTO(rc = -ENOMEM);
    rs_memset(rm, 0, RING_MMAP_SIZE);
    rs->rs_cpus_map = &rm->rm_cpus.rc_cpus_map[0];
    rs->rs_cpus_num = &rm->rm_cpus.rc_cpus_num;
    rs->rs_waits = &rm->rm_cpus.rc_waits;
    rs->rs_mmap = rm;
    RSDEBUG(D_INFO, "rs_init_work_ring: mmap inited: %px (%xh bytes).\n",
                     rm, (unsigned int)RING_MMAP_SIZE);
    /* initialize slot zones: mmap per cpu */
    for (i = 0; i < rs_query_cores(); i++) {

        /* initialize slot_core and slot_work */
        if (rs_init_core_slot(rs, i)) {
            GOTO(rc = -ENOMEM);
        }
        rm->rm_cpus.rc_cpus_num = rs->rs_head.rh_cpus_num = i + 1;
    }

#if 0
    /* backup ring_core to rs_kern */
    rs->rs_kern.rk_cpus = rm->rm_cpus;
#endif

errorout:
    return rc;
}

static void rs_fini_work_ring(struct ring_slot *rs)
{
    int i;

    /*
     * cleanup rs kernel part
     */
    rs_fini_kern_ring(rs);

    /*
     * cleanup the mmap zone
     */

    /* skip if rs_mmap is NOT yet initialized */
    if (!rs->rs_mmap)
        return;

    /* clean slot zones: mmap per cpu */
    for (i = 0; i < rs->rs_head.rh_cpus_max; i++) {
        if (rs_is_core_ready(rs, i))
            rs_fini_core_slot(rs, i);
    }
    rs_free_memory(rs->rs_mmap, RING_MMAP_SIZE);
}

int rs_init_head_ring(struct ring_slot *rs, int mode, uint32_t slotlen)
{
    struct ring_head *rh = &rs->rs_head;

    /* skip if ring slot was already initialized */
    if (RING_SLOT_MAGIC == rh->rh_magic) {
        return -1;
    }

    /* do structure initializing */
    rh->rh_magic = RING_SLOT_MAGIC;
    rh->rh_size = sizeof(struct ring_head);
    rh->rh_flags = 0;
    rh->rh_mode = mode;
    rh->rh_dawning = rs_get_seconds();
    rh->rh_cpus_max = RS_NR_CPUS;
    rh->rh_cpus_mmap = RING_MMAP_BASE(RS_NR_CPUS);
    rh->rh_cpus_size = RING_MMAP_SIZE;
    rh->rh_core_mmap = CORE_MMAP_BASE(rs);
    if (slotlen < SLOT_RECORD_MAX * 4)
        slotlen = SLOT_RECORD_MAX * 4;
    if (rs_is_ring_flex(rs))
        rh->rh_core_size = slotlen + ((SLOT_RECORD_MAX * 2) > PAGE_SIZE ?
                                      (SLOT_RECORD_MAX * 2) : PAGE_SIZE);
    else
        rh->rh_core_size = slotlen;
    rh->rh_core_mask = slotlen - 1;
    rh->rh_core_zone = ALIGN(rh->rh_core_size, 1UL << 20);

    return 0;
}

static void rs_fini_head_ring(struct ring_slot *rs)
{
    rs_memset(rs, 0, sizeof(*rs));
}

void rs_fini_ring(void)
{
    struct ring_slot *rs = &g_rs_ring;

    if (RING_SLOT_MAGIC != rs->rs_head.rh_magic) {
        RSERROR("entity was NOT yet initialized.\n");
        return;
    }

    /* cleanup kernel-specific zone */
    rs_fini_kern_ring(rs);

    /* cleanup ring work */
    rs_fini_work_ring(rs);

    /* cleanup ring head */
    rs_fini_head_ring(rs);
}

int rs_init_ring(int mode, int slotlen)
{
    struct ring_slot *rs = &g_rs_ring;
    int rc = 0;

    /* whether present cores exceed NR_CPUS */
    if (num_present_cpus() > RS_NR_CPUS) {
        printk("CPU count %d exceeds 256.\n", num_present_cpus());
        GOTO(rc = -EOPNOTSUPP);
    }

    /* query kernel routines from symbols */
    if (rs_init_kern_syms())
        GOTO(rc = -EOPNOTSUPP);

    /* initilaze common head of ring slot */
    if (rs_init_head_ring(rs, mode, slotlen))
        GOTO(rc = -EOPNOTSUPP);

    /* initialize core percpu works */
    if (rs_init_work_ring(rs))
       GOTO(rc = -ENOMEM);        

    /* intialize kernel-specific elements */
    if (rs_init_kern_ring(rs))
        GOTO(rc = -ENOMEM);

    RSDEBUG(D_INFO, "rs: entity initialized.\n");
    return 0;

errorout:
    rs_fini_ring();
    return rc;
}

int rs_vsprint_slot(struct ring_slot *rs, const char *fmt, va_list args);
int rs_vsprint_ring(const char *fmt, ...)
{
    int rc = 0;
    va_list args;

    va_start(args, fmt);
    rc = rs_vsprint_slot(&g_rs_ring, fmt, args);
    va_end(args);

    if (rc)
        rs_wake_ring(&g_rs_ring);

    return rc;
}

int rs_write_slot(struct ring_slot *rs, void *msg, int len);
int rs_write_ring(void *msg, int len)
{
    int rc = rs_write_slot(&g_rs_ring, msg, len);
    if (rc)
        rs_wake_ring(&g_rs_ring);
    return rc;
}

int rs_read_slot(struct ring_slot *rs, void *msg, int len, int cpu);
int rs_read_ring(char *msg, int len, int cpu)
{
    return rs_read_slot(&g_rs_ring, msg, len, cpu);
}

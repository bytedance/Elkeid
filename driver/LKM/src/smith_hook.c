// SPDX-License-Identifier: GPL-2.0
/*
 * smith_hook.c
 *
 * Hook some kernel function
 */
#include <linux/kthread.h>
#include <linux/moduleparam.h>
#include <linux/highmem.h>

#include "../include/smith_hook.h"
#include "../include/trace.h"

/*
 * network related header files
 */
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#if IS_ENABLED(CONFIG_IPV6)
#include <linux/ipv6.h>
#include <net/ipv6.h> /* ipv6_addr_any */
#include <linux/netfilter_ipv6.h>
#endif

/* mount_ns and pid_ns id for systemd process */
static void *ROOT_MNT_NS;
static void *ROOT_MNT_SB;
static uint64_t ROOT_MNT_NS_ID;

#undef SD_XFER_DEFINE
#define SD_XFER_DEFINE(n, p, x) SD_XFER_DEFINE_N(n, p, x)
#include "../include/kprobe_print.h"

#define EXIT_PROTECT 0
#define SANDBOX 0

#define SMITH_MAX_ARG_STRINGS (16)
#define SMITH_MAX_CMDLINE     SD_STR_MAX

#define SMITH_HOOK(name, on)                    \
    static int name##_HOOK = (on);              \
    module_param(name##_HOOK, int, S_IRUSR|S_IRGRP|S_IROTH)

// Hookpoint switch defintions

SMITH_HOOK(CONNECT, 1);
SMITH_HOOK(BIND, 1);
SMITH_HOOK(EXECVE, 1);
SMITH_HOOK(CREATE_FILE, 1);
SMITH_HOOK(PTRACE, 1);
SMITH_HOOK(MODULE_LOAD, 1);
SMITH_HOOK(UPDATE_CRED, 1);
SMITH_HOOK(RENAME, 1);
SMITH_HOOK(LINK, 1);
SMITH_HOOK(SETSID, 1);
SMITH_HOOK(PRCTL, 1);
SMITH_HOOK(MEMFD_CREATE, 1);
SMITH_HOOK(MOUNT, 1);
SMITH_HOOK(DNS, 1);
SMITH_HOOK(USERMODEHELPER, 1);
SMITH_HOOK(UDEV, 1);
SMITH_HOOK(CHMOD, 1);

SMITH_HOOK(WRITE, 0);
SMITH_HOOK(ACCEPT, 0);
SMITH_HOOK(OPEN, 0);
SMITH_HOOK(CLOSE, 1);
SMITH_HOOK(MPROTECT, 0);
SMITH_HOOK(NANOSLEEP, 0);
SMITH_HOOK(KILL, 0);
SMITH_HOOK(RM, 0);
SMITH_HOOK(EXIT, 0);

static int FAKE_SLEEP = 0;
static int FAKE_RM = 0;

static int PID_TREE_LIMIT = 12;
static int PID_TREE_LIMIT_LOW = 8;
static int EXECVE_GET_SOCK_PID_LIMIT = 4;
static int EXECVE_GET_SOCK_FD_LIMIT = 12;  /* maximum fd numbers to be queried */

static char create_file_kprobe_state = 0x0;
static char update_cred_kprobe_state = 0x0;
static char mprotect_kprobe_state = 0x0;
static char mount_kprobe_state = 0x0;
static char rename_kprobe_state = 0x0;
static char link_kprobe_state = 0x0;
static char open_kprobe_state = 0x0;
static char openat_kprobe_state = 0x0;
static char exit_kprobe_state = 0x0;
static char exit_group_kprobe_state = 0x0;
static char security_path_rmdir_kprobe_state = 0x0;
static char security_path_unlink_kprobe_state = 0x0;
static char call_usermodehelper_exec_kprobe_state = 0x0;
static char write_kprobe_state = 0x0;

#if (EXIT_PROTECT == 1) && defined(MODULE)
void exit_protect_action(void)
{
	__module_get(THIS_MODULE);
}
#endif

/*
 * delayed put_files_struct
 */

static void (*put_files_struct_sym) (struct files_struct * files);

struct delayed_put_node {
    struct memcache_node cache;
    struct delayed_put_node *next;
    union {
        struct file *filp;
        struct files_struct *files;
    };
    uint32_t flag_pool:1;
    uint32_t type:8;  /* 0: file, 1: files */
};

struct memcache_head g_delayed_put_root;

static struct delayed_put_node *smith_alloc_delayed_put_node(void)
{
    struct memcache_node *mnod;

    mnod = memcache_pop(&g_delayed_put_root);
    if (mnod) {
        struct delayed_put_node *dnod;
        dnod = container_of(mnod, struct delayed_put_node, cache);
        dnod->flag_pool = 1;
        return dnod;
    }
    return smith_kzalloc(sizeof(struct delayed_put_node), GFP_ATOMIC);
}

static void smith_free_delayed_put_node(struct delayed_put_node *dnod)
{
    if (dnod->flag_pool)
        memcache_push(&dnod->cache, &g_delayed_put_root);
    else
        smith_kfree(dnod);
}

static struct task_struct *g_delayed_put_thread;
static struct delayed_put_node *g_delayed_put_queue;
static spinlock_t g_delayed_put_lock;

static struct delayed_put_node *smith_deref_head_node(void)
{
    struct delayed_put_node *dnod;

    /* retrive head node from delayed put queue */
    spin_lock(&g_delayed_put_lock);
    dnod = g_delayed_put_queue;
    if (dnod)
        g_delayed_put_queue = dnod->next;
    spin_unlock(&g_delayed_put_lock);

    /* do actual put_files_struct or fput */
    if (dnod) {
        if (1 == dnod->type)
            put_files_struct_sym(dnod->files);
        else if (0 == dnod->type)
            fput(dnod->filp);
        smith_free_delayed_put_node(dnod);
    }

    return dnod;
}

static int smith_delayed_put_worker(void *argv)
{
    struct delayed_put_node *dnod;
    unsigned long timeout = msecs_to_jiffies(1000 * 60);

    do {
        dnod = smith_deref_head_node();
        if (dnod)
            continue;
        schedule_timeout_interruptible(timeout);
    } while (!kthread_should_stop());

    return 0;
}

static int __init smith_start_delayed_put(void)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 6, 0)
    int nobjs = EXECVE_GET_SOCK_PID_LIMIT * 2; /* currently only for files_struct */
#else
    int nobjs = EXECVE_GET_SOCK_PID_LIMIT * EXECVE_GET_SOCK_FD_LIMIT;
#endif

    spin_lock_init(&g_delayed_put_lock);
    g_delayed_put_thread = kthread_create(smith_delayed_put_worker, 0, "elkeid - dput");
    if (IS_ERR(g_delayed_put_thread)) {
        int rc = g_delayed_put_thread ? PTR_ERR(g_delayed_put_thread) : -ENOMEM;
        printk("smith_start_delayed_put: failed creating dealyed_fput worker: %d\n", rc);
        return rc;
    }

    /* initialize memory cache for dnod, errors to be ignored,
       if fails, new node will be allocated from system slab */
    memcache_init_pool(&g_delayed_put_root, nobjs * num_possible_cpus(),
                       sizeof(struct delayed_put_node), 0, NULL, NULL);

    return 0;
}

static void smith_stop_delayed_put(void)
{
    /* kthread_stop will wait until worker thread exits */
    if (!IS_ERR_OR_NULL(g_delayed_put_thread)) {
        kthread_stop(g_delayed_put_thread);
    }

    /* make sure no records leaked */
    while (g_delayed_put_queue)
        smith_deref_head_node();

    memcache_fini(&g_delayed_put_root, NULL, NULL);
}

static void smith_insert_delayed_put_node(struct delayed_put_node *dnod)
{
    /* attach dnod to deayed_fput_queue */
    spin_lock(&g_delayed_put_lock);
    dnod->next = g_delayed_put_queue;
    g_delayed_put_queue = dnod;
    spin_unlock(&g_delayed_put_lock);
    wake_up_process(g_delayed_put_thread);
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 6, 0)
static void smith_fput(struct file *filp)
{
    fput(filp);
}
#else
static void smith_fput(struct file *filp)
{
    struct delayed_put_node *dnod;

    /* just loop until we get a new recrod */
    do {
        dnod = smith_alloc_delayed_put_node();
    } while (!dnod);

    dnod->type = 0;
    dnod->filp = filp;

    /* attach dnod to deayed_put_queue */
    smith_insert_delayed_put_node(dnod);
}
#endif

static void smith_put_files_struct(struct files_struct *files)
{
    struct delayed_put_node *dnod;

    /* just loop until we get a new recrod */
    do {
        dnod = smith_alloc_delayed_put_node();
    } while (!dnod);

    dnod->type = 1;
    dnod->files = files;

    /* attach dnod to deayed_put_queue */
    smith_insert_delayed_put_node(dnod);
}

/*
 * task_lock() is required to avoid races with process termination
 */
static struct files_struct *smith_get_files_struct(struct task_struct *task)
{
    struct files_struct *files;

    task_lock(task);
    files = task->files;
    if (files)
        atomic_inc(&files->count);
    task_unlock(task);

    return files;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 11, 0)
#define smith_lookup_fd          files_lookup_fd_raw
#else
#define smith_lookup_fd          fcheck_files
#endif

static struct file *smith_fget_raw(unsigned int fd)
{
	struct file *file;
	struct files_struct *files;

	files = smith_get_files_struct(current);
	if (!files)
        return NULL;

	rcu_read_lock();
	file = smith_lookup_fd(files, fd);
	if (file) {
		/* File object ref couldn't be taken */
		if (!atomic_long_inc_not_zero(&file->f_count))
			file = NULL;
	}
	rcu_read_unlock();

	smith_put_files_struct(files);
	return file;
}

static char *(*smith_d_absolute_path)(const struct path *path,
	       char *buf, int buflen);
static __always_inline char *smith_d_path(const struct path *path, char *buf, int buflen)
{
    char *name = DEFAULT_RET_STR;
    if (buf) {
        name = smith_d_absolute_path(path, buf, buflen);
        if (PTR_ERR(name) == -EINVAL && d_path != smith_d_absolute_path)
            name = d_path(path, buf, buflen);
        if (IS_ERR(name))
            name = NAME_TOO_LONG;
    }
    return name;
}

/*
 * dentry_path_raw implementation for kernels < 2.6.38
 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 38)
static int prepend(char **buffer, int *buflen, const char *str, int namelen)
{
    *buflen -= namelen;
    if (*buflen < 0)
        return -ENAMETOOLONG;
    *buffer -= namelen;
    memcpy(*buffer, str, namelen);
    return 0;
}

static int prepend_name(char **buffer, int *buflen, struct qstr *name)
{
    return prepend(buffer, buflen, name->name, name->len);
}

//get file path from dentry struct
static char *__dentry_path(struct dentry *dentry, char *buf, int buflen)
{
    char *end = buf + buflen;
    char *retval;

    prepend(&end, &buflen, "\0", 1);
    if (buflen < 1)
        goto Elong;
    retval = end - 1;
    *retval = '/';

    while (!IS_ROOT(dentry)) {
        struct dentry *parent = dentry->d_parent;
        int error;

        prefetch(parent);
        spin_lock(&dentry->d_lock);
        error = prepend_name(&end, &buflen, &dentry->d_name);
        spin_unlock(&dentry->d_lock);
        if (error != 0 || prepend(&end, &buflen, "/", 1) != 0)
            goto Elong;

        retval = end;
        dentry = parent;
    }
    return retval;
Elong:
    return ERR_PTR(-ENAMETOOLONG);
}
#endif /* < 2.6.38 */

/*
 * query task's executable image file, with mmap lock avoided, just because
 * mmput() could lead resched() (since it's calling might_sleep() interally)
 *
 * there could be races on mm->exe_file, but we could assure we can always
 * get a valid filp or NULL
 */
static inline struct file *smith_get_task_exe_file(struct task_struct *task)
{
    struct file *exe = NULL;

    /*
     * get_task_mm/mmput must be avoided here
     *
     * mmput would put current task to sleep, which violates kprobe. or
     * use mmput_async instead, but it's only available for after 4.7.0
     * (and CONFIG_MMU is enabled)
     */
    task_lock(task);
    if (task->mm && task->mm->exe_file) {
        exe = task->mm->exe_file;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 1, 0)
        if (!get_file_rcu(exe))
            exe = NULL;
#else
        /* only inc f_count when it's not 0 to avoid races upon exe_file */
        if (!atomic_long_inc_not_zero(&exe->f_count))
            exe = NULL;
#endif
    }
    task_unlock(task);

    return exe;
}

// get full path of current task's executable image
static __always_inline char *smith_get_exe_file(char *buffer, int size)
{
    char *exe_file_str = DEFAULT_RET_STR;
    struct file *exe;

    if (!buffer || !current->mm)
        return exe_file_str;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 1, 0) && LINUX_VERSION_CODE < KERNEL_VERSION(5, 15, 0)
    /*
     * 1) performance improvement for kernels >=4.1: use get_mm_exe_file instead
     *    get_mm_exe_file internally uses rcu lock (with semaphore locks killed)
     * 2) it's safe to directly access current->mm under current's own context
     * 3) get_mm_exe_file() is no longer exported after kernel 5.15
     */
    exe = get_mm_exe_file(current->mm);
#else
    exe = smith_get_task_exe_file(current);
#endif
    if (exe) {
        exe_file_str = smith_d_path(&exe->f_path, buffer, size);
        smith_fput(exe);
    }

    return exe_file_str;
}

static char *smith_get_pwd_path(char *buffer, int size)
{
    if (!current->fs)
        return buffer;

    return smith_d_path(&current->fs->pwd, buffer, size);
}

static char *smith_get_file_path(int fd, char *buffer, int size)
{
    struct file *filp = smith_fget_raw(fd);
    char *path;

    if (!filp)
        return buffer;

    path = smith_d_path(&filp->f_path, buffer, size);
    smith_fput(filp);

    return path;
}

/* cache of executable images, managed by rbtree and lru list */
#define SI_IMG_LENGTH  (384)
#define SI_IMG_BUFLEN  (SI_IMG_LENGTH - offsetof(struct smith_img, si_buf))

struct smith_img {
    struct tt_node      si_node;    /* rbtree of cached img */
    struct list_head    si_link;    /* lru list for reaper */
    struct file        *si_exe;     /* executable image */
    void               *si_sb;      /* superblock pointer of target volume */
    uint64_t            si_size;    /* file size */
    ino_t               si_ino;     /* inode number of the executable image */
    uint32_t            si_age;     /* time stamp in seconds */
    uint16_t            si_max;
    uint16_t            si_len;
    uint64_t            si_murmur64;/* murmur64 of si_path */
    struct image_hash   si_md5;
    char               *si_path;

    union {
        char           *si_alloc;
        char            si_buf[0];
    };
};

static struct smith_img *smith_find_task_img(struct task_struct *task);
static struct smith_img *smith_find_file_img(struct file *filp);
static void smith_put_img(struct smith_img *img);

/*
 * wrapper for trusted exe checking
 */
static inline int smith_is_exe_trusted(struct smith_img *img)
{
    return g_flt_ops.exe_check(img->si_path, img->si_len,
                               img->si_murmur64);
}

/*
 * wrapper for ktime_get_real_seconds
 */

uint64_t (*smith_ktime_get_real_ns)(void);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 11, 0)
#define smith_get_seconds ktime_get_real_seconds
#else /* < 5.11.0 */
static uint64_t (*smith_ktime_get_real_seconds)(void);
static uint64_t smith_get_seconds(void)
{
    return smith_ktime_get_real_seconds();
}
static uint64_t smith_get_seconds_ext(void)
{
    return (uint64_t)get_seconds();
}
static void smith_init_get_seconds(void)
{
    if (!smith_ktime_get_real_seconds)
        smith_ktime_get_real_seconds = smith_get_seconds_ext;
}
#endif /* >= 5.11.0 */

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 39)
void (*__smith_put_task_struct)(struct task_struct *tsk);
#endif

static const struct cred *(*get_task_cred_sym) (struct task_struct *);

#if !defined(SMITH_HAVE_NO_MNTNS_OPS) && !defined(SMITH_HAVE_MNTNS_PROCFS)
/* proc_ns.h introduced from v3.10, originated from proc_fs.h */
#include <linux/proc_ns.h> /* proc_ns_operations */
#endif
#include <linux/mount.h>

struct proc_ns_operations *smith_mntns_ops;
static uint64_t smith_query_mntns_id(struct task_struct *task)
{
    struct super_block *sb = NULL;
    struct path pwd;
    uint64_t mntns;
    uint32_t inum = 0xF0000001; /* default mntns inum for kernels < 3.8 */

#ifndef SMITH_HAVE_NO_MNTNS_OPS
    void *ns;

    /* mntns_operations was introduced from v3.8 */
    if (!smith_mntns_ops || !smith_mntns_ops->get || !smith_mntns_ops->put)
        goto errorout;

#ifdef SMITH_HAVE_MNTNS_OPS_INUM
    if (!smith_mntns_ops->inum)
        goto errorout;
    ns = smith_mntns_ops->get(task);
    if (ns) {
        inum = smith_mntns_ops->inum(ns);
        smith_mntns_ops->put(ns);
    }
#else
    /* ops->inum callback was removed from v3.19 */
    ns = smith_mntns_ops->get(task);
    if (ns) {
        struct ns_common *nc = ns;
        inum = nc->inum;
        smith_mntns_ops->put(nc);
    }
#endif /* SMITH_HAVE_MNTNS_OPS_INUM */

errorout:
#endif /* !SMITH_HAVE_NO_MNTNS_OPS */

    task_lock(task);
    pwd = task->fs->pwd;
    task_unlock(task);

    /* get superblock of root fs, using as mnt namespace id */
    sb = pwd.mnt ? pwd.mnt->mnt_sb : NULL;
    if (sb && sb->s_fs_info)
        mntns = (unsigned long)sb->s_fs_info;
    else if (sb)
        mntns = (unsigned long)sb;
    else
        mntns = -1;
    mntns = (~mntns) << 28; /* canonical address */
    mntns = (mntns & 0xFFFFFFFF00000000ULL) | inum;

    return mntns;
}

static int __init kernel_symbols_init(void)
{
    void *ptr = (void *)smith_kallsyms_lookup_name("put_files_struct");
    if (!ptr)
        return -ENODEV;
    put_files_struct_sym = ptr;

    ptr = (void *)smith_kallsyms_lookup_name("get_task_cred");
    if (!ptr)
        return -ENODEV;
    get_task_cred_sym = ptr;

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 39)
    ptr = (void *)smith_kallsyms_lookup_name("__put_task_struct");
    if (!ptr)
        return -ENODEV;
    __smith_put_task_struct = ptr;
#endif

    ptr = (void *)smith_kallsyms_lookup_name("ktime_get_real");
    if (!ptr)
        return -ENODEV;
    smith_ktime_get_real_ns = ptr;

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 11, 0)
    ptr = (void *)smith_kallsyms_lookup_name("ktime_get_real_seconds");
    if (ptr)
        smith_ktime_get_real_seconds = ptr;
    smith_init_get_seconds();
#endif

/*
 * prepend_path will throw a WARN for d_absolute_path if root
 * dentry is not properly named:
 *
 *			if (IS_ROOT(dentry) &&
 *			   (dentry->d_name.len != 1 ||
 *			    dentry->d_name.name[0] != '/')) {
 *				WARN(1, "Root dentry has weird name <%.*s>\n",
 *				     (int) dentry->d_name.len,
 *				     dentry->d_name.name);
 *			}
 * The above check was removed from 4.1.2. But anyway we won't
 * try d_absolute_path for these kerenls, d_path should be fine.
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 2, 0)
    ptr = (void *)smith_kallsyms_lookup_name("d_absolute_path");
    if (ptr)
        smith_d_absolute_path = ptr;
    else
        smith_d_absolute_path = (void *)d_path;
#else
    smith_d_absolute_path = (void *)d_path;
#endif

    ptr = (void *)smith_kallsyms_lookup_name("mntns_operations");
    if (ptr)
        smith_mntns_ops = ptr;

    return 0;
}

static void to_print_privilege_escalation(const struct cred *current_cred, unsigned int p_cred_info[], char * pid_tree, int p_pid)
{
    char *exe_path = DEFAULT_RET_STR;
    struct smith_tid *tid = NULL;

    char p_cred[128];
    char c_cred[128];

    tid = smith_lookup_tid(current);
    if (tid)
        exe_path = tid->st_img->si_path;

    snprintf(p_cred, sizeof(p_cred), "%u|%u|%u|%u|%u|%u|%u|%u", p_cred_info[0], p_cred_info[1], p_cred_info[2], p_cred_info[3],
             p_cred_info[4], p_cred_info[5], p_cred_info[6], p_cred_info[7]);

    snprintf(c_cred, sizeof(c_cred), "%u|%u|%u|%u|%u|%u|%u|%u",
            _XID_VALUE(current_cred->uid), _XID_VALUE(current_cred->euid), _XID_VALUE(current_cred->suid),
            _XID_VALUE(current_cred->fsuid), _XID_VALUE(current_cred->gid), _XID_VALUE(current_cred->egid),
            _XID_VALUE(current_cred->sgid), _XID_VALUE(current_cred->fsgid));

    privilege_escalation_print(exe_path, p_pid, pid_tree, p_cred, c_cred);

    if (tid)
        smith_put_tid(tid);
}

static int smith_check_privilege_escalation(int limit, char *pid_tree)
{
    int limit_index = 0;
    int cred_detected_task_pid = 0;
    int cred_check_res = 0;
    unsigned int p_cred_info[8];

    struct task_struct *task;
    struct task_struct *old_task;
    const struct cred *current_cred = NULL;
    const struct cred *parent_cred = NULL;

    task = current;
    get_task_struct(task);
    current_cred = get_task_cred_sym(current);

    //cred privilege_escalation check only check twice
    while (++limit_index <= 2) {
        if (limit_index >= limit)
            break;

        old_task = task;
        rcu_read_lock();
        task = smith_get_task_struct(rcu_dereference(task->real_parent));
        rcu_read_unlock();
        smith_put_task_struct(old_task);
        if (!task || task->pid == 0)
            break;

        if (!cred_check_res) {
            cred_detected_task_pid = task->tgid;
            parent_cred = get_task_cred_sym(task);
            cred_check_res = check_cred(current_cred, parent_cred);
            save_cred_info(p_cred_info, parent_cred);
            put_cred(parent_cred);
        }
    }

    if (task)
        smith_put_task_struct(task);

    if (cred_check_res)
        to_print_privilege_escalation(current_cred, p_cred_info, pid_tree, cred_detected_task_pid);

    put_cred(current_cred);
    return cred_check_res;
}

/*
 * Our own implementation of kernel_getsockname and kernel_getpeername,
 * resuing codes logic of kernel inet_getname and inet6_getname.
 *
 * From 5.15.3 inet_getname and inet6_getname will call lock_sock for
 * lock acquisition, and then lock_sock would lead possible reschedule,
 * which violates the requirement of atomic context for kprobe/ketprobe.
 *
 * Interfaces of kernel_getsockname and kernel_getpeername are changed
 * after 4.17.0, then we'll use our own routines to keep things simple.
 */

#define SMITH_DECLARE_SOCKADDR(type, dst, src)	\
	type dst = (type)(src)

static int smith_get_sock_v4(struct socket *sock, struct sockaddr *sa)
{
    struct sock *sk	= sock->sk;
    struct inet_sock *inet = inet_sk(sk);
    SMITH_DECLARE_SOCKADDR(struct sockaddr_in *, sin, sa);

    sin->sin_family = AF_INET;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 33)
    sin->sin_port = inet->inet_sport;
    if (inet->inet_rcv_saddr)
        sin->sin_addr.s_addr = inet->inet_rcv_saddr;
    else
        sin->sin_addr.s_addr = inet->inet_saddr;
#else
    sin->sin_port = inet->sport;
    sin->sin_addr.s_addr = inet->saddr;
#endif

    return sizeof(*sin);
}

static int smith_get_peer_v4(struct socket *sock, struct sockaddr *sa)
{
    struct sock *sk	= sock->sk;
    struct inet_sock *inet = inet_sk(sk);
    SMITH_DECLARE_SOCKADDR(struct sockaddr_in *, sin, sa);

    sin->sin_family = AF_INET;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 33)
    sin->sin_port = inet->inet_dport;
    sin->sin_addr.s_addr = inet->inet_daddr;
#else
    sin->sin_port = inet->dport;
    sin->sin_addr.s_addr = inet->daddr;
#endif
    return sizeof(*sin);
}

#if IS_ENABLED(CONFIG_IPV6)
static int smith_get_sock_v6(struct socket *sock, struct sockaddr *sa)
{
    struct sockaddr_in6 *sin = (struct sockaddr_in6 *)sa;
    struct sock *sk = sock->sk;
    struct inet_sock *inet = inet_sk(sk);
    struct ipv6_pinfo *np = inet6_sk(sk);
    const struct in6_addr *in6;

    in6 = inet6_rcv_saddr(sk);
    if (in6 && !ipv6_addr_any(in6))
        memcpy(&sin->sin6_addr, in6, sizeof(sin->sin6_addr));
    else if (np)
        memcpy(&sin->sin6_addr, &np->saddr, sizeof(sin->sin6_addr));
    else
        memset(&sin->sin6_addr, 0, sizeof(sin->sin6_addr));

    sin->sin6_family = AF_INET6;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 33)
    sin->sin6_port = inet->inet_sport;
#else
    sin->sin6_port = inet->sport;
#endif

    return sizeof(*sin);
}

static int smith_get_peer_v6(struct socket *sock, struct sockaddr *sa)
{
    struct sockaddr_in6 *sin = (struct sockaddr_in6 *)sa;
    struct sock *sk = sock->sk;
    struct inet_sock *inet = inet_sk(sk);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 13, 0) || defined(IPV6_SUPPORT)
    memcpy(&sin->sin6_addr, &sk->sk_v6_daddr, sizeof(sin->sin6_addr));
#else
    struct ipv6_pinfo *np = inet6_sk(sk);
    if (np)
        memcpy(&sin->sin6_addr, &np->daddr, sizeof(sin->sin6_addr));
    else
        memset(&sin->sin6_addr, 0, sizeof(sin->sin6_addr));
#endif

    sin->sin6_family = AF_INET6;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 33)
    sin->sin6_port = inet->inet_dport;
#else
    sin->sin6_port = inet->dport;
#endif
    return sizeof(*sin);
}
#endif

//get task tree first AF_INET/AF_INET6 socket info
void get_process_socket(__be32 *sip4, struct in6_addr *sip6, int *sport,
                        __be32 *dip4, struct in6_addr *dip6, int *dport,
                        pid_t *socket_pid, int *sa_family)
{
    struct task_struct *task = current;
    int it = 0, socket_check = 0;

    get_task_struct(task);

    while (task && task->pid != 1 && it++ < EXECVE_GET_SOCK_PID_LIMIT) {
        struct task_struct *old_task;
        struct files_struct *files;
        unsigned int i;

        files = smith_get_files_struct(task);
        if (!files)
            goto next_task;

        for (i = 0; i < EXECVE_GET_SOCK_FD_LIMIT; i++) {
            struct socket *socket;
            int err = 0;

            rcu_read_lock();
            /* move to next if exceeding current task's max_fds,
               max_fds access should be protected by rcu lock */
            if (i >= files_fdtable(files)->max_fds) {
                rcu_read_unlock();
                break;
            }
            socket = sockfd_lookup(i, &err);
            rcu_read_unlock();

            if (!IS_ERR_OR_NULL(socket)) {
                struct sock *sk = socket->sk;

                /* only process known states: SS_CONNECTING/SS_CONNECTED/SS_DISCONNECTING,
                   SS_FREE/SS_UNCONNECTED or any possible new states are to be skipped */
                if ((socket->state == SS_CONNECTING ||
                     socket->state == SS_CONNECTED ||
                     socket->state == SS_DISCONNECTING) && sk) {

                    union {
                        struct sockaddr    sa;
                        struct sockaddr_in si4;
                        struct sockaddr_in6 si6;
                        /* to avoid overflow access of kernel_getsockname */
                        struct __kernel_sockaddr_storage kss;
                    } sa;

                    if (AF_INET == sk->sk_family) {
                        if (smith_get_sock_v4(socket, &sa.sa) < 0)
                            goto next_socket;
                        *sip4 = sa.si4.sin_addr.s_addr;
                        *sport = ntohs(sa.si4.sin_port);
                        if (smith_get_peer_v4(socket, &sa.sa) < 0)
                            goto next_socket;
                        *dip4 = sa.si4.sin_addr.s_addr;
                        *dport = ntohs(sa.si4.sin_port);
#if IS_ENABLED(CONFIG_IPV6)
                    } else if (AF_INET6 == sk->sk_family) {
                        if (smith_get_sock_v6(socket, &sa.sa) < 0)
                            goto next_socket;
                        *sport = ntohs(sa.si6.sin6_port);
                        memcpy(sip6, &sa.si6.sin6_addr, sizeof(struct in6_addr));
                        if (smith_get_peer_v6(socket, &sa.sa) < 0)
                            goto next_socket;
                        *dport = ntohs(sa.si6.sin6_port);
                        memcpy(dip6, &sa.si6.sin6_addr, sizeof(struct in6_addr));
#endif
                    }

                    socket_check = 1;
                    *sa_family = sk->sk_family;
                }
next_socket:
                sockfd_put(socket);
            }
        }
        smith_put_files_struct(files);

        if (socket_check) {
            *socket_pid = task->tgid;
            smith_put_task_struct(task);
            return;
        }

next_task:
        old_task = task;
        rcu_read_lock();
        task = smith_get_task_struct(rcu_dereference(task->real_parent));
        rcu_read_unlock();
        smith_put_task_struct(old_task);
    }

    if (task)
        smith_put_task_struct(task);

    return;
}

static void smith_trace_sysret_bind(long sockfd, long ret)
{
    struct socket *sock = NULL;
    union {
        struct sockaddr    sa;
        struct sockaddr_in si4;
        struct sockaddr_in6 si6;
        /* to avoid overflow access of kernel_getsockname */
        struct __kernel_sockaddr_storage kss;
    } sa;
    int sport = 0, err = 0;

    char *exe_path = DEFAULT_RET_STR;
    char *pid_tree = NULL;
    struct smith_tid *tid = NULL;

    /* ignore failed bind calls */
    if (ret != 0)
        goto out;

    sock = sockfd_lookup(sockfd, &err);
    if (IS_ERR_OR_NULL(sock))
        goto out;

    tid = smith_lookup_tid(current);
    if (tid) {
        exe_path = tid->st_img->si_path;
        // exe filter check
        if (smith_is_exe_trusted(tid->st_img))
            goto out;
        pid_tree = tid->st_pid_tree;
    }

    if (AF_INET == sock->sk->sk_family) {
        struct in_addr *sip4;
        if (smith_get_sock_v4(sock, &sa.sa) < 0)
            goto out;
        sip4 = &sa.si4.sin_addr;
        sport = ntohs(sa.si4.sin_port);
        bind_print(exe_path, sip4, sport, sockfd, pid_tree);
#if IS_ENABLED(CONFIG_IPV6)
    } else if (AF_INET6 == sock->sk->sk_family) {
        struct in6_addr *sip6;

        if (smith_get_sock_v6(sock, &sa.sa) < 0)
            goto out;
        sip6 = &sa.si6.sin6_addr;
        sport = ntohs(sa.si6.sin6_port);
        bind6_print(exe_path, sip6, sport, sockfd, pid_tree);
#endif
    }

out:
    if (!IS_ERR_OR_NULL(sock))
        sockfd_put(sock);
    if (tid)
        smith_put_tid(tid);
}

static void smith_trace_sysret_connect(long sockfd, long saddr, int len, int retval)
{
    struct socket *sock = NULL;

    char *exe_path = DEFAULT_RET_STR;
    char *pid_tree = NULL;
    struct smith_tid *tid = NULL;
    sa_family_t family = AF_UNSPEC;

    union {
        struct sockaddr    sa;
        struct sockaddr_in si4;
        struct sockaddr_in6 si6;
        /* to avoid overflow access of kernel_getsockname */
        struct __kernel_sockaddr_storage kss;
    } sa;
    int err, dport, sport;

    sock = sockfd_lookup(sockfd, &err);
    if (IS_ERR_OR_NULL(sock))
        goto out;

    tid = smith_lookup_tid(current);
    if (tid) {
        exe_path = tid->st_img->si_path;
        // exe filter check
        if (smith_is_exe_trusted(tid->st_img))
            goto out;
        pid_tree = tid->st_pid_tree;
    }

    /* prefer the family type specified by user */
    family = sock->sk->sk_family;
    if (family == AF_INET) {
        __be32 dip4, sip4;

        if (smith_get_sock_v4(sock, &sa.sa) < 0)
            goto out;
        sip4 = sa.si4.sin_addr.s_addr;
        sport = ntohs(sa.si4.sin_port);

        if (smith_get_peer_v4(sock, &sa.sa) < 0) {
            if (!saddr)
                goto out;
            if (len > sizeof(sa))
                len = sizeof(sa);
            if (len < 16)
                len = 16;
            if (smith_copy_from_user(&sa, (void *)saddr, len))
                goto out;
            dip4 = sa.si4.sin_addr.s_addr;
            dport = ntohs(sa.si4.sin_port);
        } else {
            dip4 = sa.si4.sin_addr.s_addr;
            dport = ntohs(sa.si4.sin_port);
        }
        connect4_print(dport, dip4, exe_path, sip4, sport, retval, pid_tree);

#if IS_ENABLED(CONFIG_IPV6)
    } else if (family == AF_INET6) {
        struct in6_addr sip6, dip6;

        if (smith_get_sock_v6(sock, &sa.sa) < 0)
            goto out;
        sport = ntohs(sa.si6.sin6_port);
        sip6 = sa.si6.sin6_addr;

        if (smith_get_peer_v6(sock, &sa.sa) < 0) {
            if (!saddr)
                goto out;
            if (len > sizeof(sa))
                len = sizeof(sa);
            if (len < 16)
                len = 16;
            if (smith_copy_from_user(&sa, (void *)saddr, len))
                goto out;
            dport = ntohs(sa.si6.sin6_port);
            dip6 = sa.si6.sin6_addr;
        } else {
            dport = ntohs(sa.si6.sin6_port);
            dip6 = sa.si6.sin6_addr;
        }
        connect6_print(dport, &dip6, exe_path, &sip6, sport, retval, pid_tree);
#endif
    }

out:
    if (!IS_ERR_OR_NULL(sock))
        sockfd_put(sock);
    if (tid)
        smith_put_tid(tid);

    return;
}

static void smith_trace_sysret_accept(long sockfd)
{
    struct socket *sock = NULL;

    union {
        struct sockaddr    sa;
        struct sockaddr_in si4;
        struct sockaddr_in6 si6;
        /* to avoid overflow access of kernel_getsockname */
        struct __kernel_sockaddr_storage kss;
    } sa;
    int sport = 0, dport = 0, err = 0;

    char *exe_path = DEFAULT_RET_STR;
    struct smith_tid *tid = NULL;

    sock = sockfd_lookup(sockfd, &err);
    if (IS_ERR_OR_NULL(sock))
        goto out;

    tid = smith_lookup_tid(current);
    if (tid) {
        exe_path = tid->st_img->si_path;
        // exe filter check
        if (smith_is_exe_trusted(tid->st_img))
            goto out;
    }

    //only get AF_INET/AF_INET6 accept info
    if (AF_INET == sock->sk->sk_family) {
        __be32 sip4, dip4;

        if (smith_get_sock_v4(sock, &sa.sa) < 0)
            goto out;
        dip4 = sa.si4.sin_addr.s_addr;
        dport = ntohs(sa.si4.sin_port);

        if (smith_get_peer_v4(sock, &sa.sa) < 0)
            goto out;
        sip4 = sa.si4.sin_addr.s_addr;
        sport = ntohs(sa.si4.sin_port);
        accept_print(dport, dip4, exe_path, sip4, sport, sockfd);
        // printk("accept4_handler: %d.%d.%d.%d/%d -> %d.%d.%d.%d/%d rc=%d\n",
        //         NIPQUAD(sip4), sport, NIPQUAD(dip4), dport, sockfd);
#if IS_ENABLED(CONFIG_IPV6)
    } else if (AF_INET6 == sock->sk->sk_family) {
        struct in6_addr *sip6, dip6;

        if (smith_get_sock_v6(sock, &sa.sa) < 0)
            goto out;
        dip6 = sa.si6.sin6_addr;
        dport = ntohs(sa.si6.sin6_port);

        if (smith_get_peer_v6(sock, &sa.sa) < 0)
            goto out;
        sport = ntohs(sa.si6.sin6_port);
        sip6 = &(sa.si6.sin6_addr);
        accept6_print(dport, &dip6, exe_path, sip6, sport, sockfd);
        // printk("accept6_handler: %04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x/%d"
        //        " -> %04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x/%d rc=%d\n",
        //         NIP6(*sip6), sport, NIP6(dip6), dport, sockfd);
#endif
    }

out:
    if (!IS_ERR_OR_NULL(sock))
        sockfd_put(sock);
    if (tid)
        smith_put_tid(tid);
}

/*
 * support routines for execve/execveat tracepoints
 */

struct execve_data {
    char *argv;
    char *env;
    char *ssh_connection;
    char *ld_preload;
    char *ld_library_path;
    int  len_argv;
};

static int smith_trace_process_exec(struct execve_data *data, int rc)
{
    int sa_family = -1, dport = 0, sport = 0, i;
    __be32 dip4, sip4;
    pid_t socket_pid = -1;
    char md5s[36] = "-1";
    uint64_t size = 0;

    char *pname = DEFAULT_RET_STR;
    char *tmp_stdin = DEFAULT_RET_STR;
    char *tmp_stdout = DEFAULT_RET_STR;
    char *pname_buf = NULL;
    char *pid_tree = NULL;
    char *tty_name = NULL;
    char *exe_path = DEFAULT_RET_STR;
    struct smith_tid *tid = NULL;
    struct smith_img *img = NULL;
    char *stdin_buf = NULL;
    char *stdout_buf = NULL;

    struct in6_addr dip6;
    struct in6_addr sip6;
    struct file *file;
    struct tty_struct *tty = NULL;

    // argv filter check
    if (g_flt_ops.argv_check(data->argv, data->len_argv))
        goto out;

    tty = get_current_tty();
    if (tty && strlen(tty->name) > 0)
        tty_name = tty->name;;

    tid = smith_lookup_tid(current);
    if (tid) {
        // exe filter check
        if (smith_is_exe_trusted(tid->st_img))
            goto out;

        exe_path = tid->st_img->si_path;
        pid_tree = tid->st_pid_tree;

         /* decode md5 hash to string */
        for (i = 0; i < 16; i++)
            sprintf(&md5s[i * 2], "%2.2x", tid->st_img->si_md5.hash.v8[i]);
        size = tid->st_img->si_md5.size;
    } else {
        img = smith_find_task_img(current);
        if (img) {
            // exe filter check
            if (smith_is_exe_trusted(img))
                goto out;
            exe_path = img->si_path;
        }
    }

    get_process_socket(&sip4, &sip6, &sport, &dip4, &dip6, &dport,
                       &socket_pid, &sa_family);

    // if socket exist,get pid tree
    if (sa_family == AF_INET6 || sa_family == AF_INET)
        smith_check_privilege_escalation(PID_TREE_LIMIT, pid_tree);
    else
        smith_check_privilege_escalation(PID_TREE_LIMIT_LOW, pid_tree);

    // get stdin
    file = smith_fget_raw(0);
    if (file) {
        stdin_buf = smith_kzalloc(256, GFP_ATOMIC);
        tmp_stdin = smith_d_path(&(file->f_path), stdin_buf, 256);
        smith_fput(file);
    }

    // get stdout
    file = smith_fget_raw(1);
    if (file) {
        stdout_buf = smith_kzalloc(256, GFP_ATOMIC);
        tmp_stdout = smith_d_path(&(file->f_path), stdout_buf, 256);
        smith_fput(file);
    }

    pname_buf = smith_kzalloc(PATH_MAX, GFP_ATOMIC);
    pname = smith_d_path(&current->fs->pwd, pname_buf, PATH_MAX);

    if (sa_family == AF_INET) {
        execve_print(pname,
                     exe_path, data->argv,
                     tmp_stdin, tmp_stdout,
                     dip4, dport, sip4, sport,
                     pid_tree, tty_name, socket_pid,
                     data->ssh_connection,
                     data->ld_preload,
                     data->ld_library_path,
                     rc, size, md5s);
#if IS_ENABLED(CONFIG_IPV6)
    } else if (sa_family == AF_INET6) {
        execve6_print(pname,
                      exe_path, data->argv,
                      tmp_stdin, tmp_stdout,
                      &dip6, dport, &sip6, sport,
                      pid_tree, tty_name, socket_pid,
                      data->ssh_connection,
                      data->ld_preload,
                      data->ld_library_path,
                      rc, size, md5s);
#endif
    } else {
        execve_nosocket_print(pname,
                              exe_path, data->argv,
                              tmp_stdin, tmp_stdout,
                              pid_tree, tty_name,
                              data->ssh_connection,
                              data->ld_preload,
                              data->ld_library_path,
                              rc, size, md5s);
    }

out:
    if (pname_buf)
        smith_kfree(pname_buf);
    if (stdin_buf)
        smith_kfree(stdin_buf);
    if (stdout_buf)
        smith_kfree(stdout_buf);
    if (tty)
        tty_kref_put(tty);
    if (img)
        smith_put_img(img);
    if (tid)
        smith_put_tid(tid);

    if (data->argv)
        smith_kfree(data->argv);
    if (data->env)
        smith_kfree(data->env);

    return 0;
}

//get execve syscall argv/LD_PRELOAD && SSH_CONNECTION && LD_LIB_PATH env info
static void smith_trace_prepare_exec(struct execve_data *data)
{
    struct task_struct *task = current;
    unsigned long args, envs, larg, lenv, i;
    char *parg, *penv;

    /* query arg and env mmap sections */
    if (!task->mm)
        return;
    task_lock(task);
    args = task->mm->arg_start;
    if (task->mm->arg_end > args)
        larg = task->mm->arg_end - args;
    else
        larg = 0;
    envs = task->mm->env_start;
    if (task->mm->env_end > envs)
        lenv = task->mm->env_end - envs;
    else
        lenv = 0;
    task_unlock(task);

    /* query argv of current task */
    if (larg > SMITH_MAX_CMDLINE)
        larg = SMITH_MAX_CMDLINE;
    if (!larg || !args)
        goto proc_env;
    parg = smith_kzalloc(larg < 16 ? 16 : larg, GFP_ATOMIC);
    if (!parg)
        goto proc_env;
    i = larg - 1 - smith_copy_from_user(parg, (void *)args, larg - 1);
    if (i == 0 || i >= larg) {
        smith_kfree(parg);
    } else {
        unsigned long j = 0;
        while(j < i) {
            if (!parg[j])
                parg[j] = ' ';
            j++;
        }
        parg[i] = 0;
        data->argv= smith_strim(parg, i);
        data->len_argv = strlen(data->argv);
    }

proc_env:

    /* query envion of current task, maxlen of env could be ARG_MAX or 32 pages */
    if (lenv > PAGE_SIZE * 4)
        lenv = PAGE_SIZE * 4;
    if (lenv < 16 || !envs)
        goto errorout;
    penv = smith_kzalloc(lenv, GFP_ATOMIC);
    if (!penv)
        goto errorout;
    data->env = penv;
    if (smith_copy_from_user(penv, (void *)envs, lenv - 1)) {
        if (!strlen(penv))
            goto errorout;
    }

    data->ssh_connection = strnstr(penv, "SSH_CONNECTION=", lenv);
    if (data->ssh_connection)
        data->ssh_connection += 15;
    data->ld_preload = strnstr(penv, "LD_PRELOAD=", lenv);
    if (data->ld_preload)
        data->ld_preload += 11;
    data->ld_library_path = strnstr(penv, "LD_LIBRARY_PATH=", lenv);
    if (data->ld_library_path)
        data->ld_library_path += 16;

errorout:

    return;
}

static void smith_trace_sysret_exec(int rc)
{
    struct execve_data data = {0};

    /* ignore the failures that target doesn't exist */
    if (rc == -ENOENT)
        return;

    /* prepare data: args & environment elements */
    smith_trace_prepare_exec(&data);

    /* process execve and generate tracelog */
    smith_trace_process_exec(&data, rc);
}

//get create file info
int security_inode_create_pre_handler(struct kprobe *p, struct pt_regs *regs)
{
    char *pname_buf = NULL;
    struct smith_tid *tid = NULL;
    char *pathstr = DEFAULT_RET_STR;
    char *exe_path = DEFAULT_RET_STR;
    char *pid_tree = NULL;
    char *s_id = NULL;

    struct dentry *de = NULL;
    struct in6_addr dip6;
    struct in6_addr sip6;

    int sa_family = -1;
    int dport = 0, sport = 0;

    __be32 dip4;
    __be32 sip4;
    pid_t socket_pid = -1;
    umode_t mode;

    mode = (umode_t)p_regs_get_arg3(regs);

    tid = smith_lookup_tid(current);
    if (tid) {
        exe_path = tid->st_img->si_path;
        // exe filter check
        if (smith_is_exe_trusted(tid->st_img))
            goto out;
        pid_tree = tid->st_pid_tree;
    }

    pname_buf = smith_kzalloc(PATH_MAX, GFP_ATOMIC);
    if (pname_buf) {
        de = (struct dentry *)p_regs_get_arg2(regs);
        if (IS_ERR_OR_NULL(de))
            goto out;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 38)
        pathstr = dentry_path_raw(de, pname_buf, PATH_MAX);
#else
        pathstr = __dentry_path(de, pname_buf, PATH_MAX);
#endif

        if(!IS_ERR_OR_NULL(de->d_sb))
            s_id = de->d_sb->s_id;

        if(IS_ERR(pathstr)) {
            pathstr = NAME_TOO_LONG;
        } else if (S_ISREG(mode)) {
            /* don't report files in /systemd/ */
            if (!memcmp(pathstr, "/systemd/", 9))
                goto out;
            smith_insert_ent(pathstr);
        }
    }

    get_process_socket(&sip4, &sip6, &sport, &dip4, &dip6, &dport,
                       &socket_pid, &sa_family);

    if (sa_family == AF_INET) {
        security_inode4_create_print(exe_path, pathstr,
                                    dip4, dport, sip4, sport,
                                    socket_pid, s_id, pid_tree);
    }
#if IS_ENABLED(CONFIG_IPV6)
    else if (sa_family == AF_INET6) {
		security_inode6_create_print(exe_path, pathstr, &dip6,
                                     dport, &sip6, sport,
			                         socket_pid, s_id, pid_tree);
	}
#endif
    else {
        security_inode_create_nosocket_print(exe_path, pathstr,
                                             s_id, pid_tree);
    }

out:
    if (pname_buf)
        smith_kfree(pname_buf);
    if (tid)
        smith_put_tid(tid);

    return 0;
}

static void smith_trace_sysret_ptrace(long request, long pid, void *addr, long ret)
{
    struct smith_tid *tid = NULL;

    // only get PTRACE_POKETEXT/PTRACE_POKEDATA ptrace
    // Read a word at the address addr in the tracee's memory,
    // returning the word as the result of the ptrace() call.  Linux
    // does not have separate text and data address spaces, so these
    // two requests are currently equivalent.  (data is ignored; but
    // see NOTES.)

    if (request == PTRACE_POKETEXT || request == PTRACE_POKEDATA) {
        char *exe_path = DEFAULT_RET_STR;
        char *pid_tree = NULL;

        if (IS_ERR_OR_NULL(addr))
            return;

        tid = smith_lookup_tid(current);
        if (tid) {
            exe_path = tid->st_img->si_path;
            // exe filter check
            if (smith_is_exe_trusted(tid->st_img))
                goto out;
            pid_tree = tid->st_pid_tree;
        }

        smith_check_privilege_escalation(PID_TREE_LIMIT, pid_tree);
        ptrace_print(request, pid, addr, "-1", exe_path, pid_tree);
    }

out:
    if (tid)
        smith_put_tid(tid);
}


/*
 * DNS query hooking
 */


/* whether socket connection is udp (dgram) ? */
static int smith_socket_is_udp(struct socket *sock)
{
    return (sock && sock->sk && sock->sk->sk_protocol == IPPROTO_UDP);
}

static void dns_data_transport(char *query, __be32 dip, __be32 sip, int dport,
                               int sport, int opcode, int rcode, int type)
{
    struct smith_tid *tid = NULL;
    char *exe_path = DEFAULT_RET_STR;
    char *pid_tree = NULL;

    tid = smith_lookup_tid(current);
    if (tid) {
        exe_path = tid->st_img->si_path;
        pid_tree = tid->st_pid_tree;
    }

    dns_print(dport, dip, exe_path, sip, sport, opcode, rcode, query, type, pid_tree);

    if (tid)
        smith_put_tid(tid);
}

#if IS_ENABLED(CONFIG_IPV6)
static void dns6_data_transport(char *query, struct in6_addr *dip,
                                struct in6_addr *sip, int dport, int sport,
                                int opcode, int rcode, int type)
{
    struct smith_tid *tid = NULL;
    char *exe_path = DEFAULT_RET_STR;
    char *pid_tree = NULL;

    tid = smith_lookup_tid(current);
    if (tid) {
        exe_path = tid->st_img->si_path;
        pid_tree = tid->st_pid_tree;
    }

    dns6_print(dport, dip, exe_path, sip, sport, opcode, rcode, query, type, pid_tree);

    if (tid)
        smith_put_tid(tid);
}
#endif

struct smith_ip_addr {

    int sa_family;
    int sport;
    int dport;

    union {
        struct {
            __be32 dip4;
            __be32 sip4;
        };
        struct {
            struct in6_addr dip6;
            struct in6_addr sip6;
        };
    };
};

static void *get_dns_query(unsigned char *data, int query_len, char *res, int *type) {
    int i;
    int flag = -1;

    for (i = 0; i < query_len; i++) {
        if (flag == -1) {
            flag = (data + 12)[i];
        } else if (flag == 0) {
            flag = (data + 12)[i];
            res[i - 1] = 46;
        } else {
            if (isprint((data + 12)[i]))
                res[i - 1] = (data + 12)[i];
            else
                res[i - 1] = '#';
            flag = flag - 1;
        }
    }

    //get dns queries type: https://en.wikipedia.org/wiki/List_of_DNS_record_types
    *type = be16_to_cpu(*((uint16_t *)(data + query_len + 13)));
    return 0;
}

static int smith_process_dns(struct smith_ip_addr *addr, unsigned char *recv_data, int iov_len)
{
    // types of queries in the DNS system: https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml
    int qr, opcode = 0, rcode = 0, type = 0;
    int query_len = 0;

    char *query;

    qr = (recv_data[2] & 0x80) ? 1 : 0;
    if (qr == 1) {
        opcode = (recv_data[2] >> 3) & 0x0f;
        rcode = recv_data[3] & 0x0f;

        query_len = strnlen(recv_data + 12, iov_len - 12);
        if (query_len == 0 || query_len > 253 || query_len + 17 > iov_len) {
            return 0;
        }

        //parser DNS protocol and get DNS query info
        query = smith_kzalloc(query_len + 1, GFP_ATOMIC);
        if (!query) {
            return 0;
        }

        get_dns_query(recv_data, query_len, query, &type);
        if (addr->sa_family == AF_INET)
            dns_data_transport(query, addr->dip4,
                               addr->sip4, addr->dport,
                               addr->sport, opcode,
                               rcode, type);
#if IS_ENABLED(CONFIG_IPV6)
        else if (addr->sa_family == AF_INET6)
			dns6_data_transport(query, &addr->dip6,
					            &addr->sip6, addr->dport,
					            addr->sport, opcode,
					            rcode, type);
#endif
        smith_kfree(query);
    }

    return 0;
}

static int smith_query_ip_addr(struct socket *sock, struct smith_ip_addr *addr)
{
    union {
        struct sockaddr    sa;
        struct sockaddr_in si4;
        struct sockaddr_in6 si6;
        /* to avoid overflow access of kernel_getsockname */
        struct __kernel_sockaddr_storage kss;
    } sa;

    if (AF_INET == sock->sk->sk_family) {
        addr->sa_family = AF_INET;
        if (smith_get_sock_v4(sock, &sa.sa) >= 0) {
            addr->sport = ntohs(sa.si4.sin_port);
            addr->sip4 = sa.si4.sin_addr.s_addr;
        } else {
            addr->sport = 0;
            addr->sip4 = 0;
        }
        if (smith_get_peer_v4(sock, &sa.sa) >= 0) {
            addr->dport = ntohs(sa.si4.sin_port);
            addr->dip4 = sa.si4.sin_addr.s_addr;
        } else {
            addr->dport = 0;
            addr->dip4 = 0;
        }
#if IS_ENABLED(CONFIG_IPV6)
    } else if (AF_INET6 == sock->sk->sk_family) {
        addr->sa_family = AF_INET6;
        if (smith_get_sock_v6(sock, &sa.sa) >= 0) {
            addr->sport = ntohs(sa.si6.sin6_port);
            memcpy(&addr->sip6, &sa.si6.sin6_addr, sizeof(struct in6_addr));
        } else {
            addr->sport = 0;
            memset(&addr->sip6, 0, sizeof(struct in6_addr));
        }
        if (smith_get_peer_v6(sock, &sa.sa) >= 0) {
            addr->dport = ntohs(sa.si6.sin6_port);
            memcpy(&addr->dip6, &sa.si6.sin6_addr, sizeof(struct in6_addr));
        } else {
            addr->dport = 0;
            memset(&addr->dip6, 0, sizeof(struct in6_addr));
        }
#endif
    } else {
        addr->sa_family = 0;
    }

    return addr->sa_family;
}

/*
 * dns threshold control for high udp traffic
 */

#define SMITH_DNS_THRESHOLD    (10)     /* threshold: 2^10 = 1024 ops/s */
#define SMITH_DNS_INTERVALS    (60)     /* 60 seconds */

struct smith_dns_threshold {
    atomic_t armed ____cacheline_aligned_in_smp;  /* dns process enabled */
    atomic_t ops ____cacheline_aligned_in_smp;    /* udp traffic count */
    uint64_t start ____cacheline_aligned_in_smp;  /* start time stamp of counting */
} g_dns_threshold;

/* global settings as module parameters */
static long dns_threshold = SMITH_DNS_THRESHOLD;
static long dns_intervals = SMITH_DNS_INTERVALS;
static long dns_minwindow = 5;

module_param(dns_threshold, long, S_IRUSR|S_IRGRP|S_IROTH);
module_param(dns_intervals, long, S_IRUSR|S_IRGRP|S_IROTH);

static void smith_check_dns_params(void)
{
    if (dns_threshold < 1) /* 1 << 1 = 2 */
        dns_threshold = 1;
    else if (dns_threshold > 24) /* 16M */
        dns_threshold = 24;

    if (dns_intervals < 12) /* min: 12 seconds */
        dns_intervals = 12;
    else if (dns_intervals > 600) /* max: 10 minutes */
        dns_intervals = 600;

    if (dns_minwindow < dns_intervals / 12)
        dns_minwindow = dns_intervals / 12;
    if (dns_minwindow > 60)
        dns_minwindow = 60;
}

static int smith_is_dns_armed(struct smith_dns_threshold *sdt)
{
    uint64_t now = smith_get_seconds(), delta = now - sdt->start;

    if (delta >= dns_intervals) {

        if (!atomic_read(&sdt->armed)) {
            /* turn on dns process if udp traffic goes low */
            if (atomic_read(&sdt->ops) < (delta << dns_threshold))
                atomic_set(&sdt->armed, 1);
        }
        /* reset timestamp for a refresh counting */
        atomic_set(&sdt->ops, 0);
        WRITE_ONCE(sdt->start, smith_get_seconds());

    } else {

        /* increment traffic count */
        atomic_inc(&sdt->ops);

        /* trun off dns process if udp traffic goes high */
        if (atomic_read(&sdt->armed) && delta >= dns_minwindow) {
            if (atomic_read(&sdt->ops) > (delta << dns_threshold))
                atomic_set(&sdt->armed, 0);
        }
    }

    return atomic_read(&sdt->armed);
}

static void smith_trace_sysret_recvdat(long sockfd, unsigned long userp, long len)
{
    struct socket *sock = NULL;
    unsigned char *data = NULL;
    struct smith_ip_addr addr;
    int err;

    sock = sockfd_lookup(sockfd, &err);
    if (IS_ERR_OR_NULL(sock))
        goto out;

    /* skip tcp connections */
    if (!smith_socket_is_udp(sock))
        goto out;

    /* query ip addresses */
    if (!smith_query_ip_addr(sock, &addr))
        goto out;

    /* we only care IP v4 or v6 and port 53 or 5353 */
    if (addr.sa_family != AF_INET && addr.sa_family != AF_INET6)
        goto out;
    if (addr.sport != 53 && addr.sport != 5353 &&
        addr.dport != 53 && addr.dport != 5353 &&
        addr.sport != 0 && addr.dport != 0)
        goto out;

    /* whether udp traffic of our interest goes high */
    if (!smith_is_dns_armed(&g_dns_threshold))
        goto out;

    /* now prepare payload from user memory space */
    if (len > 511)
        len = 511;
    data = smith_kmalloc(len + 1, GFP_ATOMIC);
    if (!data)
        goto out;
    if (smith_copy_from_user(data, (void *)userp, len))
        goto out;
    data[len] = '\0';

    /* now parse dns record */
    smith_process_dns(&addr, data, len);

out:
    if (!IS_ERR_OR_NULL(sock))
        sockfd_put(sock);
    if (data)
        smith_kfree(data);
}

#ifdef USER_MSGHDR_SUPPORT
#define user_msghdr msghdr
#endif

static void smith_trace_sysret_recvmsg(long sockfd, unsigned long umsg, long len)
{
    struct socket *sock = NULL;
    unsigned char *data = NULL;
    struct smith_ip_addr addr;
    struct user_msghdr msg;
    struct iovec iov = {0};
    int err;

    sock = sockfd_lookup(sockfd, &err);
    if (IS_ERR_OR_NULL(sock))
        goto out;

    /* skip tcp connections */
    if (!smith_socket_is_udp(sock))
        goto out;

    /* query ip addresses */
    if (!smith_query_ip_addr(sock, &addr))
        goto out;

    /* we only care IP v4 or v6 and port 53 or 5353 */
    if (addr.sa_family != AF_INET && addr.sa_family != AF_INET6)
        goto out;
    if (addr.sport != 53 && addr.sport != 5353 &&
        addr.dport != 53 && addr.dport != 5353 &&
        addr.sport != 0 && addr.dport != 0)
        goto out;

    /* whether udp traffic of our interest goes high */
    if (!smith_is_dns_armed(&g_dns_threshold))
        goto out;

    /* copy msghdr from user memory space */
    if (smith_copy_from_user(&msg, (void *)umsg, sizeof(msg)))
        goto out;
    if (msg.msg_iovlen <= 0)
        goto out;
    if (smith_copy_from_user(&iov, msg.msg_iov, sizeof(iov)))
        goto out;

    /* now prepare payload from user memory space */
    len = iov.iov_len;
    if (len < 20)
        goto out;
    if (len > 511)
        len = 511;
    data = smith_kmalloc(len + 1, GFP_ATOMIC);
    if (!data)
        goto out;
    if (smith_copy_from_user(data, iov.iov_base, len))
        goto out;
    data[len] = '\0';

    /* now parse dns record */
    smith_process_dns(&addr, data, len);

out:
    if (!IS_ERR_OR_NULL(sock))
        sockfd_put(sock);
    if (data)
        smith_kfree(data);
}

int mprotect_pre_handler(struct kprobe *p, struct pt_regs *regs)
{
    int target_pid = -1;
    unsigned long prot;

    char *file_path = "-1";
    char *file_buf = NULL;
    char *vm_file_path = "-1";
    char *vm_file_buff = NULL;
    char *exe_path = DEFAULT_RET_STR;
    struct smith_tid *tid = NULL;
    char *pid_tree = NULL;

    struct vm_area_struct *vma;

    tid = smith_lookup_tid(current);
    if (tid) {
        exe_path = tid->st_img->si_path;
        // exe filter check
        if (smith_is_exe_trusted(tid->st_img))
            goto out;
        pid_tree = tid->st_pid_tree;
    }

    //only get PROT_EXEC mprotect info
    //The memory can be used to store instructions which can then be executed. On most architectures,
    //this flag implies that the memory can be read (as if PROT_READ had been specified).
    prot = (unsigned long)p_regs_get_arg2(regs);
    if (prot & PROT_EXEC) {

        vma = (struct vm_area_struct *)p_regs_get_arg1(regs);
        if (IS_ERR_OR_NULL(vma)) {
            mprotect_print(exe_path, prot, "-1", -1, "-1", "-1");
        } else {
            rcu_read_lock();
            if (!IS_ERR_OR_NULL(vma->vm_mm)) {
                if (!IS_ERR_OR_NULL(&vma->vm_mm->exe_file)) {
                    if (get_file_rcu(vma->vm_mm->exe_file)) {
                        file_buf = smith_kzalloc(PATH_MAX, GFP_ATOMIC);
                        file_path = smith_d_path(&vma->vm_mm->exe_file->f_path, file_buf, PATH_MAX);
                        smith_fput(vma->vm_mm->exe_file);
                    }
                }
#ifdef CONFIG_MEMCG
                target_pid = vma->vm_mm->owner->pid;
#endif
            }

            if (!IS_ERR_OR_NULL(vma->vm_file)) {
                if (get_file_rcu(vma->vm_file)) {
                    vm_file_buff =
                            smith_kzalloc(PATH_MAX, GFP_ATOMIC);
                    vm_file_path = smith_d_path(&vma->vm_file->f_path, vm_file_buff, PATH_MAX);
                    smith_fput(vma->vm_file);
                }
            }
            rcu_read_unlock();

            smith_check_privilege_escalation(PID_TREE_LIMIT, pid_tree);
            mprotect_print(exe_path, prot, file_path, target_pid, vm_file_path, pid_tree);
        }

        if (file_buf)
            smith_kfree(file_buf);

        if (vm_file_buff)
            smith_kfree(vm_file_buff);
    }

out:
    if (tid)
        smith_put_tid(tid);
    return 0;
}

int call_usermodehelper_exec_pre_handler(struct kprobe *p, struct pt_regs *regs)
{
    int wait = 0, argv_res_len = 0, argv_len = 0;
    int offset = 0, res = 0, free_argv = 0, i;
    void *si_tmp;
    char *path;
    char **argv;
    char *argv_res = NULL;
    struct subprocess_info *si;

    si_tmp = (void *)p_regs_get_arg1(regs);
    if (IS_ERR_OR_NULL(si_tmp))
        return 0;

    si = (struct subprocess_info *)si_tmp;
    wait = (int)p_regs_get_arg2(regs);

    path = (char *)si->path;
    argv = si->argv;

    if (IS_ERR_OR_NULL(path))
        return 0;

    if (!IS_ERR_OR_NULL(argv)) {
        while (argv_len <= SMITH_MAX_ARG_STRINGS) {
            if (!argv[argv_len])
                break;
            argv_res_len += strlen(argv[argv_len]) + 1;
            argv_len++;
        }
    }

    //get execve args data
    if (argv_res_len > 0) {
        argv_res = smith_kmalloc(argv_res_len + 1, GFP_ATOMIC);
        if (!argv_res) {
            argv_res = "-1";
        } else {
            free_argv = 1;
            for (i = 0; offset < argv_res_len && i < argv_len; i++) {
                res = argv_res_len - offset;
                offset += strlcpy(argv_res + offset, argv[i], res) + 1;
                *(argv_res + offset - 1) = ' ';
            }
            *(argv_res + offset) = '\0';
        }
    } else {
        argv_res = DEFAULT_RET_STR;
    }

    call_usermodehelper_exec_print(path, argv_res, wait);

    if (free_argv)
        smith_kfree(argv_res);

    return 0;
}

void rename_and_link_handler(int type, char * oldori, char * newori, char * s_id)
{
    struct smith_tid *tid = NULL;
    char *exe_path = DEFAULT_RET_STR;

    tid = smith_lookup_tid(current);
    if (tid) {
        exe_path = tid->st_img->si_path;
        // exe filter check
        if (smith_is_exe_trusted(tid->st_img))
            goto out;
    }

    if (type) {
        rename_print(exe_path, oldori, newori, s_id);
        file_creation_print(exe_path, newori);
    } else {
        link_print(exe_path, oldori, newori, s_id);
    }

out:
    if (tid)
        smith_put_tid(tid);
}

int rename_pre_handler(struct kprobe *p, struct pt_regs *regs)
{
    char *old_path_str = DEFAULT_RET_STR;
    char *new_path_str = DEFAULT_RET_STR;
    char *s_id = NULL;

    char *old_buf = NULL;
    char *new_buf = NULL;

    struct dentry *old_dentry;
    struct dentry *new_dentry;

    old_dentry = (struct dentry *)p_regs_get_arg2(regs);
    new_dentry = (struct dentry *)p_regs_get_arg4(regs);

    if (IS_ERR_OR_NULL(old_dentry) || IS_ERR_OR_NULL(new_dentry))
        return 0;

    old_buf = smith_kzalloc(PATH_MAX, GFP_ATOMIC);
    new_buf = smith_kzalloc(PATH_MAX, GFP_ATOMIC);

    if(old_buf) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 38)
        old_path_str = dentry_path_raw(old_dentry, old_buf, PATH_MAX);
#else
        old_path_str = __dentry_path(old_dentry, old_buf, PATH_MAX);
#endif
    }

    if(new_buf) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 38)
        new_path_str = dentry_path_raw(new_dentry, new_buf, PATH_MAX);
#else
        new_path_str = __dentry_path(new_dentry, new_buf, PATH_MAX);
#endif
    }

    if (IS_ERR(old_path_str))
        old_path_str = DEFAULT_RET_STR;

    if (IS_ERR(new_path_str))
        new_path_str = DEFAULT_RET_STR;

    if(!IS_ERR_OR_NULL(old_dentry->d_sb))
        s_id = old_dentry->d_sb->s_id;

    rename_and_link_handler(1, old_path_str, new_path_str, s_id);

    if(old_buf)
        smith_kfree(old_buf);

    if(new_buf)
        smith_kfree(new_buf);

    return 0;
}

int link_pre_handler(struct kprobe *p, struct pt_regs *regs)
{
    char *old_path_str = DEFAULT_RET_STR;
    char *new_path_str = DEFAULT_RET_STR;
    char *s_id = NULL;

    char *old_buf = NULL;
    char *new_buf = NULL;

    struct dentry *old_dentry;
    struct dentry *new_dentry;

    old_dentry = (struct dentry *)p_regs_get_arg1(regs);
    new_dentry = (struct dentry *)p_regs_get_arg3(regs);

    if (IS_ERR_OR_NULL(old_dentry) || IS_ERR_OR_NULL(new_dentry))
        return 0;

    old_buf = smith_kzalloc(PATH_MAX, GFP_ATOMIC);
    new_buf = smith_kzalloc(PATH_MAX, GFP_ATOMIC);

    if(old_buf) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 38)
        old_path_str = dentry_path_raw(old_dentry, old_buf, PATH_MAX);
#else
        old_path_str = __dentry_path(old_dentry, old_buf, PATH_MAX);
#endif
    }

    if(new_buf) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 38)
        new_path_str = dentry_path_raw(new_dentry, new_buf, PATH_MAX);
#else
        new_path_str = __dentry_path(new_dentry, new_buf, PATH_MAX);
#endif
    }

    if (IS_ERR(old_path_str))
        old_path_str = DEFAULT_RET_STR;

    if (IS_ERR(new_path_str))
        new_path_str = DEFAULT_RET_STR;

    if (!IS_ERR_OR_NULL(old_dentry->d_sb))
        s_id = old_dentry->d_sb->s_id;

    rename_and_link_handler(0, old_path_str, new_path_str, s_id);

    if(old_buf)
        smith_kfree(old_buf);

    if(new_buf)
        smith_kfree(new_buf);

    return 0;
}

static void smith_trace_sysret_memfd_create(char __user *name, long flags, long ret)
{
    char *exe_path = DEFAULT_RET_STR;
    struct smith_tid *tid = NULL;
    char *fdname = NULL;
    int len;

    if (IS_ERR_OR_NULL(name))
        goto out;
    len = smith_strnlen_user((char __user *)name, PATH_MAX);
    if (len <= 0 || len > PATH_MAX)
        goto out;

    tid = smith_lookup_tid(current);
    if (tid) {
        exe_path = tid->st_img->si_path;
        // exe filter check
        if (smith_is_exe_trusted(tid->st_img))
            goto out;
    }

    fdname = smith_kmalloc(len + 1, GFP_ATOMIC);
    if (!fdname)
        goto out;
    if(smith_copy_from_user(fdname, name, len))
        goto out;
    fdname[len] = '\0';

    memfd_create_print(exe_path, fdname, flags);

out:
    if (tid)
        smith_put_tid(tid);
    if (fdname)
        smith_kfree(fdname);
}

int open_pre_handler(struct kprobe *p, struct pt_regs *regs)
{
    int filename_len = 0;

    char *exe_path = DEFAULT_RET_STR;
    struct smith_tid *tid = NULL;
    char *filename = NULL;
    char __user *filename_ori;

    filename_ori = (void *)p_get_arg1_syscall(regs);
    if (IS_ERR_OR_NULL(filename_ori))
        return 0;

    filename_len = smith_strnlen_user((char __user *)filename_ori, PATH_MAX);
    if (filename_len <= 0 || filename_len > PATH_MAX)
        return 0;

    filename = smith_kmalloc(filename_len + 1, GFP_ATOMIC);
    if(!filename)
        return 0;
    if(smith_copy_from_user(filename, (char __user *)filename_ori, filename_len))
        goto out;
    filename[filename_len] = '\0';

    tid = smith_lookup_tid(current);
    if (tid) {
        exe_path = tid->st_img->si_path;
        // exe filter check
        if (smith_is_exe_trusted(tid->st_img))
            goto out;
    }

    open_print(exe_path, filename, (int)p_get_arg2_syscall(regs),
               (umode_t)p_get_arg3_syscall(regs));

out:
    if (tid)
        smith_put_tid(tid);
    smith_kfree(filename);

    return 0;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 9, 0)
struct inode *file_inode(struct file * f)
{
    return f->f_path.dentry->d_inode;
}
#endif

int write_pre_handler(struct kprobe *p, struct pt_regs *regs)
{
    struct file *file;
    const char __user *buf;
    char *exe_path = DEFAULT_RET_STR;
    struct smith_tid *tid = NULL;
    char *kbuf = NULL;
    char *pname_buf = NULL;
    char *file_path = DEFAULT_RET_STR;
    size_t len;

    file = (struct file *) p_regs_get_arg1(regs);
    buf = (const char __user *) p_regs_get_arg2(regs);
    len = (size_t) p_regs_get_arg3(regs);

    if (len <= 0 || !S_ISREG(file_inode(file)->i_mode))
        return 0;

    kbuf = smith_kzalloc(len, GFP_ATOMIC);
    if(!kbuf)
        goto out;

    if(smith_copy_from_user(kbuf, buf, len))
        goto out;

    tid = smith_lookup_tid(current);
    if (tid) {
        exe_path = tid->st_img->si_path;
        // exe filter check
        if (smith_is_exe_trusted(tid->st_img))
            goto out;
    }

    pname_buf = smith_kzalloc(PATH_MAX, GFP_ATOMIC);
    file_path = smith_d_path(&(file)->f_path, pname_buf, PATH_MAX);

    write_print(exe_path, file_path, kbuf, len);

out:
    if (pname_buf)
        smith_kfree(pname_buf);
    if (kbuf)
        smith_kfree(kbuf);
    if (tid)
        smith_put_tid(tid);

    return 0;
}

int openat_pre_handler(struct kprobe *p, struct pt_regs *regs)
{
    char *exe_path = DEFAULT_RET_STR;
    struct smith_tid *tid = NULL;
    char *filename = NULL;
    char __user *filename_ori;
    int filename_len = 0;

    filename_ori = (void *)p_get_arg2_syscall(regs);
    if (IS_ERR_OR_NULL(filename_ori))
        return 0;

    filename_len = smith_strnlen_user(filename_ori, PATH_MAX);
    if (filename_len <= 0 || filename_len > PATH_MAX)
        return 0;

    tid = smith_lookup_tid(current);
    if (tid) {
        exe_path = tid->st_img->si_path;
        // exe filter check
        if (smith_is_exe_trusted(tid->st_img))
            goto out;
    }

    filename = smith_kmalloc(filename_len + 1, GFP_ATOMIC);
    if (!filename)
        goto out;

    if (smith_copy_from_user(filename, filename_ori, filename_len))
        goto out;
    filename[filename_len] = '\0';

    open_print(exe_path, filename, (int)p_get_arg3_syscall(regs),
               (umode_t)p_get_arg4_syscall(regs));

out:
    if (tid)
        smith_put_tid(tid);
    smith_kfree(filename);

    return 0;
}

static void smith_trace_sysret_chmod_comm(char *file_path, mode_t mode, int ret)
{
    struct smith_tid *tid = NULL;
    char *exe_path = DEFAULT_RET_STR;
    char *pid_tree = NULL;
    char *id;

    tid = smith_lookup_tid(current);
    if (tid) {
        exe_path = tid->st_img->si_path;
        // exe filter check
        if (smith_is_exe_trusted(tid->st_img))
            goto out;
        pid_tree = tid->st_pid_tree;
    }

    /* query s_id of pwd's filesystem super_block */
    if (current->fs && current->fs->pwd.dentry &&
        current->fs->pwd.dentry->d_sb)
        id = current->fs->pwd.dentry->d_sb->s_id;
    else
        id = NULL;

    chmod_print(exe_path, pid_tree, file_path, id, mode, ret);

out:
    if (tid)
        smith_put_tid(tid);
}

#if defined(__NR_chmod) || IS_ENABLED(CONFIG_IA32_EMULATION) || (defined(CONFIG_ARM64) && defined(CONFIG_COMPAT))
static void smith_trace_sysret_chmod(char __user *fn, mode_t mode, int ret)
{
    char *buffer = NULL;
    char *file_path;
    int s;

    if (!(mode & (S_IXUSR | S_ISUID)))
        return;

    s = smith_strnlen_user(fn, PATH_MAX);
    if (s <= 0 || s > PATH_MAX)
        return;

    buffer = smith_kzalloc(PATH_MAX + s + 2, GFP_ATOMIC);
    if (buffer) {
        file_path = smith_get_pwd_path(buffer, PATH_MAX);
        if (file_path >= buffer && file_path < buffer + PATH_MAX) {
            int l = strlen(file_path);
            file_path[l++] = '/';
            l = smith_copy_from_user(&file_path[l], fn, s);
        }
    } else {
        file_path = NULL;
    }

    smith_trace_sysret_chmod_comm(file_path, mode, ret);

    if (buffer)
        smith_kfree(buffer);
}
#endif

static void smith_trace_sysret_fchmod(int fd, mode_t mode, int ret)
{
    char *buffer = NULL;
    char *file_path;

    if (!(mode & (S_IXUSR | S_ISUID)))
        return;

    buffer = smith_kzalloc(PATH_MAX, GFP_ATOMIC);
    if (buffer) {
        file_path = smith_get_file_path(fd, buffer, PATH_MAX);
    } else {
        file_path = NULL;
    }
    smith_trace_sysret_chmod_comm(file_path, mode, ret);

    if (buffer)
        smith_kfree(buffer);
}

static void smith_trace_sysret_fchmodat(int dfd, char __user *fn, mode_t mode, int ret)
{
    char *buffer = NULL;
    char *file_path;
    int s;

    if (!(mode & (S_IXUSR | S_ISUID)))
        return;

    s = smith_strnlen_user(fn, PATH_MAX);
    if (s <= 0 || s > PATH_MAX)
        return;

    buffer = smith_kzalloc(PATH_MAX + s + 2, GFP_ATOMIC);
    if (buffer) {
        if (AT_FDCWD == dfd)
            file_path = smith_get_pwd_path(buffer, PATH_MAX);
        else
            file_path = smith_get_file_path(dfd, buffer, PATH_MAX);
        if (file_path >= buffer && file_path < buffer + PATH_MAX) {
            int l = strlen(file_path);
            file_path[l++] = '/';
            l = smith_copy_from_user(&file_path[l], fn, s);
        }
    } else {
        file_path = NULL;
    }

    smith_trace_sysret_chmod_comm(file_path, mode, ret);

    if (buffer)
        smith_kfree(buffer);
}

/*
 * data contains the mount options specified by user. It
 * could containbinary chars or utf8/unicode, depending
 * on filesystem. The buffer is fixed as 1 page long.
 */
static int mount_check_options(char *data)
{
    int i;
    for (i = PAGE_SIZE - 1; i > 0; i--) {
        if (data[i] == 0)
            return 1;
    }
    return 0;
}

int mount_pre_handler(struct kprobe *p, struct pt_regs *regs)
{
    unsigned long flags = 0;

    char *pid_tree = NULL;
    char *exe_path = DEFAULT_RET_STR;
    struct smith_tid *tid = NULL;

    char *pname_buf = NULL;
    char *file_path = DEFAULT_RET_STR;

    char *data;
    char *fstype = NULL;
    char *dev_name = NULL;

    struct super_block *sb;
    struct path *path = NULL;

    dev_name = (char *)p_regs_get_arg1(regs);
    path = (struct path *)p_regs_get_arg2(regs);
    fstype = (char *)p_regs_get_arg3(regs);
    flags = (unsigned long)p_regs_get_arg4(regs);

    if (IS_ERR_OR_NULL(path) || !dev_name || !*dev_name)
        return 0;

    if (IS_ERR_OR_NULL(path->dentry) || IS_ERR_OR_NULL(path->dentry->d_sb))
        sb = NULL;
    else
        sb = path->dentry->d_sb;

    pname_buf = smith_kzalloc(PATH_MAX, GFP_ATOMIC);
    file_path = smith_d_path(path, pname_buf, PATH_MAX);
    data = (char *)p_regs_get_arg5(regs);
    if (!data || !mount_check_options(data))
        data = DEFAULT_RET_STR;

    tid = smith_lookup_tid(current);
    if (tid) {
        exe_path = tid->st_img->si_path;
        // exe filter check
        if (smith_is_exe_trusted(tid->st_img))
            goto out;
        pid_tree = tid->st_pid_tree;
    }

    smith_check_privilege_escalation(PID_TREE_LIMIT, pid_tree);
    mount_print(exe_path, pid_tree, dev_name, file_path, sb ? sb->s_id : NULL, fstype, flags, data);

out:
    if (tid)
        smith_put_tid(tid);
    if (pname_buf)
        smith_kfree(pname_buf);

    return 0;
}

static void smith_trace_sysret_nanosleep(long tsu)
{
    char *exe_path = DEFAULT_RET_STR;
    struct smith_tid *tid = NULL;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 18, 0)
    struct __kernel_timespec *ts;
    struct timespec64 tu = {0, 0};
#else
    struct timespec tu = {0, 0};
#endif
    if (IS_ERR_OR_NULL((void *)tsu))
        return;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 18, 0)
    ts = (struct __kernel_timespec __user *)tsu;
    if (get_timespec64(&tu, ts))
        return;

    if (!timespec64_valid(&tu))
        return;
#else
    if (smith_copy_from_user(&tu, (void __user *)tsu, sizeof(tu)))
        return;
    if (!timespec_valid(&tu))
        return;
#endif

    tid = smith_lookup_tid(current);
    if (tid) {
        exe_path = tid->st_img->si_path;
        // exe filter check
        if (smith_is_exe_trusted(tid->st_img))
            goto out;
    }

    /* Year-2038 issue: signed-32bit will overflow */
    nanosleep_print(exe_path, (long long)tu.tv_sec, tu.tv_nsec);

out:
    if (tid)
        smith_put_tid(tid);
}

static void smith_trace_sysret_kill(int pid, int sig, int ret)
{
    char *exe_path = DEFAULT_RET_STR;
    struct smith_tid *tid = NULL;

    tid = smith_lookup_tid(current);
    if (tid) {
        exe_path = tid->st_img->si_path;
        // exe filter check
        if (smith_is_exe_trusted(tid->st_img))
            goto out;
    }

    kill_print(exe_path, pid, sig, ret);

out:
    if (tid)
        smith_put_tid(tid);
}

static void smith_trace_sysret_tkill(int pid, int sig, int ret)
{
    char *exe_path = DEFAULT_RET_STR;
    struct smith_tid *tid = NULL;

    tid = smith_lookup_tid(current);
    if (tid) {
        exe_path = tid->st_img->si_path;
        // exe filter check
        if (smith_is_exe_trusted(tid->st_img))
            goto out;
    }

    tkill_print(exe_path, pid, sig, ret);

out:
    if (tid)
        smith_put_tid(tid);
}

static void smith_trace_sysret_tgkill(int tgid, int pid, int sig, int ret)
{
    char *exe_path = DEFAULT_RET_STR;
    struct smith_tid *tid = NULL;

    tid = smith_lookup_tid(current);
    if (tid) {
        exe_path = tid->st_img->si_path;
        // exe filter check
        if (smith_is_exe_trusted(tid->st_img))
            goto out;
    }

    tgkill_print(exe_path, tgid, pid, sig, ret);

out:
    if (tid)
        smith_put_tid(tid);
}


static void delete_file_handler(int type, char *path)
{
    struct smith_tid *tid = NULL;
    char *exe_path = DEFAULT_RET_STR;

    tid = smith_lookup_tid(current);
    if (tid) {
        exe_path = tid->st_img->si_path;
        // exe filter check
        if (smith_is_exe_trusted(tid->st_img))
            goto out;
    }

    if (type)
        security_path_rmdir_print(exe_path, path);
    else
        security_path_unlink_print(exe_path, path);

out:
    if (tid)
        smith_put_tid(tid);
}

static int security_path_rmdir_pre_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    char *pname_buf = NULL;
    char *pathstr = DEFAULT_RET_STR;
    struct path *dir = (void *)p_regs_get_arg1(regs);
    struct dentry *de;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 0, 0)
    if (unlikely(IS_PRIVATE(d_backing_inode(dir->dentry))))
        return 0;
#else
    if (unlikely(IS_PRIVATE(dir->dentry->d_inode)))
        return 0;
#endif

    pname_buf = smith_kzalloc(PATH_MAX, GFP_ATOMIC);
    if (pname_buf) {
        de = (void *)p_regs_get_arg2(regs);
        if (IS_ERR_OR_NULL(de)) {
            smith_kfree(pname_buf);
            return 0;
        }
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 38)
        pathstr = dentry_path_raw(de, pname_buf, PATH_MAX);
#else
        pathstr = __dentry_path(de, pname_buf, PATH_MAX);
#endif

        if (IS_ERR(pathstr))
            pathstr = DEFAULT_RET_STR;
    }

    delete_file_handler(1, pathstr);

    if (pname_buf)
        smith_kfree(pname_buf);

    return 0;
}

static int rm_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    int uid = 0;
    uid = __get_current_uid();
    if (FAKE_RM && uid != 0) {
        smith_regs_set_return_value(regs, 1);
    }
    return 0;
}

static int security_path_unlink_pre_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    char *pname_buf = NULL;
    char *pathstr = DEFAULT_RET_STR;
    struct path *dir = (void *)p_regs_get_arg1(regs);
    struct dentry *de;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 0, 0)
    if (unlikely(IS_PRIVATE(d_backing_inode(dir->dentry))))
        return 0;
#else
    if (unlikely(IS_PRIVATE(dir->dentry->d_inode)))
        return 0;
#endif

    pname_buf = smith_kzalloc(PATH_MAX, GFP_ATOMIC);
    if (pname_buf) {
        de = (void *)p_regs_get_arg2(regs);
        if (IS_ERR_OR_NULL(de)) {
            smith_kfree(pname_buf);
            return 0;
        }
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 38)
        pathstr = dentry_path_raw(de, pname_buf, PATH_MAX);
#else
        pathstr = __dentry_path(de, pname_buf, PATH_MAX);
#endif
        if (IS_ERR(pathstr))
            pathstr = DEFAULT_RET_STR;
    }

    delete_file_handler(0, pathstr);

    if (pname_buf)
        smith_kfree(pname_buf);

    return 0;
}

static void exit_handler(int type)
{
    struct smith_tid *tid = NULL;
    char *exe_path = DEFAULT_RET_STR;

    tid = smith_lookup_tid(current);
    if (tid) {
        exe_path = tid->st_img->si_path;
        // exe filter check
        if (smith_is_exe_trusted(tid->st_img))
            goto out;
    }

    if (type)
        exit_print(exe_path);
    else
        exit_group_print(exe_path);

out:
    if (tid)
        smith_put_tid(tid);
    return;
}

static int exit_pre_handler(struct kprobe *p, struct pt_regs *regs)
{
    exit_handler(1);
    return 0;
}

static int exit_group_pre_handler(struct kprobe *p, struct pt_regs *regs)
{
    exit_handler(0);
    return 0;
}

#include <linux/elf.h>

struct load_info {
    void * __user mod; /* user ptr of module data */
    unsigned long len; /* file size */
    Elf_Ehdr *hdr;  /* elf header */
    Elf_Shdr *sechdrs; /* section headers */
    char *secstrings; /* section names */
    char *modinfo; /* modinfo section */
    char *modname; /* module name */
    struct module *module; /* this module seciton */
};

static int smith_validate_section_offset(struct load_info *info, Elf_Shdr *shdr)
{
    unsigned long secend;

    /* Check for both overflow and offset/size being too large */
    secend = shdr->sh_offset + shdr->sh_size;
    if (secend < shdr->sh_offset || secend > info->len)
        return -ENOEXEC;
    return 0;
}

/*
 * Sanity checks against invalid binaries, wrong arch, weird elf version.
 *
 * Also do basic validity checks against section offsets and sizes, the
 * section name string table, and the indices used for it (sh_name).
 */
static int smith_check_elf_header(struct load_info *info)
{
    if (info->len < sizeof(*(info->hdr))) {
        pr_err("Invalid ELF header len %lu\n", info->len);
        goto no_exec;
    }

    if (memcmp(info->hdr->e_ident, ELFMAG, SELFMAG) != 0) {
        pr_err("Invalid ELF header magic: != %s\n", ELFMAG);
        goto no_exec;
    }
    if (info->hdr->e_type != ET_REL) {
        pr_err("Invalid ELF header type: %u != %u\n",
                info->hdr->e_type, ET_REL);
        goto no_exec;
    }
    if (!elf_check_arch(info->hdr)) {
        pr_err("Invalid architecture in ELF header: %u\n",
                info->hdr->e_machine);
        goto no_exec;
    }
    if (info->hdr->e_shentsize != sizeof(Elf_Shdr)) {
        pr_err("Invalid ELF section header size\n");
        goto no_exec;
    }

    /*
     * e_shnum is 16 bits, and sizeof(Elf_Shdr) is
     * known and small. So e_shnum * sizeof(Elf_Shdr)
     * will not overflow unsigned long on any platform.
     */
    if (info->hdr->e_shoff >= info->len
        || (info->hdr->e_shnum * sizeof(Elf_Shdr) >
        info->len - info->hdr->e_shoff)) {
        pr_err("Invalid ELF section header overflow\n");
        goto no_exec;
    }

    /*
     * Verify if the section name table index is valid.
     */
    if (info->hdr->e_shstrndx == SHN_UNDEF
        || info->hdr->e_shstrndx >= info->hdr->e_shnum) {
        pr_err("Invalid ELF section name index: %d || e_shstrndx (%d) >= e_shnum (%d)\n",
                info->hdr->e_shstrndx, info->hdr->e_shstrndx,
                info->hdr->e_shnum);
        goto no_exec;
    }
    return 0;

no_exec:
    return -ENOEXEC;
}

/* ignore compiler buzzing of unknown fallthrough */
#ifndef fallthrough /* fallthrough attribute supported from gcc 7 */
/* __has_attribute supported on gcc >= 5, clang >= 2.9 and icc >= 17 */
# if defined __has_attribute
#  if __has_attribute(__fallthrough__)
#   define fallthrough  __attribute__((__fallthrough__))
#  endif
# endif
# ifndef fallthrough
#  define fallthrough  do {} while (0)  /* fallthrough */
# endif
#endif

static int smith_check_elf_sections(struct load_info *info)
{
    Elf_Shdr *shdr, *strhdr;
    int i, err;

    strhdr = &info->sechdrs[info->hdr->e_shstrndx];

	/*
	 * The code assumes that section 0 has a length of zero and
	 * an addr of zero, so check for it.
	 */
    if (info->sechdrs[0].sh_type != SHT_NULL
        || info->sechdrs[0].sh_size != 0
        || info->sechdrs[0].sh_addr != 0) {
        pr_err("ELF Spec violation: section 0 type(%d)!=SH_NULL or non-zero len or addr\n",
                info->sechdrs[0].sh_type);
        goto no_exec;
    }

    for (i = 1; i < info->hdr->e_shnum; i++) {
        shdr = &info->sechdrs[i];
        switch (shdr->sh_type) {
        case SHT_NULL:
        case SHT_NOBITS:
            continue;
        case SHT_SYMTAB:
            if (shdr->sh_link == SHN_UNDEF
                || shdr->sh_link >= info->hdr->e_shnum) {
                pr_err("Invalid ELF sh_link!=SHN_UNDEF(%d) or (sh_link(%d) >= hdr->e_shnum(%d)\n",
                    shdr->sh_link, shdr->sh_link, info->hdr->e_shnum);
                goto no_exec;
            }
            fallthrough;
        default:
            err = smith_validate_section_offset(info, shdr);
            if (err < 0) {
                pr_err("Invalid ELF section in module (section %u type %u)\n",
                    i, shdr->sh_type);
                return err;
            }

            if (shdr->sh_flags & SHF_ALLOC) {
                if (shdr->sh_name >= strhdr->sh_size) {
                    pr_err("Invalid ELF section name in module (section %u type %u)\n",
                        i, shdr->sh_type);
                    return -ENOEXEC;
                }
            }
            break;
        }
    }

    return 0;

no_exec:
    return -ENOEXEC;
}

/* Find a module section: 0 means not found. */
static Elf_Shdr *smith_locate_section(const struct load_info *info, const char *name)
{
    unsigned int i;

    for (i = 1; i < info->hdr->e_shnum; i++) {
        Elf_Shdr *shdr = &info->sechdrs[i];
        /* Alloc bit cleared means "ignore it." */
        if ((shdr->sh_flags & SHF_ALLOC)
            && strcmp(info->secstrings + shdr->sh_name, name) == 0)
            return shdr;
    }
    return 0;
}

static void *smith_load_section(struct load_info *info, Elf_Shdr *shdr)
{
    char *dat = NULL;

    if (!shdr->sh_size)
        return NULL;
    if (smith_validate_section_offset(info, shdr) < 0) {
        pr_err("Invalid ELF section hdr(type %u)\n", shdr->sh_type);
        return NULL;
    }

    dat = smith_kmalloc(shdr->sh_size, GFP_ATOMIC);
    if (!dat)
        return NULL;
    if (smith_copy_from_user(dat, info->mod + shdr->sh_offset, shdr->sh_size))
        goto out;
    dat[shdr->sh_size - 1] = 0;
    return dat;

out:
    smith_kfree(dat);
    return NULL;
}

static int smith_process_module_load(struct load_info *info)
{
    Elf_Shdr *shdr;
    int i;

    /* validate elf header */
    if (info->len <= sizeof(*info->hdr))
        return -EINVAL;
    if (smith_copy_from_user(info->hdr, info->mod, sizeof(*info->hdr)))
        return -EACCES;
    if (smith_check_elf_header(info))
        return -EINVAL;

    /* allocate memory for elf sections */
    info->sechdrs = smith_kmalloc(info->hdr->e_shnum * sizeof(Elf_Shdr), GFP_ATOMIC);
    if (!info->sechdrs)
        return -ENOMEM;
    if (smith_copy_from_user(info->sechdrs, info->mod + info->hdr->e_shoff,
                            info->hdr->e_shnum * sizeof(Elf_Shdr)))
        return -EACCES;

    /* load string section */
    info->secstrings = smith_load_section(info, &info->sechdrs[info->hdr->e_shstrndx]);
    if (!info->secstrings)
        return -ENOMEM;

    /* check elf sections */
    if (smith_check_elf_sections(info))
        return -EINVAL;

    /* load .modinfo section */
    shdr = smith_locate_section(info, ".modinfo");
    if (shdr) {
        info->modinfo = smith_load_section(info, shdr);
        if (info->modinfo) {
            info->modname = smith_strstr(info->modinfo, shdr->sh_size,
                                        "name=");
            if (info->modname) {
                info->modname += 5;
                goto out;
            }

            /* use whole modinfo as module name/id */
            for (i = 0; i < shdr->sh_size - 1; i++) {
                if (0 == *((char *)info->modinfo + i))
                    *((char *)info->modinfo + i) = 0x20;
            }
            info->modname = info->modinfo;
        }
    }

    /* give a try of this_module section */
    shdr = smith_locate_section(info, ".gnu.linkonce.this_module");
    if (shdr) {
        info->module = smith_load_section(info, shdr);
        if (info->module)
            info->modname = info->module->name;
    }
    if (!info->modname)
        return -ENOMEM;

out:
    return 0;
}

static void smith_trace_sysret_init_module(void __user *mod, int len, int ret)
{
    Elf_Ehdr hdr;
    struct load_info info = {.mod = mod, .hdr = &hdr, .len = len,};

    struct smith_tid *tid = NULL;
    char *pid_tree = NULL;
    char *exe_path = DEFAULT_RET_STR;
    char *pname_buf = NULL;
    char *pname = NULL;

    tid = smith_lookup_tid(current);
    if (tid) {
        exe_path = tid->st_img->si_path;
        // exe filter check
        if (smith_is_exe_trusted(tid->st_img))
            goto out;
        pid_tree = tid->st_pid_tree;
    }

    pname_buf = smith_kzalloc(PATH_MAX, GFP_ATOMIC);
    pname = smith_d_path(&current->fs->pwd, pname_buf, PATH_MAX);

    smith_check_privilege_escalation(PID_TREE_LIMIT, pid_tree);

    /* process module data */
    if (smith_process_module_load(&info))
        goto out;

    do_init_module_print(exe_path, info.modname, pid_tree, pname);

out:
    if (tid)
        smith_put_tid(tid);
    smith_kfree(pname_buf);
    smith_kfree(info.module);
    smith_kfree(info.modinfo);
    smith_kfree(info.secstrings);
    smith_kfree(info.sechdrs);
    return;
}

static void smith_trace_sysret_finit_module(int fd, int ret)
{
    struct smith_tid *tid = NULL;
    char *pid_tree = NULL;
    char *exe_path = DEFAULT_RET_STR;
    char *pname_buf = NULL;
    char *pname = NULL;
    char *buffer = NULL;
    char *file_path;

    tid = smith_lookup_tid(current);
    if (tid) {
        exe_path = tid->st_img->si_path;
        // exe filter check
        if (smith_is_exe_trusted(tid->st_img))
            goto out;
        pid_tree = tid->st_pid_tree;
    }

    pname_buf = smith_kzalloc(PATH_MAX, GFP_ATOMIC);
    pname = smith_d_path(&current->fs->pwd, pname_buf, PATH_MAX);

    smith_check_privilege_escalation(PID_TREE_LIMIT, pid_tree);

    /* query long path of module from fd */
    buffer = smith_kzalloc(PATH_MAX, GFP_ATOMIC);
    if (buffer) {
        file_path = smith_get_file_path(fd, buffer, PATH_MAX);
    } else {
        file_path = NULL;
    }

    do_init_module_print(exe_path, file_path, pid_tree, pname);

out:
    if (tid)
        smith_put_tid(tid);
    smith_kfree(pname_buf);
    smith_kfree(buffer);
    return;
}

struct update_cred_data {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 5, 0)
    uid_t old_uid;
#else
    int old_uid;
#endif
};

int update_cred_entry_handler(struct kretprobe_instance *ri,
                              struct pt_regs *regs)
{
    struct update_cred_data *data;
    data = (struct update_cred_data *)ri->data;
    data->old_uid = __get_current_uid();
    return 0;
}

int update_cred_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct smith_tid *tid = NULL;
    char *exe_path = DEFAULT_RET_STR;
    char *pid_tree = NULL;
    struct update_cred_data *data;
    int now_uid;
    int retval;

    now_uid = __get_current_uid();
    retval = regs_return_value(regs);

    //only get old uid ≠0 && new uid == 0
    if (now_uid != 0)
        return 0;

    tid = smith_lookup_tid(current);
    if (tid) {
        exe_path = tid->st_img->si_path;
        // exe filter check
        if (smith_is_exe_trusted(tid->st_img))
            goto out;
        pid_tree = tid->st_pid_tree;
    }

    data = (struct update_cred_data *)ri->data;
    if (data->old_uid != 0) {
        smith_check_privilege_escalation(PID_TREE_LIMIT, pid_tree);
        update_cred_print(exe_path, pid_tree, data->old_uid, retval);
    }

out:
    if (tid)
        smith_put_tid(tid);

    return 0;
}

int smith_usb_ncb(struct notifier_block *nb, unsigned long val, void *priv)
{
    char *exe_path = DEFAULT_RET_STR;
    struct smith_tid *tid = NULL;
    struct usb_device *udev;

    if (IS_ERR_OR_NULL(priv))
        return 0;

    tid = smith_lookup_tid(current);
    if (tid) {
        exe_path = tid->st_img->si_path;
        // exe filter check
        if (smith_is_exe_trusted(tid->st_img))
            goto out;
    }

    udev = (struct usb_device *)priv;
    if (USB_DEVICE_ADD == val) {
        udev_print(exe_path, udev->product, udev->manufacturer, udev->serial, 1);
    } else if (USB_DEVICE_REMOVE == val){
        udev_print(exe_path, udev->product, udev->manufacturer, udev->serial, 2);
    }

out:
    if (tid)
        smith_put_tid(tid);

    return NOTIFY_OK;
}

struct kprobe call_usermodehelper_exec_kprobe = {
        .symbol_name = "call_usermodehelper_exec",
        .pre_handler = call_usermodehelper_exec_pre_handler,
};

struct kprobe mount_kprobe = {
        .symbol_name = "security_sb_mount",
        .pre_handler = mount_pre_handler,
};

struct kprobe rename_kprobe = {
        .symbol_name = "security_inode_rename",
        .pre_handler = rename_pre_handler,
};

struct kprobe link_kprobe = {
        .symbol_name = "security_inode_link",
        .pre_handler = link_pre_handler,
};

struct kretprobe update_cred_kretprobe = {
        .kp.symbol_name = "commit_creds",
        .data_size = sizeof(struct update_cred_data),
        .handler = update_cred_handler,
        .entry_handler = update_cred_entry_handler,
};

struct kprobe security_inode_create_kprobe = {
        .symbol_name = "security_inode_create",
        .pre_handler = security_inode_create_pre_handler,
};

struct kprobe mprotect_kprobe = {
        .symbol_name = "security_file_mprotect",
        .pre_handler = mprotect_pre_handler,
};

struct kprobe open_kprobe = {
        .symbol_name = P_GET_SYSCALL_NAME(open),
        .pre_handler = open_pre_handler,
};

struct kprobe openat_kprobe = {
        .symbol_name = P_GET_SYSCALL_NAME(openat),
        .pre_handler = openat_pre_handler,
};

struct kprobe write_kprobe = {
        .symbol_name = "vfs_write",
        .pre_handler = write_pre_handler,
};

struct kprobe exit_kprobe = {
        .symbol_name = P_GET_SYSCALL_NAME(exit),
        .pre_handler = exit_pre_handler,
};

struct kprobe exit_group_kprobe = {
        .symbol_name = P_GET_SYSCALL_NAME(exit_group),
        .pre_handler = exit_group_pre_handler,
};

struct kretprobe security_path_rmdir_kprobe = {
        .kp.symbol_name = "security_path_rmdir",
        .handler = rm_handler,
        .entry_handler = security_path_rmdir_pre_handler,
};

struct kretprobe security_path_unlink_kprobe = {
        .kp.symbol_name = "security_path_unlink",
        .handler = rm_handler,
        .entry_handler = security_path_unlink_pre_handler,
};

static struct notifier_block smith_usb_notifier = {
        .notifier_call = smith_usb_ncb,
};

/*
 * set minimal of maxactive as 32 to avoid possible missings
 * of kretprobe events, especially for NON-PREEMPTED systems
 * with small number of CPU cores (ex: 2-core KVM guest)
 */
static int smith_register_kretprobe(struct kretprobe *kr)
{
    int ninsts = max_t(int, 32, 2 * num_present_cpus());
    if (kr->maxactive < ninsts)
        kr->maxactive = ninsts;
    return register_kretprobe(kr);
}

static void smith_unregister_kretprobe(struct kretprobe *kr)
{
    unregister_kretprobe(kr);

    /* set addr to NULL to enable re-registeration */
    kr->kp.addr = NULL;
}

int register_call_usermodehelper_exec_kprobe(void)
{
    int ret;
    ret = register_kprobe(&call_usermodehelper_exec_kprobe);

    if (ret == 0)
        call_usermodehelper_exec_kprobe_state = 0x1;

    return ret;
}

void unregister_call_usermodehelper_exec_kprobe(void)
{
    unregister_kprobe(&call_usermodehelper_exec_kprobe);
}

int register_rename_kprobe(void)
{
    int ret;
    ret = register_kprobe(&rename_kprobe);

    if (ret == 0)
        rename_kprobe_state = 0x1;

    return ret;
}

void unregister_rename_kprobe(void)
{
    unregister_kprobe(&rename_kprobe);
}

int register_exit_kprobe(void)
{
    int ret;
    ret = register_kprobe(&exit_kprobe);

    if (ret == 0)
        exit_kprobe_state = 0x1;

    return ret;
}

void unregister_exit_kprobe(void)
{
    unregister_kprobe(&exit_kprobe);
}

int register_exit_group_kprobe(void)
{
    int ret;
    ret = register_kprobe(&exit_group_kprobe);

    if (ret == 0)
        exit_group_kprobe_state = 0x1;

    return ret;
}

void unregister_exit_group_kprobe(void)
{
    unregister_kprobe(&exit_group_kprobe);
}

int register_link_kprobe(void)
{
    int ret;
    ret = register_kprobe(&link_kprobe);

    if (ret == 0)
        link_kprobe_state = 0x1;

    return ret;
}

void unregister_link_kprobe(void)
{
    unregister_kprobe(&link_kprobe);
}

int register_create_file_kprobe(void)
{
    int ret;
    ret = register_kprobe(&security_inode_create_kprobe);
    if (ret == 0)
        create_file_kprobe_state = 0x1;

    return ret;
}

void unregister_create_file_kprobe(void)
{
    unregister_kprobe(&security_inode_create_kprobe);
}

int register_mount_kprobe(void)
{
    int ret;
    ret = register_kprobe(&mount_kprobe);
    if (ret == 0)
        mount_kprobe_state = 0x1;

    return ret;
}

void unregister_mount_kprobe(void)
{
    unregister_kprobe(&mount_kprobe);
}

int register_update_cred_kprobe(void)
{
    int ret;
    ret = smith_register_kretprobe(&update_cred_kretprobe);
    if (ret == 0)
        update_cred_kprobe_state = 0x1;

    return ret;
}

void unregister_update_cred_kprobe(void)
{
    smith_unregister_kretprobe(&update_cred_kretprobe);
}

int register_mprotect_kprobe(void)
{
    int ret;
    ret = register_kprobe(&mprotect_kprobe);
    if (ret == 0)
        mprotect_kprobe_state = 0x1;

    return ret;
}

void unregister_mprotect_kprobe(void)
{
    unregister_kprobe(&mprotect_kprobe);
}

int register_open_kprobe(void)
{
    int ret;
    ret = register_kprobe(&open_kprobe);
    if (ret == 0)
        open_kprobe_state = 0x1;

    return ret;
}

void unregister_open_kprobe(void)
{
    unregister_kprobe(&open_kprobe);
}

int register_openat_kprobe(void)
{
    int ret;
    ret = register_kprobe(&openat_kprobe);
    if (ret == 0)
        openat_kprobe_state = 0x1;

    return ret;
}

void unregister_openat_kprobe(void)
{
    unregister_kprobe(&openat_kprobe);
}

int register_security_path_rmdir_kprobe(void)
{
    int ret;
    ret = smith_register_kretprobe(&security_path_rmdir_kprobe);
    if (ret == 0)
        security_path_rmdir_kprobe_state = 0x1;

    return ret;
}

void unregister_security_path_rmdir_kprobe(void)
{
    smith_unregister_kretprobe(&security_path_rmdir_kprobe);
}

int register_security_path_unlink_kprobe(void)
{
    int ret;
    ret = smith_register_kretprobe(&security_path_unlink_kprobe);
    if (ret == 0)
        security_path_unlink_kprobe_state = 0x1;

    return ret;
}

void unregister_security_path_unlink_kprobe(void)
{
    smith_unregister_kretprobe(&security_path_unlink_kprobe);
}

int register_write_kprobe(void)
{
    int ret;
    ret = register_kprobe(&write_kprobe);
    if (ret == 0)
        write_kprobe_state = 0x1;

    return ret;
}

void unregister_write_kprobe(void)
{
    unregister_kprobe(&write_kprobe);
}

void uninstall_kprobe(void)
{
    if (UDEV_HOOK == 1) {
        static void (*smith_usb_unregister_notify) (struct notifier_block * nb);
        smith_usb_unregister_notify = (void *)__symbol_get("usb_unregister_notify");
        if (smith_usb_unregister_notify) {
            smith_usb_unregister_notify(&smith_usb_notifier);
            __symbol_put("usb_unregister_notify");
        }
    }

    if (call_usermodehelper_exec_kprobe_state == 0x1)
        unregister_call_usermodehelper_exec_kprobe();

    if (mprotect_kprobe_state == 0x1)
        unregister_mprotect_kprobe();

    if (create_file_kprobe_state == 0x1)
        unregister_create_file_kprobe();

    if (update_cred_kprobe_state == 0x1)
        unregister_update_cred_kprobe();

    if (mount_kprobe_state == 0x1)
        unregister_mount_kprobe();

    if (write_kprobe_state == 0x1)
        unregister_write_kprobe();

    if (rename_kprobe_state == 0x1)
        unregister_rename_kprobe();

    if (open_kprobe_state == 0x1)
        unregister_open_kprobe();

    if (openat_kprobe_state == 0x1)
        unregister_openat_kprobe();

    if (exit_kprobe_state == 0x1)
        unregister_exit_kprobe();

    if (exit_group_kprobe_state == 0x1)
        unregister_exit_group_kprobe();

    if (security_path_rmdir_kprobe_state == 0x1)
        unregister_security_path_rmdir_kprobe();

    if (security_path_unlink_kprobe_state == 0x1)
        unregister_security_path_unlink_kprobe();

    if (link_kprobe_state == 0x1)
        unregister_link_kprobe();
}

void install_kprobe(void)
{
    int ret;

    if (SANDBOX == 1) {
        DNS_HOOK = 1;
        USERMODEHELPER_HOOK = 1;
        //MPROTECT_HOOK = 1;
        ACCEPT_HOOK = 1;
        OPEN_HOOK = 1;
        MPROTECT_HOOK = 1;
        //NANOSLEEP_HOOK = 1;
        KILL_HOOK = 1;
        RM_HOOK = 1;
        EXIT_HOOK = 1;
        WRITE_HOOK = 1;

        PID_TREE_LIMIT = 100;
        PID_TREE_LIMIT_LOW = 100;
        EXECVE_GET_SOCK_PID_LIMIT = 100;
        EXECVE_GET_SOCK_FD_LIMIT = 100;

        FAKE_SLEEP = 1;
        FAKE_RM = 1;
    }

    if (UDEV_HOOK == 1) {
        static void (*smith_usb_register_notify) (struct notifier_block * nb);
        smith_usb_register_notify = __symbol_get("usb_register_notify");
        if (smith_usb_register_notify && __symbol_get("usb_unregister_notify")) {
            smith_usb_register_notify(&smith_usb_notifier);
            __symbol_put("usb_unregister_notify");
        }
        if (smith_usb_register_notify)
            __symbol_put("usb_register_notify");
    }

    if (RM_HOOK == 1) {
        ret = register_security_path_rmdir_kprobe();
        if (ret < 0)
            printk(KERN_INFO "[ELKEID] security_path_rmdir register_kprobe failed, returned %d\n", ret);

        ret = register_security_path_unlink_kprobe();
        if (ret < 0)
            printk(KERN_INFO "[ELKEID] security_path_unlink register_kprobe failed, returned %d\n", ret);
    }

    if (OPEN_HOOK == 1) {
        ret = register_open_kprobe();
        if (ret < 0)
            printk(KERN_INFO "[ELKEID] open register_kprobe failed, returned %d\n", ret);

        ret = register_openat_kprobe();
        if (ret < 0)
            printk(KERN_INFO "[ELKEID] openat register_kprobe failed, returned %d\n", ret);
    }

    if (WRITE_HOOK == 1) {
        ret = register_write_kprobe();
        if (ret < 0)
            printk(KERN_INFO "[ELKEID] write register_kprobe failed, returned %d\n", ret);
    }

    if (EXIT_HOOK == 1) {
        ret = register_exit_kprobe();
        if (ret < 0)
            printk(KERN_INFO "[ELKEID] exit register_kprobe failed, returned %d\n", ret);

        ret = register_exit_group_kprobe();
        if (ret < 0)
            printk(KERN_INFO "[ELKEID] exit_group register_kprobe failed, returned %d\n", ret);
    }

    if (MPROTECT_HOOK == 1) {
        ret = register_mprotect_kprobe();
        if (ret < 0)
            printk(KERN_INFO "[ELKEID] mprotect register_kprobe failed, returned %d\n", ret);
    }

    if (MOUNT_HOOK == 1) {
        ret = register_mount_kprobe();
        if (ret < 0)
            printk(KERN_INFO "[ELKEID] mount register_kprobe failed, returned %d\n", ret);
    }

    if (RENAME_HOOK == 1) {
        ret = register_rename_kprobe();
        if (ret < 0)
            printk(KERN_INFO "[ELKEID] renameat register_kprobe failed, returned %d\n", ret);
    }

    if (LINK_HOOK == 1) {
        ret = register_link_kprobe();
        if (ret < 0)
            printk(KERN_INFO "[ELKEID] link register_kprobe failed, returned %d\n", ret);
    }

    if (CREATE_FILE_HOOK == 1) {
        ret = register_create_file_kprobe();
        if (ret < 0)
            printk(KERN_INFO "[ELKEID] create_file register_kprobe failed, returned %d\n", ret);
    }

    if (USERMODEHELPER_HOOK == 1) {
        ret = register_call_usermodehelper_exec_kprobe();
        if (ret < 0)
            printk(KERN_INFO "[ELKEID] call_usermodehelper_exec register_kprobe failed, returned %d\n", ret);
    }

    if (UPDATE_CRED_HOOK == 1) {
        ret = register_update_cred_kprobe();
        if (ret < 0)
            printk(KERN_INFO "[ELKEID] update_cred register_kprobe failed, returned %d\n", ret);
    }
}

/*
 * rbtree defs for exectuable images
 */
static struct tt_rb g_rb_img;  /* rbtree of cached images */
static LIST_HEAD(g_lru_img);   /* lru list of cached images */

#define SMITH_IMG_REAPER  (600)     /* 10 minutes */
#define SMITH_IMG_MAX    (2048)     /* max cached imgs */

/*
 * callbacks for img-cache
 */

static char *smith_build_path(struct smith_img *img)
{
    char *buf = img->si_buf, *path;
    int len = SI_IMG_LENGTH;

    /* better d_absolute_path, but it's not exported */
    path = d_path(&img->si_exe->f_path, buf, img->si_max);
    while (IS_ERR(path) && len <= PATH_MAX) {
        buf = smith_kmalloc(len, GFP_ATOMIC);
        if (!buf)
            break;
        /* d_absolute_path */
        path = d_path(&img->si_exe->f_path, buf, len);
        /* got ERR_PTR(-ENAMETOOLONG) */
        if (!IS_ERR(path)) {
            img->si_max = len;
            img->si_alloc = buf;
            break;
        }
        kfree(buf);
        len += 128;
    }

    if (IS_ERR(path))
        return NULL;

    return path;
}

static int smith_build_img(struct smith_img *img)
{
    struct dentry *de;

    de = img->si_exe->f_path.dentry;
    img->si_max = SI_IMG_BUFLEN;
    img->si_sb = de->d_sb;
    img->si_ino = de->d_inode->i_ino;
    img->si_size = i_size_read(de->d_inode);
    img->si_path = smith_build_path(img);
    if (!img->si_path)
        return -ENOMEM;
    img->si_len = (uint16_t)strlen(img->si_path);
    img->si_murmur64 = hash_murmur_OAAT64(img->si_path, img->si_len);

    return 0;
}

static struct tt_node *smith_init_img(struct tt_rb *rb, void *key)
{
    struct smith_img *img;

    img = (struct smith_img *)tt_rb_alloc_node(rb);
    if (img) {
        tt_memcpy(img, key, offsetof(struct smith_img, si_age));
        /* initialize pid (binding to its tid) */
        if (smith_build_img(img)) {
            tt_rb_free_node(rb, &img->si_node);
            return 0;
        }
        INIT_LIST_HEAD(&img->si_link);
        atomic_set(&img->si_node.refs, 0);
        img->si_age = 0;
        return &img->si_node;
    }

    return NULL;
}

static int smith_cmp_img(struct tt_rb *rb, struct tt_node *tnod, void *key)
{
    struct tt_node *node = key;
    struct smith_img *img1, *img2;

    img1 = container_of(tnod, struct smith_img, si_node);
    img2 = container_of(node, struct smith_img, si_node);
    if (img2->si_ino > img1->si_ino)
        return 1;
    if (img2->si_ino < img1->si_ino)
        return -1;
    if (img2->si_size > img1->si_size)
        return 1;
    if (img2->si_size < img1->si_size)
        return -1;
    if (img2->si_sb > img1->si_sb)
        return 1;
    if (img2->si_sb < img1->si_sb)
        return -1;
    return 0;
}

static void smith_release_img(struct tt_rb *rb, struct tt_node *tnod)
{
    struct smith_img *img = container_of(tnod, struct smith_img, si_node);
    list_del(&img->si_link);
    if (img->si_max > SI_IMG_BUFLEN)
        kfree(img->si_alloc);
    tt_rb_free_node(rb, tnod);
}

/*
 * img-cache support routines
 */

static int smith_drop_head_img(void)
{
    struct list_head *link;
    struct smith_img *img;
    int rc = 0;

    write_lock(&g_rb_img.lock);
    link = g_lru_img.next;
    img = list_entry(link, struct smith_img, si_link);
    if (list_empty(&g_lru_img))
        goto errorout;

    if (0 == atomic_read(&img->si_node.refs)) {
        if (smith_get_seconds() > img->si_age) {
            list_del_init(&img->si_link);
            /* img hasn't been touched for seconds */
            /* remove this img from rbtree */
            /* drop img */
            tt_rb_remove_node_nolock(&g_rb_img, &img->si_node);
            rc++;
        } else {
            /* it doesn't timeout yet, so continue and wait */
        }
    } else {
        list_del_init(&img->si_link);
        /* smith_put_img will put it back to lru list */
    }

errorout:
    write_unlock(&g_rb_img.lock);

    return rc;
}

static void smith_drop_head_imgs(struct tt_rb *rb)
{
    int count = atomic_read(&rb->count);

    do {
        if (!smith_drop_head_img())
            break;
    } while (--count > SMITH_IMG_MAX);
}

struct smith_img *smith_get_img(struct smith_img *img)
{
    if (img)
        atomic_inc_return(&img->si_node.refs);
    return img;
}

void smith_put_img(struct smith_img *img)
{
    if (in_interrupt()) {
        img->si_age = smith_get_seconds() + SMITH_IMG_REAPER;
        atomic_dec(&img->si_node.refs);
        return;
    }

    if (atomic_add_unless(&img->si_node.refs, -1, 1))
        return;

    write_lock(&g_rb_img.lock);
    list_del_init(&img->si_link);
    if (0 == atomic_dec_return(&img->si_node.refs)) {
        img->si_age = smith_get_seconds() + SMITH_IMG_REAPER;
        list_add_tail(&img->si_link, &g_lru_img);
    }
    write_unlock(&g_rb_img.lock);

    smith_drop_head_imgs(&g_rb_img);
}

static int smith_file2img(struct file *filp, struct smith_img *img)
{
    struct dentry *de;

    if (!filp)
        return -ENOENT;
    img->si_exe = filp;

    de = img->si_exe->f_path.dentry;
    img->si_sb = de->d_sb;
    img->si_ino = file_inode(filp)->i_ino;
    img->si_size = i_size_read(file_inode(filp));

    return 0;
}

static int smith_task2img(struct task_struct *task, struct smith_img *img)
{
    struct file *filp = smith_get_task_exe_file(task);

    if (!filp)
        return -ENOENT;

    return smith_file2img(filp, img);
}

static struct smith_img *smith_find_img(struct smith_img *img)
{
    struct smith_img *si = NULL;
    struct tt_node *tnod = NULL;

    /* check whether the image was already inserted ? */
    read_lock(&g_rb_img.lock);
    tnod = tt_rb_lookup_nolock(&g_rb_img, img);
    if (tnod) {
        atomic_inc(&tnod->refs);
        read_unlock(&g_rb_img.lock);
        si = container_of(tnod, struct smith_img, si_node);
        goto errorout;
    } else {
        read_unlock(&g_rb_img.lock);
    }

    /* insert new node to rbtree */
    write_lock(&g_rb_img.lock);
    tnod = tt_rb_insert_key_nolock(&g_rb_img, &img->si_node);
    if (tnod) {
        atomic_inc(&tnod->refs);
        si = container_of(tnod, struct smith_img, si_node);
    }
    write_unlock(&g_rb_img.lock);

errorout:
    return si;
}

static struct smith_img *smith_find_task_img(struct task_struct *task)
{
    struct smith_img img, *si = NULL;

    memset(&img, 0, sizeof(img));
    if (!smith_task2img(task, &img))
        si = smith_find_img(&img);

    /* si_exe grabbed by smith_task2img */
    if (img.si_exe)
        smith_fput(img.si_exe);

    return si;
}

static struct smith_img *smith_find_file_img(struct file *filp)
{
    struct smith_img img, *si = NULL;

    memset(&img, 0, sizeof(img));
    if (!smith_file2img(filp, &img))
        si = smith_find_img(&img);

    return si;
}

static void smith_show_img(struct tt_node *tnod)
{
    struct smith_img *img;

    if (!tnod)
        return;

    img = container_of(tnod, struct smith_img, si_node);
    printk("img: %px (%s) sb: %px ino: %lu refs: %d\n",
            img, img->si_path, img->si_sb, img->si_ino,
            atomic_read(&img->si_node.refs));
}

void smith_enum_img(void)
{
    printk("enum all imgs (%u):\n", atomic_read(&g_rb_img.count));
    tt_rb_enum(&g_rb_img, smith_show_img);
}

/* FMODE_CREATED added since v4.19 */
#define SMITH_FILE_CREATION_TRACK  !defined(FMODE_CREATED)

#if SMITH_FILE_CREATION_TRACK

/*
 * cache for newly created file entries
 */

/*
 * rbtree defs for exectuable images
 */
static struct tt_rb g_rb_ent;  /* rbtree of cached ents */
static LIST_HEAD(g_lru_ent);   /* lru list of cached ents */

#define SMITH_ENT_REAPER (60)         /* 60 seconds */
#define SMITH_ENT_MAX    (1UL << 16)  /* max pathes to be cached */

static int smith_build_ent(struct smith_ent *ent, struct smith_ent *obj)
{
    uint16_t len = ent->se_len = obj->se_len;
    if (len >= SE_ENT_BUFLEN) {
        ent->se_path = smith_kzalloc(len + 1, GFP_ATOMIC);
        if (!ent->se_path)
            return -EINVAL;
    } else {
        ent->se_path = ent->se_buf;
    }
    strncpy(ent->se_path, obj->se_path, len + 1);
    ent->se_hash = obj->se_hash;
    ent->se_age = smith_get_seconds() + SMITH_ENT_REAPER;
    ent->se_tgid = current->tgid;

    return 0;
}

static struct tt_node *smith_init_ent(struct tt_rb *rb, void *key)
{
    struct tt_node *node = key;
    struct smith_ent *ent, *obj;

    ent = (struct smith_ent *)tt_rb_alloc_node(rb);
    if (ent) {
        /* initialize file entry */
        obj = container_of(node, struct smith_ent, se_node);
        if (smith_build_ent(ent, obj)) {
            tt_rb_free_node(rb, &ent->se_node);
            return 0;
        }
        INIT_LIST_HEAD(&ent->se_link);
        atomic_set(&ent->se_node.refs, 0);
        return &ent->se_node;
    }

    return NULL;
}

static int smith_cmp_ent(struct tt_rb *rb, struct tt_node *tnod, void *key)
{
    struct tt_node *node = key;
    struct smith_ent *ent1, *ent2;

    ent1 = container_of(tnod, struct smith_ent, se_node);
    ent2 = container_of(node, struct smith_ent, se_node);
    if (ent2->se_hash > ent1->se_hash)
        return 1;
    if (ent2->se_hash < ent1->se_hash)
        return -1;
    if (ent2->se_len < ent1->se_len)
        return 1;
    if (ent2->se_len < ent1->se_len)
        return -1;
    return 0;
}

static void smith_release_ent(struct tt_rb *rb, struct tt_node *tnod)
{
    struct smith_ent *ent = container_of(tnod, struct smith_ent, se_node);
    list_del(&ent->se_link);
    if (ent->se_len >= SE_ENT_BUFLEN)
        kfree(ent->se_path);
    ent->se_path = NULL;
    tt_rb_free_node(rb, tnod);
}

/*
 * support routines for entry cache of newly-created files
 */

static int smith_drop_head_ent(int count)
{
    struct list_head *link;
    struct smith_ent *ent;
    int rc = 0;

    if (count <= 0) {
        read_lock(&g_rb_ent.lock);
        if (!list_empty(&g_lru_ent)) {
            link = g_lru_ent.next;
            ent = list_entry(link, struct smith_ent, se_link);
            if (smith_get_seconds() > ent->se_age)
                count = 1;
        }
        read_unlock(&g_rb_ent.lock);
    }

    if (count <= 0)
        goto errout;

    write_lock(&g_rb_ent.lock);
    while (count--) {
        if (list_empty(&g_lru_ent))
            break;
        link = g_lru_ent.next;
        ent = list_entry(link, struct smith_ent, se_link);
        /* remove entry from lru list */
        list_del_init(&ent->se_link);
        /* this entry hasn't been touched for seconds */
        /* so remove the ent from rbtree and drop it */
        tt_rb_remove_node_nolock(&g_rb_ent, &ent->se_node);
        rc++;
    }
    write_unlock(&g_rb_ent.lock);

errout:
    return rc;
}

static void smith_drop_head_ents(struct tt_rb *rb)
{
    smith_drop_head_ent(atomic_read(&rb->count) - SMITH_ENT_MAX);
}

static void smith_prepare_ent(char *path, struct smith_ent *ent)
{
    memset(ent, 0, sizeof(*ent));
    ent->se_path = path;
    ent->se_len = strlen(path);
    ent->se_hash = hash_murmur_OAAT64(path, ent->se_len);
}

int smith_insert_ent(char *path)
{
    struct smith_ent obj, *ent;
    struct tt_node *tnod = NULL;


    /* init obj */
    smith_prepare_ent(path, &obj);

    /* check whether the entry was already inserted ? */
    read_lock(&g_rb_ent.lock);
    tnod = tt_rb_lookup_nolock(&g_rb_ent, &obj);
    read_unlock(&g_rb_ent.lock);
    if (tnod)
        goto out;

    /* insert new node to rbtree */
    write_lock(&g_rb_ent.lock);
    tnod = tt_rb_insert_key_nolock(&g_rb_ent, &obj.se_node);
    if (tnod) {
        ent = container_of(tnod, struct smith_ent, se_node);
        /* remove ent from LRU if it's already LRUed */
        list_del_init(&ent->se_link);
        ent->se_age = smith_get_seconds() + SMITH_ENT_REAPER;
        /* insert ent to the tail of LRU list */
        list_add_tail(&ent->se_link, &g_lru_ent);
    }
    write_unlock(&g_rb_ent.lock);

    smith_drop_head_ents(&g_rb_ent);

out:
    return (!!tnod);
}

int smith_remove_ent(char *path)
{
    struct smith_ent obj, *ent;
    struct tt_node *tnod = NULL;

    /* init obj */
    smith_prepare_ent(path, &obj);

    /* check whether the entry was already inserted ? */
    read_lock(&g_rb_ent.lock);
    tnod = tt_rb_lookup_nolock(&g_rb_ent, &obj);
    read_unlock(&g_rb_ent.lock);
    if (!tnod)
        goto out;

    write_lock(&g_rb_ent.lock);
    /* do 2nd search to assure it's in lru list */
    tnod = tt_rb_lookup_nolock(&g_rb_ent, &obj);
    if (tnod) {
        ent = container_of(tnod, struct smith_ent, se_node);
        list_del_init(&ent->se_link);
        tt_rb_remove_node_nolock(&g_rb_ent, tnod);
    }
    write_unlock(&g_rb_ent.lock);

out:
    smith_drop_head_ents(&g_rb_ent);
    return (!!tnod);
}

static void smith_show_ent(struct tt_node *tnod)
{
    struct smith_ent *ent;

    if (!tnod)
        return;

    ent = container_of(tnod, struct smith_ent, se_node);
    printk("ent: %px (%s) refs: %d pid: %u.\n", ent,
            ent->se_path, atomic_read(&ent->se_node.refs),
            (uint32_t)ent->se_tgid);
}

void smith_enum_ent(void)
{
    printk("smith_enum_ent: newly created ents (%u):\n",
            atomic_read(&g_rb_ent.count));
    read_lock(&g_rb_ent.lock);
    tt_rb_enum(&g_rb_ent, smith_show_ent);
    read_unlock(&g_rb_ent.lock);
    printk("smith_enum_ent: done\n");
}

#else

int smith_insert_ent(char *path)
{
    return 1;
}

int smith_remove_ent(char *path)
{
    return 1;
}

#endif /* SMITH_FILE_CREATION_TRACK */

static int smith_is_anchor(struct task_struct *task)
{
    struct {int len; char *name;} anchors[] = {
        /* ordered via len, max is TASK_COMM_LEN (16) */
        {4, "sshd"},
        {5, "login"},
        {15, "containerd-shim"},
             /* k8s ? */

        {0, 0} /* the end */
    };
    int len, i;

    /* systemd / init */
    if (NULL == task || task->pid == 1)
        return 1;

    len = strnlen(task->comm, TASK_COMM_LEN);
    if (len <= 0)
        return 0;

    for (i = 0; anchors[i].name; i++) {
        if (len < anchors[i].len)
            break;
        if (len == anchors[i].len &&
            0 == strncmp(anchors[i].name, task->comm, len))
            return 1;
    }
    return 0;
}

/*
 * hash lists for all active tasks
 */
struct hlist_root g_hlist_tid;

/* query mntns id */
uint64_t smith_query_mntns(void)
{
    struct smith_tid tid;

    if (0 == hlist_query_key(&g_hlist_tid, current, &tid))
        return tid.st_root;

    return smith_query_mntns_id(current);
}

/* query the original session id */
int smith_query_tid(struct task_struct *task)
{
    struct smith_tid tid;
    int rc = -1;

    if (0 == hlist_query_key(&g_hlist_tid, task, &tid))
        rc = tid.st_sid;

    return rc;
}

struct smith_tid *smith_lookup_tid(struct task_struct *task)
{
    struct smith_tid *tid = NULL;
    struct hlist_hnod *nod;

    nod = hlist_lookup_key(&g_hlist_tid, task);
    if (nod)
        tid = container_of(nod, struct smith_tid, st_node);

    return tid;
}

int smith_put_tid(struct smith_tid *tid)
{
    int rc = 0;
    if (tid)
        rc = hlist_deref_node(&g_hlist_tid, &tid->st_node);
    return rc;
}

int smith_drop_tid(struct task_struct *task)
{
    return hlist_remove_key(&g_hlist_tid, task);
}

/*
 * callbacks routines for tid
 */

static int smith_query_parents(struct task_struct *task)
{
    struct task_struct *old_task;
    int i = 0;

    get_task_struct(task);

    while (task && task->pid != 0) {
        i++;
        old_task = task;
        rcu_read_lock();
        task = smith_get_task_struct(rcu_dereference(task->real_parent));
        rcu_read_unlock();
        smith_put_task_struct(old_task);
    }

    if (task)
        smith_put_task_struct(task);

    return i;
}

#define PID_TREE_METADATA_LEN (10 /* len of max uint32_t */ + 2 + 16 /* TASK_COMM_LEN */ + 4 /* rounded to 32 */)
static char *smith_build_pid_tree(struct smith_tid *tid, struct task_struct *task)
{
    char pid[PID_TREE_METADATA_LEN];
    char *tree = NULL;
    int n, rc;

    get_task_struct(task);
    n = smith_query_parents(task);
    if (n > PID_TREE_LIMIT)
        n = PID_TREE_LIMIT;
    if (n < 1)
        n = 1;

    tree = smith_kzalloc(n * PID_TREE_METADATA_LEN, GFP_ATOMIC);
    if (!tree)
        goto out;
    tid->st_pid_tree = tree;
    tid->st_size_pidtree = n * PID_TREE_METADATA_LEN;

    rc = snprintf(tree, PID_TREE_METADATA_LEN, "%u.%.16s", task->tgid, task->comm);
    if (rc <= 0 || rc >= PID_TREE_METADATA_LEN)
        goto out;
    tid->st_len_pidtree = tid->st_len_current_pid = (uint16_t)rc;

    while (--n > 0) {

        struct task_struct *old_task = task;
        rcu_read_lock();
        task = smith_get_task_struct(rcu_dereference(task->real_parent));
        rcu_read_unlock();
        smith_put_task_struct(old_task);
        if (!task || task->pid == 0)
            break;

        rc = snprintf(pid, PID_TREE_METADATA_LEN, "<%u.%.16s", task->tgid, task->comm);
        if (rc <= 0 || rc >= PID_TREE_METADATA_LEN)
            break;
        strcat(tree, pid);
        tid->st_len_pidtree += (uint16_t)rc;
    }

out:
    if (task)
        smith_put_task_struct(task);

    return tree;
}

static void smith_update_comm(struct smith_tid *tid, char *comm_new)
{
    char pid[PID_TREE_METADATA_LEN];
    char *tree = tid->st_pid_tree;
    int n, o = tid->st_len_current_pid, l = tid->st_len_pidtree;

    if (!tree || l < o || l <= 0 || l >= tid->st_size_pidtree)
        return;

    /* comm_new could be longer than TASK_COMM_LEN */
    n = snprintf(pid, PID_TREE_METADATA_LEN, "%u.%.16s", tid->st_tgid, comm_new);
    if (n <= 0 || n >= PID_TREE_METADATA_LEN || l - o + n >= tid->st_size_pidtree)
        return;

    if (o != n)
        memmove(tree + n, tree + o, l - o + 1); /* extra tailing 0 */
    memcpy(tree, pid, n);
    tid->st_len_pidtree = l - o + n;
    tid->st_len_current_pid = n;
}

static int smith_build_tid(struct smith_tid *tid, struct task_struct *task)
{
    tid->st_start = smith_task_start_time(task);
    tid->st_tgid = task->tgid;
    /* flags was already inited during allocation */
    tid->st_node.flag_newsid = smith_is_anchor(task->parent);
    tid->st_sid = task_session_nr_ns(task, &init_pid_ns);
    tid->st_img = smith_find_task_img(task);
    if (!tid->st_img)
        return -ENOMEM;
    smith_build_pid_tree(tid, task);
    tid->st_root = smith_query_mntns_id(task);
    return 0;
}

static struct hlist_hnod *smith_init_tid(struct hlist_root *hr, void *key)
{
    struct task_struct *task = key;
    struct hlist_hnod *hnod;
    struct smith_tid *tid;

    hnod = hlist_alloc_node(hr);
    if (hnod) {
        tid = container_of(hnod, struct smith_tid, st_node);
        if (!smith_build_tid(tid, task))
            return &tid->st_node;
        hlist_free_node(hr, &tid->st_node);
    }

    return NULL;
}

static int smith_cmp_tid(struct hlist_root *hr, struct hlist_hnod *hnod, void *key)
{
    struct task_struct *task = key;
    struct smith_tid *tid;

    tid = container_of(hnod, struct smith_tid, st_node);
    return (tid->st_tgid != task->tgid);
}

static void smith_release_tid(struct hlist_root *hr, struct hlist_hnod *hnod)
{
    struct smith_tid *tid = container_of(hnod, struct smith_tid, st_node);

    if (unlikely(!hnod))
        return;

    /* dereference st_img */
    if (tid->st_img)
        smith_put_img(tid->st_img);
    if (tid->st_pid_tree)
        smith_kfree(tid->st_pid_tree);
    hlist_free_node(hr, hnod);
}

static int smith_insert_tid(struct task_struct *task)
{
    /* alloc tid and insert to tid hash lists */
    return !hlist_insert_key(&g_hlist_tid, task);
}

static void smith_show_tid(struct hlist_hnod *hnod)
{
    struct smith_tid *tid;

    if (!hnod)
        return;

    tid = container_of(hnod, struct smith_tid, st_node);
    printk("tgid: %u sid: %u task: %s mnt: %llu refs: %d\n",
            tid->st_tgid, tid->st_sid, tid->st_pid_tree,
            tid->st_root, atomic_read(&tid->st_node.refs));
}

void smith_enum_tid(void)
{
    printk("enum all tids:\n");
    hlist_enum(&g_hlist_tid, smith_show_tid);
}

static int smith_hash_tid(struct hlist_root *hr, void *key)
{
    struct task_struct *task = key;
    return (task->tgid & hr->nlists);
}

static void smith_process_tasks(struct hlist_root *hr)
{
    struct task_struct *task;

    hlist_lock(hr);
    /* hlist locked instead of grabing tasklist_lock */
    for_each_process(task) {
        /* skip kernel threads and tasks being shut donw */
        if (task->flags & (PF_KTHREAD | PF_EXITING))
            continue;
        /* only process group_leader */
        if (task->pid != task->tgid)
            continue;
        hlist_insert_key_nolock(hr, task);
    }
    hlist_unlock(hr);
}

/*
 * sched/process tracepoints support routines
 */

#include <linux/tracepoint.h>

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 35))
    #define TRACEPOINT_PROBE_REGISTER(p1, p2) tracepoint_probe_register(p1, p2)
    #define TRACEPOINT_PROBE_UNREGISTER(p1, p2) tracepoint_probe_unregister(p1, p2)
    #define TRACEPOINT_PROBE(probe, args...) static void probe(args)
#else
    #define TRACEPOINT_PROBE_REGISTER(p1, p2) tracepoint_probe_register(p1, p2, NULL)
    #define TRACEPOINT_PROBE_UNREGISTER(p1, p2) tracepoint_probe_unregister(p1, p2, NULL)
    #define TRACEPOINT_PROBE(probe, args...) static void probe(void *__data, args)
#endif

TRACEPOINT_PROBE(smith_trace_proc_fork,
                 struct task_struct *self,
                 struct task_struct *task)
{
    /* skip kernel threads */
    if (task->flags & PF_KTHREAD)
        return;
    /* only process group leader */
    if (task->pid != task->tgid)
        return;
    smith_insert_tid(task);
}

/*
 * Tracepoint sched_process_exec is only available for v3.4 and later kernels;
 * For earlier kernels, we have to register kretprobe handler and call manually.
 */
static void smith_trace_proc_exec(
                     void *data,
                     struct task_struct *task,
                     pid_t pid,
                     struct linux_binprm *bprm)
{
    struct smith_tid *tid = NULL;
    struct smith_img *img = NULL, *exe;

    /* already inserted ? */
    tid = smith_lookup_tid(task);
    if (!tid)
        goto errorout;

    /* update pid tree strings */
    if (task->tgid == task->pid)
        smith_update_comm(tid, task->comm);

    /* build img for execed task */
    exe = smith_find_task_img(task);
    if (exe) {
        /* update st_img with new execed image */
        img = tid->st_img;
        rcu_assign_pointer(tid->st_img, exe);
    }

errorout:
    if (img)
        smith_put_img(img);
    if (tid)
        smith_put_tid(tid);

/*
 * Workaround for ARM64:
 *
 * sys_exit tracepoint events for successful execve or execveat syscalls will be
 * bypassed. Failed execve or execveat still have notification callbacks.
 *
 * Here we are using process_exec tracepoint as a supplement to handle exec events.
 * Luckily that kernels with ARM64 support are newer than 3.4.
 *
 * This bug is to be fixed in 5.20 and later, more details:
 * 1) https://git.kernel.org/pub/scm/linux/kernel/git/arm64/linux.git/commit/?id=de6921856f99
 * 2) https://github.com/iovisor/bcc/pull/3982
 */

#if defined(CONFIG_ARM64) && LINUX_VERSION_CODE < KERNEL_VERSION(5, 20, 0)
    /* Workaround for ARM64: lack of sys_exit tracing for execve */
    if (EXECVE_HOOK)
        smith_trace_sysret_exec(0);
#endif

    return;
}

/*
 * Process exec notifier: workaround for earlier kernels (< 3.4)
 */
static void smith_trace_proc_execve(struct task_struct *task)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 4, 0)
    smith_trace_proc_exec(NULL, task, task->pid, NULL);
#endif
}

TRACEPOINT_PROBE(smith_trace_proc_exit, struct task_struct *task)
{
    /* skip kernel threads */
    if (task->flags & PF_KTHREAD)
        return;

    /* only process group leader */
    if (task->pid != task->tgid)
        return;

    /* try to cleanup current taks's tid record */
    smith_drop_tid(task);
}

#include <linux/thread_info.h>
#include <asm/syscall.h> /* syscall_get_nr() */
#include <asm/unistd.h> /* __NR_syscall defintions */


#if IS_ENABLED(CONFIG_X86) || IS_ENABLED(CONFIG_IA32_EMULATION)

/* only for x86 systems */
static void smith_trace_sysexit_x86(struct pt_regs *regs, long id, long ret)
{
    switch (id) {

        /*
         * exec related: context of execved task
         */
        case 11 /* __NR_ia32_execve */ :
        case 358 /* __NR_ia32_execveat */:
            /*
             * sched_process_exec emulation for earlier kernels (3.4).
             * execve returns -1 on error
             */
            if (ret >= 0)
                smith_trace_proc_execve(current);

            if (EXECVE_HOOK)
                smith_trace_sysret_exec(ret);
            break;

        /*
         * ptrace: PTRACE_POKETEXT and PTRACE_POKEDATA
         */
        case 26 /* __NR_ia32_ptrace */:
            if (PTRACE_HOOK)
                smith_trace_sysret_ptrace(regs->bx, regs->cx,
                                          (void *)regs->dx, ret);
            break;

        /*
         * task kill / tkill / tgkill
         */
        case 37 /* __NR_ia32_kill */:
            if (KILL_HOOK)
                smith_trace_sysret_kill(regs->bx, regs->cx, ret);
            break;
        case 238 /* __NR_ia32_tkill */:
            if (KILL_HOOK)
                smith_trace_sysret_tkill(regs->bx, regs->cx, ret);
            break;
        case 270 /* __NR_ia32_tgkill */:
            if (KILL_HOOK)
                smith_trace_sysret_tgkill(regs->bx, regs->cx, regs->dx, ret);
            break;

        /*
         * chmod operations
         */
        case 15 /* __NR_ia32_chmod */:
            if (CHMOD_HOOK)
                smith_trace_sysret_chmod((char __user *)regs->bx, regs->cx, ret);
            break;
        case 94 /* __NR_ia32_fchmod */:
            if (CHMOD_HOOK)
                smith_trace_sysret_fchmod(regs->bx, regs->cx, ret);
            break;
       case 306 /* __NR_ia32_fchmodat */:
            if (CHMOD_HOOK)
                smith_trace_sysret_fchmodat(regs->bx, (char *)regs->cx, regs->dx, ret);
            break;

        /*
         * nanosleep
         */
        case 162 /* __NR_ia32_nanosleep */:
            if (NANOSLEEP_HOOK)
                smith_trace_sysret_nanosleep(regs->bx);
            break;

        /*
         * memfd_create
         */
        case 356 /* __NR_ia32_memfd_create */:
            if (MEMFD_CREATE_HOOK)
                smith_trace_sysret_memfd_create((char __user *)regs->bx, regs->cx, ret);
            break;

        /*
         * module insmod
         */
        case 128: /* __NR_ia32_init_module */
            if (MODULE_LOAD_HOOK)
                smith_trace_sysret_init_module((char __user *)regs->bx, regs->cx, ret);
        break;

        case 350: /* __NR_ia32_finit_module */
            if (MODULE_LOAD_HOOK)
                smith_trace_sysret_finit_module(regs->bx, ret);
        break;

        /*
         * socket related
         */

        case 102 /* __NR_ia32_socketcall */:
            if (CONNECT_HOOK && SYS_CONNECT == regs->bx) {
                int32_t ua[3];
                if (copy_from_user(ua, (void *)regs->cx, sizeof(ua)))
                    break;
                smith_trace_sysret_connect(ua[0], ua[1], ua[2], ret);
            } else if (DNS_HOOK && ret >= 20 && (SYS_RECV == regs->bx ||
                                                 SYS_RECVFROM == regs->bx ||
                                                 SYS_RECVMSG == regs->bx)) {
                int32_t ua[2];
                if (copy_from_user(ua, (void *)regs->cx, sizeof(ua)))
                    break;
                if (SYS_RECVMSG == regs->bx)
                    smith_trace_sysret_recvmsg((long)ua[0], (long)ua[1], ret);
                else
                    smith_trace_sysret_recvdat((long)ua[0], (long)ua[1], ret);
            } else if (DNS_HOOK && SYS_RECVMMSG == regs->bx) {
            } else if (BIND_HOOK && SYS_BIND == regs->bx) {
                int32_t sockfd;
                if (copy_from_user(&sockfd, (void *)regs->cx, sizeof(sockfd)))
                    break;
                smith_trace_sysret_bind(sockfd, ret);
            } else if (ACCEPT_HOOK && (SYS_ACCEPT == regs->bx ||
                                       SYS_ACCEPT4 == regs->bx)) {
                smith_trace_sysret_accept(ret);
            }
            break;

        case 361 /* __NR_ia32_bind */:
            if (BIND_HOOK)
                smith_trace_sysret_bind(regs->bx, ret);
            break;

        case 362 /* __NR_ia32_connect */:
            if (CONNECT_HOOK)
                smith_trace_sysret_connect(regs->bx, regs->cx, regs->dx, ret);
            break;

        case 364 /* __NR_ia32_accept4 */:
            if (ACCEPT_HOOK)
                smith_trace_sysret_accept(ret);
            break;

        case 371 /* __NR_ia32_recvfrom */:
            if (DNS_HOOK && ret >= 20)
                smith_trace_sysret_recvdat(regs->bx, regs->cx, ret);
            break;
        case 372 /* __NR_ia32_recvmsg */:
            if (DNS_HOOK && ret >= 20)
                smith_trace_sysret_recvmsg(regs->bx, regs->cx, ret);
            break;

        default:
            break;
    }
}

#elif defined(CONFIG_ARM64) && defined(CONFIG_COMPAT)

/* only for ARM64 system */
static void smith_trace_sysexit_arm32(struct pt_regs *regs, long id, long ret)
{
    switch (id) {

        /*
         * exec related: context of execved task
         */
        case 11: /* execve */
        case 387: /* execveat */
            /*
             * sched_process_exec emulation for earlier kernels (3.4).
             * execve returns -1 on error
             */
            if (ret >= 0)
                smith_trace_proc_execve(current);

            if (EXECVE_HOOK)
                smith_trace_sysret_exec(ret);
            break;

        /*
         * ptrace: PTRACE_POKETEXT and PTRACE_POKEDATA
         */
        case 26: /* ptrace */
            if (PTRACE_HOOK)
                smith_trace_sysret_ptrace(regs->orig_x0, regs->regs[1],
                                          (void *)regs->regs[2], ret);
            break;

        /*
         * task kill / tkill / tgkill
         */
        case 37: /* kill */
            if (KILL_HOOK)
                smith_trace_sysret_kill(regs->orig_x0, regs->regs[1], ret);
            break;
        case 238: /* tkill */
            if (KILL_HOOK)
                smith_trace_sysret_tkill(regs->orig_x0, regs->regs[1], ret);
            break;
        case 268: /* tgkill */
            if (KILL_HOOK)
                smith_trace_sysret_tgkill(regs->orig_x0, regs->regs[1],
                                          regs->regs[2], ret);
            break;

        /*
         * chmod operations
         */
        case 15: /* chmod */
            if (CHMOD_HOOK)
                smith_trace_sysret_chmod((char __user *)regs->orig_x0, regs->regs[1], ret);
            break;
        case 94: /* fchmod */
            if (CHMOD_HOOK)
                smith_trace_sysret_fchmod(regs->orig_x0, regs->regs[1], ret);
            break;
       case 333: /* fchmodat */
            if (CHMOD_HOOK)
                smith_trace_sysret_fchmodat(regs->orig_x0, (char *)regs->regs[1],
                                            regs->regs[2], ret);
            break;

        /*
         * nanosleep
         */
        case 162: /* nanosleep */
            if (NANOSLEEP_HOOK)
                smith_trace_sysret_nanosleep(regs->orig_x0);
            break;

        /*
         * memfd_create
         */
        case 385: /* memfd_create */
            if (MEMFD_CREATE_HOOK)
                smith_trace_sysret_memfd_create((char __user *)regs->orig_x0,
                                                 regs->regs[1], ret);
            break;

        /*
         * module insmod
         */
        case 128: /* nit_module */
            if (MODULE_LOAD_HOOK)
                smith_trace_sysret_init_module((char __user *)regs->orig_x0,
                                               regs->regs[1], ret);
        break;

        case 379: /* finit_module */
            if (MODULE_LOAD_HOOK)
                smith_trace_sysret_finit_module(regs->orig_x0, ret);
        break;

        /*
         * socket related
         */
#if 0   /* socketcall not implemented for ARM64 */
        case 102: /* socketcall */
            if (CONNECT_HOOK && SYS_CONNECT == regs->orig_x0) {
                int32_t ua[2];
                if (copy_from_user(ua, (void *)regs->regs[1], sizeof(ua)))
                    break;
                smith_trace_sysret_connect(ua[0], ua[1], ret);
            } else if (DNS_HOOK && ret >= 20 && (SYS_RECV == regs->orig_x0 ||
                                                 SYS_RECVFROM == regs->orig_x0 ||
                                                 SYS_RECVMSG == regs->orig_x0)) {
                int32_t ua[2];
                if (copy_from_user(ua, (void *)regs->regs[1], sizeof(ua)))
                    break;
                if (SYS_RECVMSG == regs->orig_x0)
                    smith_trace_sysret_recvmsg((long)ua[0], (long)ua[1], ret);
                else
                    smith_trace_sysret_recvdat((long)ua[0], (long)ua[1], ret);
            } else if (DNS_HOOK && SYS_RECVMMSG == regs->orig_x0) {
            } else if (BIND_HOOK && SYS_BIND == regs->orig_x0) {
                int32_t sockfd;
                if (copy_from_user(&sockfd, (void *)regs->regs[1], sizeof(sockfd)))
                    break;
                smith_trace_sysret_bind(sockfd, ret);
            } else if (ACCEPT_HOOK && (SYS_ACCEPT == regs->orig_x0 ||
                                       SYS_ACCEPT4 == regs->orig_x0)) {
                smith_trace_sysret_accept(ret);
            }
            break;
#endif

        case 282: /* bind */
            if (BIND_HOOK)
                smith_trace_sysret_bind(regs->orig_x0, ret);
            break;

        case 283: /* connect */
            if (CONNECT_HOOK)
                smith_trace_sysret_connect(regs->orig_x0, regs->regs[1],
                                           regs->regs[2], ret);
            break;

        case 285: /* accept */
        case 366: /* accept4 */
            if (ACCEPT_HOOK)
                smith_trace_sysret_accept(ret);
            break;

        case 291: /* recv */
        case 292: /* recvfrom */
            if (DNS_HOOK && ret >= 20)
                smith_trace_sysret_recvdat(regs->orig_x0, regs->regs[1], ret);
            break;
        case 297: /* recvmsg */
            if (DNS_HOOK && ret >= 20)
                smith_trace_sysret_recvmsg(regs->orig_x0, regs->regs[1], ret);
            break;
        case 365: /* recvmmsg */
            break;

        default:
            break;
    }
}
#endif

static void smith_trace_sysent_close(long fd)
{
    struct smith_tid *tid = NULL;
    char *exe_path = DEFAULT_RET_STR;
    char *buffer = NULL;
    char *file_path;
    struct file *filp = smith_fget_raw(fd);

    if (!filp)
        return;

#if !SMITH_FILE_CREATION_TRACK
    if (!(filp->f_mode & FMODE_CREATED))
        goto out;
#endif

    tid = smith_lookup_tid(current);
    if (tid) {
        exe_path = tid->st_img->si_path;
        // exe filter check
        if (smith_is_exe_trusted(tid->st_img))
            goto out;
    }

    buffer = smith_kzalloc(PATH_MAX, GFP_ATOMIC);
    if (!buffer)
        goto out;

    file_path = smith_get_file_path(fd, buffer, PATH_MAX);
    if (!smith_remove_ent(file_path))
        goto out;

    /* we only care about nonempty regular files */
    if (!S_ISREG(file_inode(filp)->i_mode))
        goto out;
    if (!i_size_read(file_inode(filp)))
        goto out;
    file_creation_print(exe_path, file_path);

out:
    if (tid)
        smith_put_tid(tid);
    smith_fput(filp);
    if (buffer)
        smith_kfree(buffer);
}

static void smith_trace_sysent_prctl(long option, char __user *name)
{
    struct smith_tid *tid = NULL;
    char *exe_path = DEFAULT_RET_STR;
    char *newname = NULL;
    int len;

    //only get PS_SET_NAME data
    //PR_SET_NAME (since Linux 2.6.9)
    //Set the name of the calling thread, using the value in the lo‐
    //cation pointed to by (char *) arg2.  The name can be up to 16
    //bytes long, including the terminating null byte.  (If the
    //length of the string, including the terminating null byte, ex‐
    //ceeds 16 bytes, the string is silently truncated.)
    if (PR_SET_NAME != option || IS_ERR_OR_NULL(name))
        return;

    len = smith_strnlen_user(name, PATH_MAX);
    if (len <= 0 || len > PATH_MAX)
        return;

    newname = smith_kzalloc(len + 1, GFP_ATOMIC);
    if(!newname)
        return;

    if(smith_copy_from_user(newname, name, len)) {
        smith_kfree(newname);
        return;
    }
    newname[len] = '\0';

    tid = smith_lookup_tid(current);
    if (tid) {
        exe_path = tid->st_img->si_path;
        // exe filter check
        if (smith_is_exe_trusted(tid->st_img))
            goto out;
    }

    /*
     * pidtree to be updated in kprobe callback of set_task_comm
     * so here we won't do smith_update_comm(tid, current->comm)
     */
    prctl_print(exe_path, PR_SET_NAME, newname);

out:
    smith_kfree(newname);
    if (tid)
        smith_put_tid(tid);
}

/* create new session id (-1 if got errors) */
static void smith_trace_sysent_setsid(int ret)
{
    char *exe_path = DEFAULT_RET_STR;
    char *pid_tree = NULL;
    struct smith_tid *tid = NULL;

    tid = smith_lookup_tid(current);
    if (tid) {
        exe_path = tid->st_img->si_path;
        // exe filter check
        if (smith_is_exe_trusted(tid->st_img))
            goto out;
        pid_tree = tid->st_pid_tree;
    }

    setsid_print(exe_path, ret, pid_tree);

out:
    if (tid)
        smith_put_tid(tid);
}

#if IS_ENABLED(CONFIG_X86) || IS_ENABLED(CONFIG_IA32_EMULATION)

/* only for x86 systems */
static void smith_trace_sysent_x86(struct pt_regs *regs, long id, long ret)
{
    switch (id) {

        /*
         * close:
         */
        case 6 /* __NR_ia32_close */:
            if (CLOSE_HOOK)
                smith_trace_sysent_close(regs->bx);
            break;

        /*
         * create new session id
         */
        case 66 /*__NR_ia32_setsid */:
            if (SETSID_HOOK)
                smith_trace_sysent_setsid(ret);
            break;

        /*
         * prctl: PR_SET_NAME
         */
        case 172 /* __NR_ia32_prctl */:
            if (PRCTL_HOOK)
                smith_trace_sysent_prctl(regs->bx, (char *)regs->cx);
            break;
    }
}

#elif defined(CONFIG_ARM64) && defined(CONFIG_COMPAT)

/* only for ARM64 system */
static void smith_trace_sysent_arm32(struct pt_regs *regs, long id, long ret)
{
    switch (id) {

        /*
         * close
         */
        case 6: /* close */
            if (CLOSE_HOOK)
                smith_trace_sysent_close(regs->orig_x0);
            break;

        /*
         * create new session id
         */
        case 66: /* setsid */
            if (SETSID_HOOK)
                smith_trace_sysent_setsid(ret);
            break;

        /*
         * prctl: PR_SET_NAME
         */
        case 172: /* prctl */
            if (PRCTL_HOOK)
                smith_trace_sysent_prctl(regs->orig_x0, (char *)regs->regs[1]);
            break;
    }
}
#endif

TRACEPOINT_PROBE(smith_trace_sys_enter, struct pt_regs *regs, long ret)
{
    long id = syscall_get_nr(current, regs);

    /* ignore all kernel threads */
    if (current->flags & PF_KTHREAD)
        return;

#if BITS_PER_LONG == 32

#if IS_ENABLED(CONFIG_X86)
    /* 32bit OS - x86 / i386 */
    smith_trace_sysent_x86(regs, id, ret);
    return;
#endif

#elif BITS_PER_LONG == 64

#if IS_ENABLED(CONFIG_IA32_EMULATION)
    /*
     * Parameters passing for x86-32 syscall:
     * 1) %eax for syscall_number
     * 2) %ebx, %ecx, %edx, %esi, %edi, %ebp are used for passing 6 parameters
     * 3) if there are more than 6 arguments (very unlikely), %ebx must contain
     *    the user memory location where the list of arguments is stored
     */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 7, 0)
    /* in_ia32_syscall(): introduced after 4.7.0 */
    if (unlikely(in_ia32_syscall())) {
#else
    if (unlikely(current_thread_info()->status & TS_COMPAT)) {
#endif
        smith_trace_sysent_x86(regs, id, ret);
        return;
    }
#endif

#if defined(CONFIG_ARM64) && defined(CONFIG_COMPAT)
    if (ESR_ELx_EC_SVC32 == ESR_ELx_EC(read_sysreg(esr_el1))) {
        smith_trace_sysent_arm32(regs, id, ret);
        return;
    }
#endif

    /* 64-bit native mode: HIDS doesn't support 32bit OS */
    switch (id) {

        case __NR_close:
            if (CLOSE_HOOK)
                smith_trace_sysent_close(p_regs_get_arg1_of_syscall(regs));
            break;

        /*
         * create new session id
         */
        case __NR_setsid:
            if (SETSID_HOOK)
                smith_trace_sysent_setsid(ret);
            break;

        /*
         * prctl: PR_SET_NAME
         */
        case __NR_prctl:
            if (PRCTL_HOOK)
                smith_trace_sysent_prctl(p_regs_get_arg1_of_syscall(regs),
                                         (char __user *)p_regs_get_arg2_syscall(regs));
            break;
    }
#endif /* BITS_PER_LONG == 64 */
}

TRACEPOINT_PROBE(smith_trace_sys_exit, struct pt_regs *regs, long ret)
{
    long id = syscall_get_nr(current, regs);

    /* ignore all kernel threads */
    if (current->flags & PF_KTHREAD)
        return;

#if BITS_PER_LONG == 32

#if IS_ENABLED(CONFIG_X86)
    /* 32bit OS - x86 / i386 */
    smith_trace_sysexit_x86(regs, id, ret);
    return;
#endif

#elif BITS_PER_LONG == 64

#if IS_ENABLED(CONFIG_IA32_EMULATION)
    /*
     * Parameters passing for x86-32 syscall:
     * 1) %eax for syscall_number
     * 2) %ebx, %ecx, %edx, %esi, %edi, %ebp are used for passing 6 parameters
     * 3) if there are more than 6 arguments (very unlikely), %ebx must contain
     *    the user memory location where the list of arguments is stored
     */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 7, 0)
    /* in_ia32_syscall(): introduced after 4.7.0 */
    if (unlikely(in_ia32_syscall())) {
#else
    if (unlikely(current_thread_info()->status & TS_COMPAT)) {
#endif
        smith_trace_sysexit_x86(regs, id, ret);
        return;
    }
#endif

#if defined(CONFIG_ARM64) && defined(CONFIG_COMPAT)
    if (ESR_ELx_EC_SVC32 == ESR_ELx_EC(read_sysreg(esr_el1))) {
        smith_trace_sysexit_arm32(regs, id, ret);
        return;
    }
#endif

    /* 64-bit native mode: HIDS doesn't support 32bit OS */
    switch (id) {

        /*
         * exec related: context of execved task
         */
#ifdef       __NR_execveat
        case __NR_execveat:
#endif
        case __NR_execve:
            /*
             * sched_process_exec emulation for earlier kernels (3.4).
             * execve returns -1 on error
             */
            if (ret >= 0)
                smith_trace_proc_execve(current);

            if (EXECVE_HOOK)
                smith_trace_sysret_exec(ret);
            break;

        /*
         * ptrace: PTRACE_POKETEXT and PTRACE_POKEDATA
         */
        case __NR_ptrace:
            if (PTRACE_HOOK)
                smith_trace_sysret_ptrace(p_regs_get_arg1_of_syscall(regs),
                                          p_regs_get_arg2_syscall(regs),
                                          (void *)p_regs_get_arg3_syscall(regs),
                                          ret);
            break;

        /*
         * task kill / tkill / tgkill
         */
        case __NR_kill:
            if (KILL_HOOK)
                smith_trace_sysret_kill(p_regs_get_arg1_of_syscall(regs),
                                        p_regs_get_arg2_syscall(regs),
                                        ret);
            break;
        case __NR_tkill:
            if (KILL_HOOK)
                smith_trace_sysret_tkill(p_regs_get_arg1_of_syscall(regs),
                                         p_regs_get_arg2_syscall(regs),
                                         ret);
            break;
        case __NR_tgkill:
            if (KILL_HOOK)
                smith_trace_sysret_tgkill(p_regs_get_arg1_of_syscall(regs),
                                          p_regs_get_arg2_syscall(regs),
                                          p_regs_get_arg3_syscall(regs),
                                          ret);
            break;

        /*
         * chmod operations
         */
#ifdef       __NR_chmod
        case __NR_chmod:
            if (CHMOD_HOOK)
                smith_trace_sysret_chmod((char __user *)p_regs_get_arg1_of_syscall(regs),
                                         p_regs_get_arg2_syscall(regs), ret);
            break;
#endif
#ifdef       __NR_fchmod
        case __NR_fchmod:
            if (CHMOD_HOOK)
                smith_trace_sysret_fchmod(p_regs_get_arg1_of_syscall(regs),
                                          p_regs_get_arg2_syscall(regs), ret);
            break;
#endif
#ifdef       __NR_fchmodat
        case __NR_fchmodat:
            if (CHMOD_HOOK)
                smith_trace_sysret_fchmodat(p_regs_get_arg1_of_syscall(regs),
                                            (char *)p_regs_get_arg2_syscall(regs),
                                            p_regs_get_arg3_syscall(regs), ret);
            break;
#endif

        /*
         * nanosleep
         */
        case __NR_nanosleep:
            if (NANOSLEEP_HOOK)
                smith_trace_sysret_nanosleep(p_regs_get_arg1_of_syscall(regs));
            break;

        /*
         * memfd_create
         */
#ifdef       __NR_memfd_create /* introduced by 3.17 */
        case __NR_memfd_create:
            if (MEMFD_CREATE_HOOK)
                smith_trace_sysret_memfd_create(
                    (char __user *)p_regs_get_arg1_of_syscall(regs),
                    p_regs_get_arg2_syscall(regs), ret);
            break;
#endif

        /*
         * module insmod
         */
        case __NR_init_module:
            if (MODULE_LOAD_HOOK) {
                char *__mod = (char __user *)p_regs_get_arg1_of_syscall(regs);
                int __len = p_regs_get_arg2_syscall(regs);
                smith_trace_sysret_init_module(__mod, __len, ret);
            }
        break;
#ifdef       __NR_finit_module
        case __NR_finit_module:
            if (MODULE_LOAD_HOOK)
                smith_trace_sysret_finit_module(
                    p_regs_get_arg1_of_syscall(regs), ret);
        break;
#endif

        /*
         * socket related
         */

#ifdef       __NR_socketcall
        case __NR_socketcall:
            if (CONNECT_HOOK && SYS_CONNECT == p_regs_get_arg1_of_syscall(regs)) {
                long ua[3];
                if (copy_from_user(ua, p_regs_get_arg2_syscall(regs), sizeof(ua)))
                    break;
                smith_trace_sysret_connect(ua[0], ua[1], ua[2], ret);
            } else if (DNS_HOOK && SYS_RECV == p_regs_get_arg1_of_syscall(regs)) {
            } else if (DNS_HOOK && SYS_RECVFROM == p_regs_get_arg1_of_syscall(regs)) {
            } else if (DNS_HOOK && SYS_RECVMSG == p_regs_get_arg1_of_syscall(regs)) {
            } else if (DNS_HOOK && SYS_RECVMMSG == p_regs_get_arg1_of_syscall(regs)) {
            } else if (BIND_HOOK && SYS_BIND == p_regs_get_arg1_of_syscall(regs)) {
                long sockfd;
                if (copy_from_user(&sockfd, p_regs_get_arg2_syscall(regs), sizeof(sockfd)))
                    break;
                smith_trace_sysret_bind(sockfd, ret);
            } else if (ACCEPT_HOOK && (SYS_ACCEPT == p_regs_get_arg1_of_syscall(regs) ||
                                       SYS_ACCEPT4 == p_regs_get_arg1_syscall(regs))) {
                smith_trace_sysret_accept(ret);
            }

            break;
#endif

        case __NR_bind:
            if (BIND_HOOK)
                smith_trace_sysret_bind(p_regs_get_arg1_of_syscall(regs), ret);
            break;

        case __NR_accept:
        case __NR_accept4:
            if (ACCEPT_HOOK)
                smith_trace_sysret_accept(ret);
            break;

        case __NR_connect:
            if (CONNECT_HOOK)
                smith_trace_sysret_connect(p_regs_get_arg1_of_syscall(regs),
                                           p_regs_get_arg2_syscall(regs),
                                           p_regs_get_arg3_syscall(regs), ret);
            break;

#ifdef       __NR_recv
        case __NR_recv:
#endif
        case __NR_recvfrom:
            if (DNS_HOOK && ret >= 20)
                smith_trace_sysret_recvdat(p_regs_get_arg1_of_syscall(regs),
                                           p_regs_get_arg2_syscall(regs), ret);
            break;
        case __NR_recvmsg:
            if (DNS_HOOK && ret >= 20)
                smith_trace_sysret_recvmsg(p_regs_get_arg1_of_syscall(regs),
                                           p_regs_get_arg2_syscall(regs), ret);
            break;

        default:
            break;
    }
#endif /* BITS_PER_LONG == 64 */
}

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 3, 0))

TRACEPOINT_PROBE(smith_trace_task_rename,
                 struct task_struct *task,
                 char *buf)
{
    struct smith_tid *tid = NULL;

    /* skip kernel threads */
    if (task->flags & PF_KTHREAD || !buf)
        return;

    tid = smith_lookup_tid(task);
    if (tid) {
        if (task->tgid == task->pid)
            smith_update_comm(tid, buf);
        smith_put_tid(tid);
    }
}

#else

/*
 * 3.16 and later:
 * void __set_task_comm(struct task_struct *tsk, const char *buf, bool exec);
 *
 * pre 3.16:
 * void set_task_comm(struct task_struct *tsk, char *buf);
 */
static int set_task_comm_pre_handler(struct kprobe *kp, struct pt_regs *regs)
{
    struct task_struct *task = (void *)p_regs_get_arg1(regs);
    struct smith_tid *tid = NULL;

    /* ignore __set_task_comm callings in exec */
    if (kp->symbol_name[0] == '_' && (char)p_regs_get_arg3(regs))
        return 0;

    tid = smith_lookup_tid(task);
    if (tid) {
        if (task->tgid == task->pid)
            smith_update_comm(tid, (char *)p_regs_get_arg2(regs));
        smith_put_tid(tid);
    }

    return 0;
}

struct kprobe  set_task_comm_kprobe = {
        .symbol_name = "__set_task_comm",
        .pre_handler = set_task_comm_pre_handler,
};

#endif

struct smith_tracepoint {
    const char *name;
    void *handler;
    void *data;
    struct tracepoint *control;
} g_smith_tracepoints[] = {

    /*
     * only hook sys_exit tracepoint, since sys_enter or sys_exit will
     * affect all syscalls, and could lead performance drop of about 3
     * - 5%, even with noop-processing in the hookpoint callback
     */
    {.name = "sys_enter", .handler = smith_trace_sys_enter},
    {.name = "sys_exit", .handler = smith_trace_sys_exit},

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 3, 0)
    {.name = "task_rename", .handler = smith_trace_task_rename},
#endif
    {.name = "sched_process_exit", .handler = smith_trace_proc_exit},
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 4, 0)
    {.name = "sched_process_exec", .handler = smith_trace_proc_exec},
#endif
    {.name = "sched_process_fork", .handler = smith_trace_proc_fork} };
#define NUM_TRACE_POINTS (sizeof(g_smith_tracepoints) / sizeof(struct smith_tracepoint))

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 15, 0)
static void smith_query_tracepoints(struct tracepoint *tp, void *ignore)
{
    int i;
    for (i = 0; i < NUM_TRACE_POINTS; i++) {
        if (strcmp(g_smith_tracepoints[i].name, tp->name) == 0)
            g_smith_tracepoints[i].control = tp;
    }
}
static int smith_assert_tracepoints(void)
{
    int i;

    for_each_kernel_tracepoint(smith_query_tracepoints, NULL);
    for (i = 0; i < NUM_TRACE_POINTS; i++) {
        if (!g_smith_tracepoints[i].control)
            return -ENOENT;
    }

    return 0;
}
static int smith_register_tracepoint(struct smith_tracepoint *tp)
{
    return tracepoint_probe_register(tp->control, tp->handler, tp->data);
}
static int smith_unregister_tracepoint(struct smith_tracepoint *tp)
{
    return tracepoint_probe_unregister(tp->control, tp->handler, tp->data);
}
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 35)
static int smith_assert_tracepoints(void)
{
    return 0;
}
static int smith_register_tracepoint(struct smith_tracepoint *tp)
{
    return tracepoint_probe_register(tp->name, tp->handler, tp->data);
}
static int smith_unregister_tracepoint(struct smith_tracepoint *tp)
{
    return tracepoint_probe_unregister(tp->name, tp->handler, tp->data);
}
#else
static int smith_assert_tracepoints(void)
{
    return 0;
}
static int smith_register_tracepoint(struct smith_tracepoint *tp)
{
    return tracepoint_probe_register(tp->name, tp->handler);
}
static int smith_unregister_tracepoint(struct smith_tracepoint *tp)
{
    return tracepoint_probe_unregister(tp->name, tp->handler);
}
#endif

static int __init smith_tid_init(void)
{
    int i, rc, nimgs, ntids;

    /* check the tracepoints of our interest */
    rc = smith_assert_tracepoints();
    if (rc)
        goto errorout;

    /* check dns parameters */
    smith_check_dns_params();

    /* number of cached objects to be pre-allocated */
    ntids = 64 * num_present_cpus();
    if (ntids < 512)
        ntids = 512;
    if (ntids > (SMITH_IMG_MAX << 1))
        ntids = SMITH_IMG_MAX << 1;
    nimgs = SMITH_IMG_MAX;
    if (nimgs > ntids)
        nimgs = ntids;

    rc = tt_rb_init(&g_rb_img, 0, nimgs,
                    SI_IMG_LENGTH, GFP_ATOMIC, 0,
                    smith_init_img, smith_cmp_img,
                    smith_release_img);
    if (rc)
        goto errorout;
    rc = hlist_init(&g_hlist_tid, 0, ntids,
                    sizeof(struct smith_tid), GFP_ATOMIC, 0,
                    smith_init_tid, smith_hash_tid,
                    smith_cmp_tid, smith_release_tid);
    if (rc)
        goto fini_rb_img;
#if SMITH_FILE_CREATION_TRACK
    rc = tt_rb_init(&g_rb_ent, 0, SMITH_ENT_MAX,
                    SE_ENT_LENGTH, GFP_ATOMIC, 0,
                    smith_init_ent, smith_cmp_ent,
                    smith_release_ent);
    if (rc)
        goto fini_rb_ent;
#endif

    /* register callbacks for the tracepoints of our interest */
    for (i = 0; i < NUM_TRACE_POINTS; i++) {
        rc = smith_register_tracepoint(&g_smith_tracepoints[i]);
        if (rc)
            goto clean_trace;
    }

    /* enum active tasks and build tid for each user task */
    smith_process_tasks(&g_hlist_tid);

#if (LINUX_VERSION_CODE < KERNEL_VERSION(3, 3, 0))
    /*
     * try __set_task_comm first, then set_task_comm. kernels >= 3.16 should work
     * with __set_task_comm, and the 2nd try should work for kernels < 3.16
     */
    if (register_kprobe(&set_task_comm_kprobe)) {
        set_task_comm_kprobe.symbol_name = &set_task_comm_kprobe.symbol_name[2];
        register_kprobe(&set_task_comm_kprobe);
    }
#endif

errorout:
    return rc;

clean_trace:
    while (--i >= 0)
        smith_unregister_tracepoint(&g_smith_tracepoints[i]);

#if SMITH_FILE_CREATION_TRACK
    tt_rb_fini(&g_rb_ent);
fini_rb_ent:
#endif
    hlist_fini(&g_hlist_tid);
fini_rb_img:
    tt_rb_fini(&g_rb_img);

    return rc;
}

static void smith_tid_fini(void)
{
    int i;

    /* register callbacks for the tracepoints of our interest */
    for (i = NUM_TRACE_POINTS; i > 0; i--)
        smith_unregister_tracepoint(&g_smith_tracepoints[i - 1]);

#if (LINUX_VERSION_CODE < KERNEL_VERSION(3, 3, 0))
    unregister_kprobe(&set_task_comm_kprobe);
#endif

    hlist_fini(&g_hlist_tid);
    tt_rb_fini(&g_rb_img);
#if SMITH_FILE_CREATION_TRACK
    tt_rb_fini(&g_rb_ent);
#endif
}

static void __init smith_init_systemd_ns(void)
{
    struct pid *pid_struct;
    struct task_struct *task;
    struct path root;

    pid_struct = find_get_pid(1);
    if (!pid_struct)
        return;
    task = get_pid_task(pid_struct, PIDTYPE_PID);
    if (!task) {
        put_pid(pid_struct);
        return;
    }
    root = task->fs->root;
    if (root.mnt)
        ROOT_MNT_SB = root.mnt->mnt_sb;
    if (task->nsproxy)
        ROOT_MNT_NS = task->nsproxy->mnt_ns;
    ROOT_MNT_NS_ID = smith_query_mntns_id(task);
    smith_put_task_struct(task);
    put_pid(pid_struct);
}

/*
 * netfilter nf_hooks for port-scan attack detection
 */
#define TCP_FLAG_NUL __constant_cpu_to_be32(0x80000000)
static unsigned long g_psad_flags = TCP_FLAG_SYN;

static unsigned int smith_nf_psad_v4_handler(
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 4, 0)
                    void *priv,
                    struct sk_buff *skb,
                    const struct nf_hook_state *state
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4, 1, 0)
                    const struct nf_hook_ops *ops,
                    struct sk_buff *skb,
                    const struct nf_hook_state *state
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3, 13, 0)
                    const struct nf_hook_ops *ops,
                    struct sk_buff *skb,
                    const struct net_device *in,
                    const struct net_device *out,
                    int (*okfn)(struct sk_buff *)
#else
                    unsigned int hooknum,
                    struct sk_buff *skb,
                    const struct net_device *in,
                    const struct net_device *out,
                    int (*okfn)(struct sk_buff *)
#endif
    )
{
    const struct iphdr *iph = ip_hdr(skb);
    const struct tcphdr *tcp;
    u32 len;
    int flags = 0;

    if (iph->protocol != IPPROTO_TCP)
        goto out;
    len = ntohs(iph->tot_len);
    if (len > skb->len || sizeof(*iph) + sizeof(*tcp) > skb->len)
        goto out;
    tcp = (struct tcphdr *)(iph + 1) /* tcp_hdr(skb) */;

    flags |= (tcp->syn ? TCP_FLAG_SYN : 0) |
             (tcp->fin ? TCP_FLAG_FIN : 0) |
             (tcp->rst ? TCP_FLAG_RST : 0) |
             (tcp->urg ? TCP_FLAG_URG : 0) |
             (tcp->ack ? TCP_FLAG_ACK : 0) |
             (tcp->psh ? TCP_FLAG_PSH : 0);
    if (flags) {
        if (!(flags & g_psad_flags))
            goto out;
    } else {
        if (!(g_psad_flags & TCP_FLAG_NUL))
            goto out;
    }

    /* skip if src or dst are in allowlist */
    if (g_flt_ops.ipv4_check(iph->saddr))
        goto out;
    if (g_flt_ops.ipv4_check(iph->daddr))
        goto out;

    /* report the malicious scanning */
    psad4_print(iph->saddr, ntohs(tcp->source),
                iph->daddr, ntohs(tcp->dest), flags);

out:
    return NF_ACCEPT;
}

#if IS_ENABLED(CONFIG_IPV6)
static unsigned int smith_nf_psad_v6_handler(
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 4, 0)
                    void *priv,
                    struct sk_buff *skb,
                    const struct nf_hook_state *state
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4, 1, 0)
                    const struct nf_hook_ops *ops,
                    struct sk_buff *skb,
                    const struct nf_hook_state *state
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3, 13, 0)
                    const struct nf_hook_ops *ops,
                    struct sk_buff *skb,
                    const struct net_device *in,
                    const struct net_device *out,
                    int (*okfn)(struct sk_buff *)
#else
                    unsigned int hooknum,
                    struct sk_buff *skb,
                    const struct net_device *in,
                    const struct net_device *out,
                    int (*okfn)(struct sk_buff *)
#endif
    )
{
    const struct ipv6hdr *iph = ipv6_hdr(skb);
    const struct tcphdr *tcp;
    u32 len;
    int flags = 0;

    if (iph->version != 6)
        goto out;
    if (iph->nexthdr != 6 /* NEXTHDR_TCP */)
        goto out;
    len = ntohs(iph->payload_len);
    if (len + sizeof(*iph) > skb->len || sizeof(*iph) + sizeof(*tcp) > skb->len)
        goto out;
    tcp = (struct tcphdr *)(iph + 1) /* tcp_hdr(skb) */;

    flags |= (tcp->syn ? TCP_FLAG_SYN : 0) |
             (tcp->fin ? TCP_FLAG_FIN : 0) |
             (tcp->rst ? TCP_FLAG_RST : 0) |
             (tcp->urg ? TCP_FLAG_URG : 0) |
             (tcp->ack ? TCP_FLAG_ACK : 0) |
             (tcp->psh ? TCP_FLAG_PSH : 0);
    if (flags) {
        if (!(flags & g_psad_flags))
            goto out;
    } else {
        if (!(g_psad_flags & TCP_FLAG_NUL))
            goto out;
    }

    /* skip if src or dst are in allowlist */
    if (g_flt_ops.ipv6_check((uint32_t *)&iph->saddr))
        goto out;
    if (g_flt_ops.ipv6_check((uint32_t *)&iph->daddr))
        goto out;

    psad6_print(&iph->saddr, ntohs(tcp->source),
                &iph->daddr, ntohs(tcp->dest), flags);

out:
    return NF_ACCEPT;
}
#endif

static struct nf_hook_ops g_smith_nf_psad[] = {
        {
                .hook = (void *)smith_nf_psad_v4_handler,
                .pf =           NFPROTO_IPV4,
                .hooknum =      NF_INET_PRE_ROUTING,
                .priority =     NF_IP_PRI_FIRST,
        },
#if IS_ENABLED(CONFIG_IPV6)
        {
                .hook = (void *)smith_nf_psad_v6_handler,
                .pf =           NFPROTO_IPV6,
                .hooknum =      NF_INET_PRE_ROUTING,
                .priority =     NF_IP_PRI_FIRST,
        },
#endif
};

static DEFINE_MUTEX(g_nf_psad_lock);
static int g_nf_psad_switch = 0;
static int g_nf_psad_status = 0;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 3, 0)

static int smith_nf_psad_reg(struct net *net)
{
    return nf_register_net_hooks(net, g_smith_nf_psad, ARRAY_SIZE(g_smith_nf_psad));
}

static void smith_nf_psad_unreg(struct net *net)
{
    nf_unregister_net_hooks(net, g_smith_nf_psad, ARRAY_SIZE(g_smith_nf_psad));
}

#else

static atomic_t g_nf_hooks_regged = ATOMIC_INIT(0);

static int smith_nf_psad_reg(struct net *net)
{
    int rc = 0;

    /*
     * only do register for the 1st time. We need control the callings of
     * nf_register_hooks if we keep register_pernet_subsys for kernels < 4.3
     */
    if (1 == atomic_inc_return(&g_nf_hooks_regged))
        rc = nf_register_hooks(g_smith_nf_psad, ARRAY_SIZE(g_smith_nf_psad));

    return rc;
}

static void smith_nf_psad_unreg(struct net *net)
{
    /* do cleanup for the last instance of net namespace */
    if (0 == atomic_dec_return(&g_nf_hooks_regged))
        nf_unregister_hooks(g_smith_nf_psad, ARRAY_SIZE(g_smith_nf_psad));
}

#endif /* >= 4.3.0 */

static struct pernet_operations smith_psad_net_ops = {
    .init = smith_nf_psad_reg,
    .exit = smith_nf_psad_unreg,
};

static void smith_switch_psad(void)
{
    mutex_lock(&g_nf_psad_lock);
    if (g_nf_psad_switch != g_nf_psad_status) {
        if (g_nf_psad_switch) {
            if (!register_pernet_subsys(&smith_psad_net_ops))
                g_nf_psad_status = 1;
            else
                g_nf_psad_switch = 0;
        } else {
            unregister_pernet_subsys(&smith_psad_net_ops);
            g_nf_psad_status = 0;
        }
        printk("psad_switch: %d psad_status: %d\n", g_nf_psad_switch, g_nf_psad_status);
    }
    mutex_unlock(&g_nf_psad_lock);
}

#if defined(module_param_cb)
# define K_PARAM_CONST const
#else
# define K_PARAM_CONST
#endif

static int psad_set_params(const char *val, K_PARAM_CONST struct kernel_param *kp)
{
    if (0 == strcmp(kp->name, "psad_switch")) {
        int rc = param_set_bool(val, kp);
        if (!rc)
            smith_switch_psad();
        return rc;
    }

    if (0 == strcmp(kp->name, "psad_flags"))
        return param_set_ulong(val, kp);

    return 0;
}

static struct {
    unsigned long flag;
    char *name;
} g_psad_tcp_flags[] = {
    { TCP_FLAG_NUL, "NUL" },
    { TCP_FLAG_FIN, "FIN" },
    { TCP_FLAG_SYN, "SYN" },
    { TCP_FLAG_RST, "RST" },
    { TCP_FLAG_PSH, "PSH" },
    { TCP_FLAG_ACK, "ACK" },
    { TCP_FLAG_URG, "URG" },
    {0}
};

static int psad_get_params(char *val, K_PARAM_CONST struct kernel_param *kp)
{
    int len, i;

    if (0 == strcmp(kp->name, "psad_switch"))
        return param_get_bool(val, kp);

    if (0 != strcmp(kp->name, "psad_flags"))
        return 0;

    len = scnprintf(val, PAGE_SIZE, "0x%8.8lx:", g_psad_flags);
    for (i = 0; g_psad_tcp_flags[i].flag; i++) {
        int rc = scnprintf(val + len, PAGE_SIZE - len, " %c%s (%lx)",
                    (g_psad_flags & g_psad_tcp_flags[i].flag) ? '+' : '-',
                    g_psad_tcp_flags[i].name, g_psad_tcp_flags[i].flag);
        len = len + rc;
    }
    return len + scnprintf(val + len, PAGE_SIZE - len, "\n");
}

#if defined(module_param_cb)
const struct kernel_param_ops psad_params_ops = {
    .set = psad_set_params,
    .get = psad_get_params,
};
module_param_cb(psad_switch, &psad_params_ops, &g_nf_psad_switch, 0600);
module_param_cb(psad_flags, &psad_params_ops, &g_psad_flags, 0600);
#elif defined(module_param_call)
module_param_call(psad_switch, psad_set_params, psad_get_params, &g_nf_psad_switch, 0600);
module_param_call(psad_flags, psad_set_params, psad_get_params, &g_psad_flags, 0600);
#else
# warning "moudle_param_cb or module_param_call are not supported by target kernel"
#endif
MODULE_PARM_DESC(psad_switch, "Set to 1 to enable detection of port-scanning, 0 otherwise");
MODULE_PARM_DESC(psad_flags, "psad scanning mask of tcp flags");

/*
 * file md5 hash computation
 */

#include <crypto/hash.h>

typedef struct {
    struct shash_desc shash;
    char ctx[];
} smith_shash_t;

typedef struct {
    smith_shash_t *md5;
    struct crypto_shash *tfm;
} smith_md5_t;

static int smith_md5_create(smith_md5_t *md5)
{
    struct crypto_shash *tfm;
    smith_shash_t *shash;
    int len, rc;

    if(!md5)
        return -EINVAL;

    tfm = crypto_alloc_shash("md5", 0, 0);
    if (IS_ERR(tfm))
        return PTR_ERR(tfm);

    len = sizeof(*shash) + crypto_shash_descsize(tfm);
    shash = kzalloc(len, GFP_KERNEL);
    if (shash == NULL) {
        crypto_free_shash(tfm);
        return -ENOMEM;
    }

    shash->shash.tfm = tfm;
    rc = crypto_shash_init(&shash->shash);
    if (rc) {
        kfree(shash);
        crypto_free_shash(tfm);
        return rc;
    }

    md5->tfm = tfm;
    md5->md5 = shash;

    return 0;
}

static int smith_md5_update(smith_md5_t *md5, char *buf, int len)
{
    if (md5 == NULL || md5->md5 == NULL || buf == NULL)
        return -EINVAL;

    return crypto_shash_update(&md5->md5->shash, buf, len);
}

static int smith_md5_final(smith_md5_t *md5, char *out)
{
    if (md5 == NULL || md5->md5 == NULL || out == NULL)
        return -EINVAL;

    return crypto_shash_final(&md5->md5->shash, out);
}

static void smith_md5_destroy(smith_md5_t *md5)
{
    if (IS_ERR_OR_NULL(md5))
        return;

    if (md5->md5)
        kfree(md5->md5);
    if (md5->tfm)
        crypto_free_shash(md5->tfm);
    md5->tfm = NULL;
    md5->md5 = NULL;
}

int smith_get_hash_file(struct file *file, image_hash_t *hash)
{
    char *buf = NULL;
    smith_md5_t md5 = {0};
    loff_t off = 0;
    ssize_t rc = 0, len = 1048576;

    if (hash == NULL || file == NULL)
        return -EINVAL;

    hash->size = i_size_read(file_inode(file));
    if (!hash->size)
        return -EINVAL;
    if (len > hash->size)
        len = hash->size;

    memset(&md5, 0, sizeof(smith_md5_t));
    rc = smith_md5_create(&md5);
    if (rc) {
        printk("failed to create md5 crypto, rc=%zd\n", rc);
        return rc;
    }

    buf = vmalloc(len);
    if (!buf) {
        rc = -ENOMEM;
        goto out;
    }

    do {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 14, 0)
        rc = kernel_read(file, buf, len, &off);
        if (rc <= 0)
            break;
#else
        rc = kernel_read(file, off, buf, len);
        if (rc <= 0)
            break;
        off += rc;
#endif
        rc = smith_md5_update(&md5, buf, rc);
        if (rc) {
            printk("md5 update failure: rc=%zd\n", rc);
            goto out;
        }
    } while (off < 1048576 * 2 && off < hash->size);

    rc = smith_md5_final(&md5, (char *)&hash->hash);
    if (rc) {
        printk("crypto_shash_final: rc=%zd\n", rc);
        goto out;
    }
    hash->hlen = 16;

out:
    smith_md5_destroy(&md5);
    if (buf)
        vfree(buf);
    return rc;
}

static void exe_block_notify(char *rule, char *file_path, char *args)
{
    char *pname = DEFAULT_RET_STR;
    char *pname_buf = NULL;
    char *pid_tree = NULL;
    char *exe_path = file_path;
    struct smith_tid *tid = NULL;

    tid = smith_lookup_tid(current);
    if (tid) {
        if (!exe_path)
            exe_path = tid->st_img->si_path;
        pid_tree = tid->st_pid_tree;
    }

    pname_buf = smith_kzalloc(PATH_MAX, GFP_ATOMIC);
    pname = smith_d_path(&current->fs->pwd, pname_buf, PATH_MAX);

    exe_warn_md5_print(exe_path, rule, args, pname, pid_tree, NULL);

    if (pname_buf)
        smith_kfree(pname_buf);
    if (tid)
        smith_put_tid(tid);
}

static void md5_block_notify(image_hash_t *hash, char *file_path, char *args)
{
    char *pname = DEFAULT_RET_STR;
    char *pname_buf = NULL;
    char *pid_tree = NULL;
    char *exe_path = file_path;
    struct smith_tid *tid = NULL;
    char rule[12];
    char md5s[36] = {0};
    int i;

    for (i = 0; i < 16; i++)
        sprintf(&md5s[i * 2], "%2.2x", hash->hash.v8[i]);
    snprintf(rule, sizeof(rule), "EL%6.6s", hash->id);
    tid = smith_lookup_tid(current);
    if (tid) {
        if (!exe_path)
            exe_path = tid->st_img->si_path;
        pid_tree = tid->st_pid_tree;
    }

    pname_buf = smith_kzalloc(PATH_MAX, GFP_ATOMIC);
    pname = smith_d_path(&current->fs->pwd, pname_buf, PATH_MAX);

    exe_warn_md5_print(exe_path, rule, args, pname, pid_tree, md5s);

    if (pname_buf)
        smith_kfree(pname_buf);
    if (tid)
        smith_put_tid(tid);
}

static char *smith_query_args(struct linux_binprm *bprm)
{
    struct page *page = NULL;
    struct mm_struct *mm = bprm->mm;
    char *kaddr, *cmd = NULL;
    unsigned long pos = bprm->p;
    int ret, i, nargs = 0;

    /* remap args page, should be already mapped by copy_strings */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 5, 0)
    ret = get_user_pages_remote(mm, pos, 1, FOLL_FORCE, &page, NULL);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(5, 9, 0)
    ret = get_user_pages_remote(mm, pos, 1, FOLL_FORCE, &page, NULL, NULL);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4, 10, 0)
    ret = get_user_pages_remote(current, mm, pos, 1, FOLL_FORCE, &page, NULL, NULL);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4, 9, 0)
    ret = get_user_pages_remote(current, mm, pos, 1, FOLL_FORCE, &page, NULL);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4, 6, 0)
    ret = get_user_pages_remote(current, mm, pos, 1, 0, 1, &page, NULL);
#else
    ret = get_user_pages(current, mm, pos, 1, 0, 1, &page, NULL);
#endif
    if (ret <= 0)
        return cmd;
    if (!page)
        return cmd;

    kaddr = kmap(page);
    if (kaddr) {
        uint32_t offset = (uint32_t)(pos % PAGE_SIZE);
        for (i = offset + 1; i < PAGE_SIZE; i++) {
            if (kaddr[i] == 0) {
                nargs++;
                if (nargs >= bprm->argc)
                    break;
            }
        }
        if (i > offset) {
            cmd = smith_kzalloc(i - offset + 1, GFP_KERNEL);
            if (cmd) {
                memcpy(cmd, kaddr + offset, i - offset);
                i -= offset;
                while (--i >= 0) {
                    if (!cmd[i])
                        cmd[i] = ' ';
                }
            }
        }
        kunmap(page);
    }
    put_page(page);
    return cmd;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 8, 0)
static int smith_exec_load(struct linux_binprm *bprm)
#else
static int smith_exec_load(struct linux_binprm *bprm, struct pt_regs *regs)
#endif
{
    char *file_path = (char *)bprm->filename;
    char *buffer = NULL, *args = NULL;
    char *stdin_buf = NULL, *stdout_buf = NULL;
    struct smith_img *img = NULL;
    struct file *file;
    struct exe_item ei[4] = {{0}, {0}, {0}, {0}};
    image_hash_t md5 = {0};
    char id[12] = {0};
    int rc = -ENOEXEC; /* continue to next bprm checking */

    /* always do md5 hash computing as required */
    if (bprm->file) {
        img = smith_find_file_img(bprm->file);
        if (img && !img->si_node.flag_usr1) {
            if (!smith_get_hash_file(bprm->file, &md5) &&
                img->si_size == md5.size) {
                memcpy(&img->si_md5, &md5, sizeof(md5));
                img->si_node.flag_usr1 = 1;
            }
        }
    }

    /* both path and hash rules are empty, so skip */
    if (!g_flt_ops.rule_check(NULL, 0, NULL) &&
        !g_flt_ops.hash_check(NULL))
        return -ENOEXEC;

    /*
     * path rules matching
     */

    /* query stdin */
    file = smith_fget_raw(0);
    if (file) {
        stdin_buf = smith_kzalloc(256, GFP_ATOMIC);
        ei[2].item = smith_d_path(&(file->f_path), stdin_buf, 256);
        if (ei[2].item)
            ei[2].size = strlen(ei[2].item);
        smith_fput(file);
    }

    /* query stdout */
    file = smith_fget_raw(1);
    if (file) {
        stdout_buf = smith_kzalloc(256, GFP_ATOMIC);
        ei[3].item = smith_d_path(&(file->f_path), stdout_buf, 256);
        if (ei[3].item)
            ei[3].size = strlen(ei[3].item);
        smith_fput(file);
    }

    /* query exe_path */
    if (!file_path || file_path[0] != '/') {
        buffer = smith_kzalloc(PATH_MAX, GFP_KERNEL);
        if (!buffer)
            goto hash_check;
        if (bprm->file)
            file_path = smith_d_path(&bprm->file->f_path,
                                      buffer, PATH_MAX);
        if (!file_path || file_path[0] != '/') {
            file_path = smith_get_pwd_path(buffer, PATH_MAX);
            if (file_path[0] == '/' && bprm->filename) {
                int i = strlen(file_path);
                while (i > 0 && file_path[i - 1] == '/')
                    i--;
                if (i + strlen(bprm->filename) < PATH_MAX)
                    strcpy(&file_path[i], bprm->filename);
            }
        }
    }
    ei[0].item = file_path;
    if (ei[0].item)
        ei[0].size = strlen(ei[0].item);

    /* query cmdline with arguments */
    args = smith_query_args(bprm);
    ei[1].item = args;
    if (ei[1].item)
        ei[1].size = strlen(ei[1].item);

    /* checking exe/cmd rules */
    if (g_flt_ops.rule_check(ei, 4, id)) {
        exe_block_notify(id, file_path, args);
        rc = -EACCES;
        goto errorout;
    }

hash_check:

    /* there are no hash rules, so skip md5 checking */
    if (!g_flt_ops.hash_check(NULL))
        goto errorout;

    /*
     * MD5 hash rules matching
     */

    if (!bprm->file)
        goto errorout;

    /* check whether img is already cached */
    if (!img)
        img = smith_find_file_img(bprm->file);
    if (img && img->si_node.flag_usr1) {
        memcpy(&md5, &img->si_md5, sizeof(md5));
    } else {
        if (smith_get_hash_file(bprm->file, &md5))
            goto errorout;
        if (img && img->si_size == md5.size) {
            memcpy(&img->si_md5, &md5, sizeof(md5));
            img->si_node.flag_usr1 = 1;
        }
    }

    /* compute md5 of specified file */
    if (md5.hlen == 16) {
        /* checking md5 rules */
        if (g_flt_ops.hash_check(&md5)) {
            md5_block_notify(&md5, file_path, args);
            rc = -EACCES;
            goto errorout;
        }
    }

errorout:
    if (buffer)
        smith_kfree(buffer);
    if (args)
        smith_kfree(args);
    if (stdin_buf)
        smith_kfree(stdin_buf);
    if (stdout_buf)
        smith_kfree(stdout_buf);
    if (img)
        smith_put_img(img);
    return rc;
}

static struct linux_binfmt g_smith_exec_load = {
    /* search_binary_handler will try grab module if .module is set */
    .module      = THIS_MODULE,
    .load_binary = smith_exec_load,
};
static atomic_t g_binfmt_regged = ATOMIC_INIT(0);

int smith_register_exec_load(void)
{
    int rc = atomic_cmpxchg(&g_binfmt_regged, 0, 1);

    if (rc == 0)
        __register_binfmt(&g_smith_exec_load, 1);

    return (rc <= 0 ? rc : -EALREADY);
}

int smith_unregister_exec_load(void)
{
    int rc = atomic_cmpxchg(&g_binfmt_regged, 1, 0);

    if (rc)
        unregister_binfmt(&g_smith_exec_load);

    return (rc ? 0 : -EALREADY);
}

static int __init kprobe_hook_init(void)
{
    int ret;

#if defined(MODULE)
    printk(KERN_INFO "[ELKEID] kmod %s (%s) loaded.\n",
           THIS_MODULE->name, THIS_MODULE->version);
#else
    printk(KERN_INFO "[ELKEID] intree (" SMITH_VERSION ") loaded.\n");
#endif

    ret = kernel_symbols_init();
    if (ret)
        return ret;

    smith_init_systemd_ns();

    /*  prepare delayed-put thread for async put_files_struct */
    ret = smith_start_delayed_put();
    if (ret)
        return ret;

    /* need ROOT_MNT_NS inited by smith_init_systemd_ns */
    ret = smith_tid_init();
    if (ret) {
        smith_stop_delayed_put();
        return ret;
    }

    printk(KERN_INFO "[ELKEID] Filter Init Success \n");

#if (EXIT_PROTECT == 1) && defined(MODULE)
    exit_protect_action();
#endif

    /* install kprobe & kretprobe hookpoints */
    install_kprobe();

    /* register binfmt callback for image checking */
    smith_register_exec_load();

    printk(KERN_INFO "[ELKEID] SANDBOX: %d\n", SANDBOX);
    printk(KERN_INFO
    "[ELKEID] register_kprobe success: connect_hook: %d, load_module_hook:"
    " %d, execve_hook: %d, call_usermodehelper_exec_hook: %d, bind_hook: %d, create_file_hook: %d, ptrace_hook: %d, update_cred_hook:"
    " %d, dns_hook: %d, accept_hook:%d, mprotect_hook: %d, chmod_hook: %d, mount_hook: %d, link_hook: %d, memfd_create: %d, rename_hook: %d,"
    "setsid_hook:%d, prctl_hook:%d, open_hook:%d, udev_notifier:%d, nanosleep_hook:%d, kill_hook: %d, rm_hook: %d, "
    " exit_hook: %d, write_hook: %d, EXIT_PROTECT: %d\n",
            CONNECT_HOOK, MODULE_LOAD_HOOK, EXECVE_HOOK, USERMODEHELPER_HOOK, BIND_HOOK,
            CREATE_FILE_HOOK, PTRACE_HOOK, UPDATE_CRED_HOOK, DNS_HOOK, ACCEPT_HOOK, MPROTECT_HOOK,
            CHMOD_HOOK, MOUNT_HOOK, LINK_HOOK, MEMFD_CREATE_HOOK, RENAME_HOOK, SETSID_HOOK,
            PRCTL_HOOK, OPEN_HOOK, UDEV_HOOK, NANOSLEEP_HOOK, KILL_HOOK, RM_HOOK, EXIT_HOOK, WRITE_HOOK,
            EXIT_PROTECT);

    return 0;
}

static void kprobe_hook_exit(void)
{
    /* unregister binfmt callback first */
    smith_unregister_exec_load();

    /* clean nf_hooks of psad if hooked */
    mutex_lock(&g_nf_psad_lock);
    if (g_nf_psad_status)
        unregister_pernet_subsys(&smith_psad_net_ops);
    mutex_unlock(&g_nf_psad_lock);

    /* cleaning up kprobe hook points */
    uninstall_kprobe();

    /* cleaning up tid & img cache */
    smith_tid_fini();
    smith_stop_delayed_put();

    printk(KERN_INFO "[ELKEID] uninstall_kprobe success\n");
}

KPROBE_INITCALL(kprobe_hook, kprobe_hook_init, kprobe_hook_exit);

// SPDX-License-Identifier: GPL-2.0
/*
 * smith_hook.c
 *
 * Hook some kernel function
 */
#include "../include/smith_hook.h"
#include "../include/trace.h"

#define CREATE_PRINT_EVENT
#include "../include/kprobe_print.h"

#include <linux/kthread.h>
#include <linux/moduleparam.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>

#if IS_ENABLED(CONFIG_IPV6)
#include <linux/ipv6.h>
#include <net/ipv6.h> /* ipv6_addr_any */
#include <linux/netfilter_ipv6.h>
#endif

#define EXIT_PROTECT 0
#define SANDBOX 0
#define SMITH_MAX_ARG_STRINGS (16)

/*
 * Hookpoint switch defintions
 */

#define SMITH_HOOK(name, on)                    \
    static int name##_HOOK = (on);              \
    module_param(name##_HOOK, int, 0400)

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
SMITH_HOOK(USERMODEHELPER, 1);
SMITH_HOOK(UDEV, 1);
SMITH_HOOK(CHMOD, 1);
SMITH_HOOK(NANOSLEEP, 0);

SMITH_HOOK(WRITE, SANDBOX);
SMITH_HOOK(ACCEPT, SANDBOX);
SMITH_HOOK(OPEN, SANDBOX);
SMITH_HOOK(MPROTECT, SANDBOX);
SMITH_HOOK(KILL, SANDBOX);
SMITH_HOOK(RM, SANDBOX);
SMITH_HOOK(EXIT, SANDBOX);

/*
 *
 * raw tracepoint brings severe performance penalty for syscall-intensive ops.
 * so disabled by default, and enabled only for SANDBOX or kernels >= 5.5.0
 * 5.4.210 was used before, but ubuntu 20.04 focal defines kernel version as
 * 5.4.255 for 5.4.0-xxx versions, which brings disorders
 */
SMITH_HOOK(RAWTP, SANDBOX || (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 5, 0)));
SMITH_HOOK(DNS, SANDBOX || (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 5, 0)));

static int FAKE_RM = SANDBOX;

#if SANDBOX
static int PID_TREE_LIMIT = 100;
static int PID_TREE_LIMIT_LOW = 100;
static int EXECVE_GET_SOCK_PID_LIMIT = 100;
static int EXECVE_GET_SOCK_FD_LIMIT = 100;
#else
static int PID_TREE_LIMIT = 12;
static int PID_TREE_LIMIT_LOW = 8;
static int EXECVE_GET_SOCK_PID_LIMIT = 4;
static int EXECVE_GET_SOCK_FD_LIMIT = 12;  /* maximum fd numbers to be queried */
#endif

static char connect_syscall_kprobe_state = 0x0;
static char execve_kretprobe_state = 0x0;
static char bind_kprobe_state = 0x0;
static char create_file_kprobe_state = 0x0;
static char ptrace_kprobe_state = 0x0;
static char do_init_module_kprobe_state = 0x0;
static char update_cred_kprobe_state = 0x0;
static char ip4_datagram_connect_kprobe_state = 0x0;
static char ip6_datagram_connect_kprobe_state = 0x0;
static char tcp_v4_connect_kprobe_state = 0x0;
static char tcp_v6_connect_kprobe_state = 0x0;
static char mprotect_kprobe_state = 0x0;
static char mount_kprobe_state = 0x0;
static char rename_kprobe_state = 0x0;
static char link_kprobe_state = 0x0;
static char setsid_kprobe_state = 0x0;
static char prctl_kprobe_state = 0x0;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 17, 0)
static char memfd_create_kprobe_state = 0x0;
#endif
static char accept_kretprobe_state = 0x0;
static char accept4_kretprobe_state = 0x0;
static char open_kprobe_state = 0x0;
static char openat_kprobe_state = 0x0;
static char nanosleep_kprobe_state = 0x0;
static char kill_kprobe_state = 0x0;
static char tkill_kprobe_state = 0x0;
static char exit_kprobe_state = 0x0;
static char exit_group_kprobe_state = 0x0;
static char security_path_rmdir_kprobe_state = 0x0;
static char security_path_unlink_kprobe_state = 0x0;
static char call_usermodehelper_exec_kprobe_state = 0x0;
static char write_kprobe_state = 0x0;

#ifdef CONFIG_COMPAT
static char compat_execve_kretprobe_state = 0x0;
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 19, 0)
static char execveat_kretprobe_state = 0x0;
#ifdef CONFIG_COMPAT
static char compat_execveat_kretprobe_state = 0x0;
#endif
#endif

#if EXIT_PROTECT == 1
void exit_protect_action(void)
{
	__module_get(THIS_MODULE);
}
#endif

static struct task_struct *smith_get_task_struct(struct task_struct *tsk)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 1, 0)
    if (tsk && refcount_inc_not_zero(&tsk->usage))
#else
    if (tsk && atomic_inc_not_zero((atomic_t *)&tsk->usage))
#endif
        return tsk;
    return NULL;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 39)
static void (*__smith_put_task_struct)(struct task_struct *t);
static void smith_put_task_struct(struct task_struct *t)
{
	if (atomic_dec_and_test(&t->usage))
		__smith_put_task_struct(t);
}
#else
#define smith_put_task_struct(tsk)  put_task_struct(tsk)
#endif

unsigned int ROOT_PID_NS_INUM;

static inline void __init_root_pid_ns_inum(void) {
    struct pid *pid_struct;
    struct task_struct *task;

    pid_struct = find_get_pid(1);
    task = pid_task(pid_struct,PIDTYPE_PID);

    smith_get_task_struct(task);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 19, 0)
    ROOT_PID_NS_INUM = task->nsproxy->pid_ns_for_children->ns.inum;
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3, 11, 0)
    ROOT_PID_NS_INUM = task->nsproxy->pid_ns_for_children->proc_inum;
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3, 8, 0)
    ROOT_PID_NS_INUM = task->nsproxy->pid_ns->proc_inum;
#else
    /*
     * For kernels < 3.8.0, id for pid namespaces isn't defined.
     * So here we are using fixed values, no emulating any more,
     * previously we were using image file's inode number.
     */
    ROOT_PID_NS_INUM = 0xEFFFFFFCU /* PROC_PID_INIT_INO */;
#endif
    smith_put_task_struct(task);
    put_pid(pid_struct);
}

/*
 * delayed put_files_struct
 */

static void (*put_files_struct_sym) (struct files_struct * files);

struct delayed_put_node {
    struct delayed_put_node *next;
    union {
        struct file *filp;
        struct files_struct *files;
    };
    uint32_t flag_pool:1;
    uint32_t type:8;  /* 0: file, 1: files */
};

static struct memcache_head g_delayed_put_root;
static atomic_t g_delayed_put_active; /* active nodes */

static struct delayed_put_node *smith_alloc_delayed_put_node(void)
{
    struct delayed_put_node *dnod;

    dnod = memcache_pop(&g_delayed_put_root);
    if (dnod) {
        dnod->flag_pool = 1;
    } else {
        dnod = smith_kzalloc(sizeof(struct delayed_put_node), GFP_ATOMIC);
    }

    return dnod;
}

static void smith_free_delayed_put_node(struct delayed_put_node *dnod)
{
    if (!dnod)
        return;

    if (dnod->flag_pool)
        memcache_push(dnod, &g_delayed_put_root);
    else
        smith_kfree(dnod);
}

static struct task_struct *g_delayed_put_thread;
static struct delayed_put_node *g_delayed_put_queue;
static spinlock_t g_delayed_put_lock;

static struct delayed_put_node *smith_deref_head_node(void)
{
    struct delayed_put_node *dnod;
    unsigned long flags;

    /* retrive head node from delayed put queue */
    spin_lock_irqsave(&g_delayed_put_lock, flags);
    dnod = g_delayed_put_queue;
    if (dnod)
        g_delayed_put_queue = dnod->next;
    spin_unlock_irqrestore(&g_delayed_put_lock, flags);

    /* do actual put_files_struct or fput */
    if (dnod) {
        if (1 == dnod->type)
            put_files_struct_sym(dnod->files);
        else if (0 == dnod->type)
            fput(dnod->filp);
        smith_free_delayed_put_node(dnod);
        atomic_dec(&g_delayed_put_active);
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
        printk("smith_start_delayed_put: failed creating delayed_fput worker: %d\n", rc);
        return rc;
    }

    /* initialize memory cache for dnod, errors to be ignored,
       if fails, new node will be allocated from system slab */
    memcache_init(&g_delayed_put_root, nobjs * num_possible_cpus(),
                  sizeof(struct delayed_put_node), 0, NULL, NULL, NULL);

    /* wake up delayed-put worker thread */
    wake_up_process(g_delayed_put_thread);
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

    memcache_fini(&g_delayed_put_root);
}

static void smith_insert_delayed_put_node(struct delayed_put_node *dnod)
{
    unsigned long flags;

    if (!dnod)
        return;

    atomic_inc(&g_delayed_put_active);
    /* attach dnod to deayed_fput_queue */
    spin_lock_irqsave(&g_delayed_put_lock, flags);
    dnod->next = g_delayed_put_queue;
    g_delayed_put_queue = dnod;
    spin_unlock_irqrestore(&g_delayed_put_lock, flags);
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

    /* just deref the reference of file structure */
    if (atomic_long_add_unless(&filp->f_count, -1, 1))
        return;

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

    /* just deref the reference of files_table */
    if (atomic_add_unless(&files->count, -1, 1))
        return;

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

/* only inc f_count when it's not 0 to avoid races upon exe_file */
#ifdef SMITH_FS_FILE_REF
#define smith_get_file(x) (file_ref_read(&(x)->f_ref) && \
                    atomic_long_inc_not_zero(&(x)->f_ref.refcnt))
#else
#define smith_get_file(x) atomic_long_inc_not_zero(&(x)->f_count)
#endif

#ifdef SMITH_HAVE_FCHECK_FILES
#define smith_lookup_fd          fcheck_files /* < 5.10.220 */
#else
#define smith_lookup_fd          files_lookup_fd_raw /* >= 5.10.220 */
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
		if (!smith_get_file(file))
			file = NULL;
	}
	rcu_read_unlock();

	/* it's safe to call put_files_struct for current */
	put_files_struct_sym(files);
	return file;
}


static char *smith_d_path(const struct path *path, char *buf, int buflen)
{
    char *name = DEFAULT_RET_STR;
    if (buf) {
        name = d_path(path, buf, buflen);
        if (IS_ERR(name))
            name = NAME_TOO_LONG;
    }
    return name;
}

/*
 * query task's executable image file, with mmap lock avoided, just because
 * mmput() could lead resched() (since it's calling might_sleep() interally)
 *
 * there could be races on mm->exe_file, but we could assure we can always
 * get a valid filp or NULL
 */
static struct file *smith_get_current_exe_file(void)
{
    struct file *exe = NULL;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 1, 0) && LINUX_VERSION_CODE < KERNEL_VERSION(5, 15, 0)
    /*
     * 1) performance improvement for kernels >=4.1: use get_mm_exe_file instead
     *    get_mm_exe_file internally uses rcu lock (with semaphore locks killed)
     * 2) it's safe to directly access current->mm under current's own context
     * 3) get_mm_exe_file() is no longer exported after kernel 5.15
     */
    exe = get_mm_exe_file(current->mm);
#else
    /*
     * get_task_mm/mmput must be avoided here
     *
     * mmput would put current task to sleep, which violates kprobe. or
     * use mmput_async instead, but it's only available for after 4.7.0
     * (and CONFIG_MMU is enabled)
     */
    task_lock(current);
    if (current->mm && current->mm->exe_file) {
        exe = current->mm->exe_file;
        if (!smith_get_file(exe))
            exe = NULL;
    }
    task_unlock(current);
#endif

    return exe;
}

// get full path of current task's executable image
static char *smith_get_exe_file(char *buffer, int size)
{
    char *exe_file_str = DEFAULT_RET_STR;
    struct file *exe;

    if (!buffer || !current->mm)
        return exe_file_str;

    exe = smith_get_current_exe_file();
    if (exe) {
        exe_file_str = smith_d_path(&exe->f_path, buffer, size);
        fput(exe);
    }

    return exe_file_str;
}

static char *smith_query_exe_path(char **alloc, int len, int min)
{
    char *buffer = NULL;

    while (len >= min) {
        buffer = smith_kzalloc(len, GFP_ATOMIC);
        if (buffer)
            break;
        len = len / 2;
    }
    *alloc = buffer;
    return smith_get_exe_file(buffer, len);
}

/*
 * wrapper for ktime_get_real_seconds
 */

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

static const struct cred *(*get_task_cred_sym) (struct task_struct *);

static ssize_t (*smith_strscpy)(char *dest, const char *src, size_t count);

static int __init kernel_symbols_init(void)
{
    void *ptr;

    /* sized_strscpy introduced from v6.9 to replace strscpy */
    ptr = (void *)smith_kallsyms_lookup_name("strscpy");
    if (!ptr)
        ptr = (void *)smith_kallsyms_lookup_name("sized_strscpy");
    if (!ptr)
        ptr = (void *)smith_kallsyms_lookup_name("strlcpy");
    if (!ptr)
        return -ENODEV;
    smith_strscpy = ptr;

    ptr = (void *)smith_kallsyms_lookup_name("put_files_struct");
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

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 11, 0)
    ptr = (void *)smith_kallsyms_lookup_name("ktime_get_real_seconds");
    if (ptr)
        smith_ktime_get_real_seconds = ptr;
    smith_init_get_seconds();
#endif

    return 0;
}

static void to_print_privilege_escalation(const struct cred *current_cred, unsigned int p_cred_info[], char * pid_tree, int p_pid)
{
    char p_cred[128];
    char c_cred[128];

    snprintf(p_cred, sizeof(p_cred), "%u|%u|%u|%u|%u|%u|%u|%u", p_cred_info[0], p_cred_info[1], p_cred_info[2], p_cred_info[3],
             p_cred_info[4], p_cred_info[5], p_cred_info[6], p_cred_info[7]);

    snprintf(c_cred, sizeof(c_cred), "%u|%u|%u|%u|%u|%u|%u|%u",
            _XID_VALUE(current_cred->uid), _XID_VALUE(current_cred->euid), _XID_VALUE(current_cred->suid),
            _XID_VALUE(current_cred->fsuid), _XID_VALUE(current_cred->gid), _XID_VALUE(current_cred->egid),
            _XID_VALUE(current_cred->sgid), _XID_VALUE(current_cred->fsgid));

    privilege_escalation_print(p_pid, pid_tree, p_cred, c_cred);
}

static char *smith_get_pid_tree(int limit)
{
    int real_data_len = PID_TREE_MATEDATA_LEN;
    int limit_index = 0;
    int cred_detected_task_pid = 0;
    int cred_check_res = 0;
    unsigned int p_cred_info[8];

    char *tmp_data = NULL;
    char pid[24];

    struct task_struct *task;
    struct task_struct *old_task;
    const struct cred *current_cred = NULL;
    const struct cred *parent_cred = NULL;

    task = current;
    get_task_struct(task);

    snprintf(pid, 24, "%d", task->tgid);
    tmp_data = smith_kzalloc(1024, GFP_ATOMIC);

    if (!tmp_data) {
        smith_put_task_struct(task);
        return tmp_data;
    }

    strcat(tmp_data, pid);
    strcat(tmp_data, ".");
    strcat(tmp_data, current->comm);

    current_cred = get_task_cred_sym(current);

    while (1) {
        limit_index = limit_index + 1;

        if (limit_index >= limit)
            break;

        old_task = task;
        rcu_read_lock();
        task = smith_get_task_struct(rcu_dereference(task->real_parent));
        rcu_read_unlock();
        smith_put_task_struct(old_task);
        if (!task || task->pid == 0) {
            break;
        }

        //cred privilege_escalation check only check twice
        if (!cred_check_res && limit_index <= 2) {
            cred_detected_task_pid = task->tgid;
            parent_cred = get_task_cred_sym(task);
            cred_check_res = check_cred(current_cred, parent_cred);
            save_cred_info(p_cred_info, parent_cred);
            put_cred(parent_cred);
        }

        real_data_len = real_data_len + PID_TREE_MATEDATA_LEN;
        if (real_data_len > 1024)
            break;

        snprintf(pid, 24, "%d", task->tgid);
        strcat(tmp_data, "<");
        strcat(tmp_data, pid);
        strcat(tmp_data, ".");
        strcat(tmp_data, task->comm);
    }

    if (task)
        smith_put_task_struct(task);

    if (cred_check_res)
        to_print_privilege_escalation(current_cred, p_cred_info, tmp_data, cred_detected_task_pid);

    put_cred(current_cred);
    return tmp_data;
}

//get task tree first AF_INET/AF_INET6 socket info
static void
get_process_socket(__be32 * sip4, struct in6_addr *sip6, int *sport,
                   __be32 * dip4, struct in6_addr *dip6, int *dport,
                   pid_t * socket_pid, int *sa_family)
{
    struct task_struct *task = current;
    int it = 0;

    get_task_struct(task);
    while (task && task->pid != 1 && it++ < EXECVE_GET_SOCK_PID_LIMIT) {
        struct task_struct *old_task;
        struct files_struct *files;
        int i, socket_check = 0;

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
                    struct inet_sock *inet = (struct inet_sock *)sk;
                    switch (sk->sk_family) {
                        case AF_INET:
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 33)
                            *dip4 = inet->inet_daddr;
						    *sip4 = inet->inet_saddr;
						    *sport = ntohs(inet->inet_sport);
						    *dport = ntohs(inet->inet_dport);
#else
                            *dip4 = inet->daddr;
                            *dip4 = inet->saddr;
                            *sport = ntohs(inet->sport);
                            *dport = ntohs(inet->dport);
#endif
                            socket_check = 1;
                            *sa_family = sk->sk_family;
                            break;
#if IS_ENABLED(CONFIG_IPV6)
                            case AF_INET6:
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 13, 0) || defined(IPV6_SUPPORT)
						    memcpy(dip6, &(sk->sk_v6_daddr), sizeof(sk->sk_v6_daddr));
						    memcpy(sip6, &(sk->sk_v6_rcv_saddr), sizeof(sk->sk_v6_rcv_saddr));
						    *sport = ntohs(inet->inet_sport);
						    *dport = ntohs(inet->inet_dport);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 33)
						    memcpy(dip6, &(inet->pinet6->daddr), sizeof(inet->pinet6->daddr));
						    memcpy(sip6, &(inet->pinet6->saddr), sizeof(inet->pinet6->saddr));
						    *sport = ntohs(inet->inet_sport);
						    *dport = ntohs(inet->inet_dport);
#else
						    memcpy(dip6, &(inet->pinet6->daddr), sizeof(inet->pinet6->daddr));
						    memcpy(sip6, &(inet->pinet6->saddr), sizeof(inet->pinet6->saddr));
						    *sport = ntohs(inet->sport);
						    *dport = ntohs(inet->dport);
#endif
						    socket_check = 1;
						    *sa_family = sk->sk_family;
						    break;
#endif
                    }
                }
                sockfd_put(socket);
            }
        }
        if (task == current)
            put_files_struct_sym(files);
        else
            smith_put_files_struct(files);

        if (socket_check) {
            *socket_pid = task->pid;
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

struct connect_data {
    struct sock *sk;
    int sa_family;
    int type;
};

struct connect_syscall_data {
    int fd;
    struct sockaddr *dirp;
};

struct accept_data {
    int type;
    union {
        struct sockaddr    sa;
        struct sockaddr_in si4;
        struct sockaddr_in6 si6;
        struct __kernel_sockaddr_storage kss; /* to avoid overflow access of kernel_getsockname */
    };
};

struct bind_data {
    int fd;
    union {
        struct sockaddr dirp;
        struct sockaddr_in sin;
#if IS_ENABLED(CONFIG_IPV6)
        struct sockaddr_in6 sin6;
#endif
    };
};

struct execve_data {
    char *argv;
    char *ssh_connection;
    char *ld_preload;

    int len_argv;
    int free_argv;
    int free_ssh_connection;
    int free_ld_preload;
};

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

/*
 * Workaround for kretprobe BUG (fixed in 3.2.6):
 *
 * kretprobe instance memory leaking if entry_handler returns failure codes.
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 2, 6)

static int bind_entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct bind_data *data = (struct bind_data *)ri->data;
    struct sockaddr_storage address;
    struct sockaddr *uaddr;
    int ulen = p_get_arg3_syscall(regs);

    if (ulen <= 0 || ulen > sizeof(struct sockaddr_storage))
        return -EINVAL;

    if (smith_copy_from_user(&address, (void __user *)p_get_arg2_syscall(regs), ulen))
        return -EFAULT;

    uaddr = (struct sockaddr *)&address;
    if (uaddr->sa_family == AF_INET && ulen >= sizeof(data->sin))
        memcpy(&data->sin, (void *)&address, sizeof(data->sin));
#if IS_ENABLED(CONFIG_IPV6)
    else if (uaddr->sa_family == AF_INET6 && ulen >= sizeof(data->sin6))
		memcpy(&data->sin6, (void *)&address, sizeof(data->sin6));
#endif
    else
        return -EINVAL;

    return 0;
}

#else

static int bind_entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct bind_data *data = (struct bind_data *)ri->data;
    struct sockaddr_storage address;
    struct sockaddr *uaddr;
    int ulen = p_get_arg3_syscall(regs);

    /* clear bind_data to avoid unnecessary process in bind_handler */
    memset(data, 0, sizeof(*data));

    if (ulen <= 0 || ulen > sizeof(struct sockaddr_storage))
        return 0;

    if (smith_copy_from_user(&address, (void __user *)p_get_arg2_syscall(regs), ulen))
        return 0;

    uaddr = (struct sockaddr *)&address;
    if (uaddr->sa_family == AF_INET && ulen >= sizeof(data->sin))
        memcpy(&data->sin, (void *)&address, sizeof(data->sin));
#if IS_ENABLED(CONFIG_IPV6)
    else if (uaddr->sa_family == AF_INET6 && ulen >= sizeof(data->sin6))
		memcpy(&data->sin6, (void *)&address, sizeof(data->sin6));
#endif

    return 0;
}

#endif

static int bind_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    int retval, sa_family, sport;

    char *exe_path = DEFAULT_RET_STR;
    char *buffer = NULL;

    struct sockaddr *uaddr;
    struct sockaddr_in *sin;
    struct sockaddr_in6 *sin6;
    struct in_addr *in_addr = NULL;
    struct in6_addr *in6_addr = NULL;

    uaddr = &((struct bind_data *)ri->data)->dirp;
    retval = regs_return_value(regs);
    /*
     * If the return value is not zero, the data passed by the user
     * is untrusted. Access to untrusted data may be problematic.
     */
    if (retval)
        return 0;

    sa_family = uaddr->sa_family;
    //only get AF_INET/AF_INET6 bind info
    switch (sa_family) {
        case AF_INET:
            sin = &((struct bind_data *)ri->data)->sin;
            in_addr = &sin->sin_addr;
            sport = ntohs(sin->sin_port);
            break;
#if IS_ENABLED(CONFIG_IPV6)
        case AF_INET6:
		    sin6 = &((struct bind_data *)ri->data)->sin6;
		    in6_addr = &sin6->sin6_addr;
		    sport = ntohs(sin6->sin6_port);
		    break;
#endif
        default:
            return 0;
    }

    buffer = smith_kzalloc(PATH_MAX, GFP_ATOMIC);
    exe_path = smith_get_exe_file(buffer, PATH_MAX);
    if (!execve_exe_check(exe_path, strlen(exe_path))) {
        if (sa_family == AF_INET)
            bind_print(exe_path, in_addr, sport, retval);
#if IS_ENABLED(CONFIG_IPV6)
        else if (sa_family == AF_INET6)
            bind6_print(exe_path, in6_addr, sport, retval);
#endif
    }

    if (buffer)
        smith_kfree(buffer);

    return 0;
}

static int connect_syscall_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    int err, fd;
    int dport = 0, sport = 0, retval, sa_family;

    __be32 dip4 = 0;
    __be32 sip4 = 0;

    char *exe_path = DEFAULT_RET_STR;
    char *buffer = NULL;

    struct socket *socket;
    struct sock *sk;
    struct sockaddr tmp_dirp;
    struct connect_syscall_data *data;
    struct inet_sock *inet;
    struct in6_addr *dip6 = NULL;
    struct in6_addr *sip6 = NULL;

    retval = regs_return_value(regs);

    data = (struct connect_syscall_data *)ri->data;
    fd = data->fd;

    if (!fd || IS_ERR_OR_NULL(data->dirp))
        return 0;

    if (smith_copy_from_user(&tmp_dirp, data->dirp, 16))
        return 0;

    socket = sockfd_lookup(fd, &err);
    if (IS_ERR_OR_NULL(socket))
        return 0;

    switch (tmp_dirp.sa_family) {
        case AF_INET:
                sk = socket->sk;
                inet = (struct inet_sock *)sk;
#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 32)
				//dip4 = ((struct sockaddr_in *)&tmp_dirp)->sin_addr.s_addr;
                dip4 = inet->inet_daddr;
			    sip4 = inet->inet_saddr;
			    sport = ntohs(inet->inet_sport);
			    dport = ntohs(((struct sockaddr_in *)&tmp_dirp)->sin_port);
			    if (dport == 0)
			        dport = ntohs(inet->inet_dport);
#else
                //dip4 = ((struct sockaddr_in *)&tmp_dirp)->sin_addr.s_addr;
                dip4 = inet->daddr;
                sip4 = inet->saddr;
                sport = ntohs(inet->sport);
                dport = ntohs(((struct sockaddr_in *)&tmp_dirp)->sin_port);
                if (dport == 0)
                    dport = ntohs(inet->dport);
#endif
                sa_family = AF_INET;
                break;
#if IS_ENABLED(CONFIG_IPV6)
        case AF_INET6:
			    sk = socket->sk;
			    inet = (struct inet_sock *)sk;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 13, 0) || defined(IPV6_SUPPORT)
				//dip6 = &((struct sockaddr_in6 *)&tmp_dirp)->sin6_addr;
				dip6 = &(sk->sk_v6_daddr);
				sip6 = &(sk->sk_v6_rcv_saddr);
				sport = ntohs(inet->inet_sport);
				dport = ntohs(((struct sockaddr_in *)&tmp_dirp)->sin_port);
				if (dport == 0)
				    dport = ntohs(inet->inet_dport);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 33)
				//dip6 = &((struct sockaddr_in6 *)&tmp_dirp)->sin6_addr;
				dip6 = &(inet->pinet6->daddr);
				sip6 = &(inet->pinet6->saddr);
				sport = ntohs(inet->inet_sport);
				dport = ntohs(((struct sockaddr_in *)&tmp_dirp)->sin_port);
				if (dport)
				    dport = ntohs(inet->inet_dport);
#else
				//dip6 = &((struct sockaddr_in6 *)&tmp_dirp)->sin6_addr;
				dip6 = &(inet->pinet6->daddr);
				sip6 = &(inet->pinet6->saddr);
				sport = ntohs(inet->sport);
				dport = ntohs(((struct sockaddr_in *)&tmp_dirp)->sin_port);
				if (dport)
				    dport = ntohs(inet->dport);
#endif
			    sa_family = AF_INET6;
			    break;
#endif
        default:
                break;
    }

    if (dport != 0) {
        buffer = smith_kzalloc(PATH_MAX, GFP_ATOMIC);
        exe_path = smith_get_exe_file(buffer, PATH_MAX);
        if (!execve_exe_check(exe_path, strlen(exe_path))) {
            if (sa_family == AF_INET)
                connect4_print(dport, dip4, exe_path, sip4, sport, retval);
#if IS_ENABLED(CONFIG_IPV6)
            else if (dip6 && sip6)
                connect6_print(dport, dip6, exe_path, sip6, sport, retval);
#endif
        }

        if (buffer)
            smith_kfree(buffer);
    }

    /* refed by sip6 & dip6 for ipv6 */
    sockfd_put(socket);

    return 0;
}

static int connect_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    int retval, dport = 0, sport = 0;

    __be32 dip4 = 0, sip4 = 0;

    char *exe_path = DEFAULT_RET_STR;
    char *buffer = NULL;

    struct sock *sk;
    struct connect_data *data;
    struct inet_sock *inet;
    struct in6_addr *dip6 = NULL, *sip6 = NULL;

    retval = regs_return_value(regs);
    data = (struct connect_data *)ri->data;

    sk = data->sk;
    if (IS_ERR_OR_NULL(sk))
        return 0;

    buffer = smith_kzalloc(PATH_MAX, GFP_ATOMIC);
    exe_path = smith_get_exe_file(buffer, PATH_MAX);

    //exe filter check
    if (execve_exe_check(exe_path, strlen(exe_path))) {
        if (buffer)
            smith_kfree(buffer);
        return 0;
    }
    //only get AF_INET/AF_INET6 connect info
    inet = (struct inet_sock *)sk;
    switch (data->sa_family) {
        case AF_INET:
#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 32)
			dip4 = inet->inet_daddr;
			sip4 = inet->inet_saddr;
			sport = ntohs(inet->inet_sport);
			dport = ntohs(inet->inet_dport);
#else
            dip4 = inet->daddr;
            sip4 = inet->saddr;
            sport = ntohs(inet->sport);
            dport = ntohs(inet->dport);
#endif
            break;
#if IS_ENABLED(CONFIG_IPV6)
        case AF_INET6:
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 13, 0) || defined(IPV6_SUPPORT)
			dip6 = &(sk->sk_v6_daddr);
			sip6 = &(sk->sk_v6_rcv_saddr);
			sport = ntohs(inet->inet_sport);
			dport = ntohs(inet->inet_dport);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 33)
			dip6 = &(inet->pinet6->daddr);
			sip6 = &(inet->pinet6->saddr);
			sport = ntohs(inet->inet_sport);
			dport = ntohs(inet->inet_dport);
#else
			dip6 = &(inet->pinet6->daddr);
			sip6 = &(inet->pinet6->saddr);
			sport = ntohs(inet->sport);
			dport = ntohs(inet->dport);
#endif
		    break;
#endif
        default:
            break;
    }

    if (dport != 0) {
        if (data->sa_family == AF_INET)
            //connect4_print(data->type, dport, dip4, exe_path, sip4,
            //               sport, retval);
            connect4_print(dport, dip4, exe_path, sip4, sport, retval);
#if IS_ENABLED(CONFIG_IPV6)
        else
			//connect6_print(data->type, dport, dip6, exe_path, sip6,
			//	       sport, retval);
			connect6_print(dport, dip6, exe_path, sip6, sport, retval);
#endif
    }

    if (buffer)
        smith_kfree(buffer);

    return 0;
}

/*
 * Workaround for kretprobe BUG (fixed in 3.2.6):
 *
 * kretprobe instance memory leaking if entry_handler returns failure codes.
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 2, 6)

static int accept_entry_handler(struct kretprobe_instance *ri,
                                struct pt_regs *regs)
{
    struct accept_data *data;
    struct sockaddr *dirp;

    data = (struct accept_data *)ri->data;
    data->type = 2;

    dirp = (void __user *)p_get_arg2_syscall(regs);
    if(IS_ERR_OR_NULL(dirp))
        return -EINVAL;
    return 0;
}

static int accept4_entry_handler(struct kretprobe_instance *ri,
                                 struct pt_regs *regs)
{
    struct accept_data *data;
    struct sockaddr *dirp;

    data = (struct accept_data *)ri->data;
    data->type = 1;

    dirp = (void __user *)p_get_arg2_syscall(regs);
    if(IS_ERR_OR_NULL(dirp))
        return -EINVAL;
    return 0;
}

#else

static int accept_entry_handler(struct kretprobe_instance *ri,
                                struct pt_regs *regs)
{
    struct accept_data *data;

    data = (struct accept_data *)ri->data;
    data->type = 2;

    return 0;
}

static int accept4_entry_handler(struct kretprobe_instance *ri,
                                 struct pt_regs *regs)
{
    struct accept_data *data;

    data = (struct accept_data *)ri->data;
    data->type = 1;

    return 0;
}
#endif

static int accept_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct accept_data *data;
    struct socket *sock = NULL;

    int sport, dport;
    int retval, err = 0;

    char *exe_path = DEFAULT_RET_STR;
    char *buffer = NULL;

    data = (struct accept_data *)ri->data;
    retval = regs_return_value(regs);
    sock = sockfd_lookup(retval, &err);
    if (IS_ERR_OR_NULL(sock))
        goto out;

    buffer = smith_kzalloc(PATH_MAX, GFP_ATOMIC);
    exe_path = smith_get_exe_file(buffer, PATH_MAX);

    //only get AF_INET/AF_INET6 accept info
    if (sock->sk->sk_family == AF_INET) {
        __be32 sip4, dip4;

        if (smith_get_sock_v4(sock, &data->sa) < 0)
            goto out;
        dip4 = data->si4.sin_addr.s_addr;
        dport = ntohs(data->si4.sin_port);

        if (smith_get_peer_v4(sock, &data->sa) < 0)
            goto out;
        sip4 = data->si4.sin_addr.s_addr;
        sport = ntohs(data->si4.sin_port);
        accept_print(dport, dip4, exe_path, sip4, sport, retval);
        // printk("accept4_handler: %d.%d.%d.%d/%d -> %d.%d.%d.%d/%d rc=%d\n",
        //         NIPQUAD(sip4), sport, NIPQUAD(dip4), dport, retval);
    }
#if IS_ENABLED(CONFIG_IPV6)
    else if (sock->sk->sk_family == AF_INET6) {
        struct in6_addr *sip6, dip6;

        if (smith_get_sock_v6(sock, &data->sa) < 0)
            goto out;
        dip6 = data->si6.sin6_addr;
        dport = ntohs(data->si6.sin6_port);

        if (smith_get_peer_v6(sock, &data->sa) < 0)
            goto out;
        sport = ntohs(data->si6.sin6_port);
        sip6 = &(data->si6.sin6_addr);
        accept6_print(dport, &dip6, exe_path, sip6, sport, retval);
        // printk("accept6_handler: %04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x/%d"
        //        " -> %04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x/%d rc=%d\n",
        //         NIP6(*sip6), sport, NIP6(dip6), dport, retval);
    }
#endif

out:
    if (!IS_ERR_OR_NULL(sock))
        sockfd_put(sock);
    if (buffer)
        smith_kfree(buffer);
    return 0;
}

static int execve_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    int sa_family = -1, dport = 0, sport = 0;
    int rc = regs_return_value(regs);

    __be32 dip4;
    __be32 sip4;
    pid_t socket_pid = -1;

    char *pname = DEFAULT_RET_STR;
    char *tmp_stdin = DEFAULT_RET_STR;
    char *tmp_stdout = DEFAULT_RET_STR;
    char *buffer = NULL;
    char *pname_buf = NULL;
    char *pid_tree = NULL;
    char *tty_name = "-1";
    char *exe_path = DEFAULT_RET_STR;
    char *stdin_buf = NULL;
    char *stdout_buf = NULL;

    struct in6_addr dip6;
    struct in6_addr sip6;
    struct file *file;
    struct execve_data *data;
    struct tty_struct *tty = NULL;

     /* query kretprobe instance for current call */
    data = (struct execve_data *)ri->data;

    /* ignore the failures that target doesn't exist */
    if (rc == -ENOENT)
        goto release_data;

    tty = get_current_tty();
    if(tty && strlen(tty->name) > 0)
        tty_name = tty->name;

    //exe filter check and argv filter check
    exe_path = smith_query_exe_path(&buffer, PATH_MAX, 128);
    if (execve_exe_check(exe_path, strlen(exe_path)))
        goto out;
    if (execve_argv_check(data->argv, data->len_argv))
        goto out;

    get_process_socket(&sip4, &sip6, &sport, &dip4, &dip6, &dport,
                       &socket_pid, &sa_family);

    //if socket exist,get pid tree
    if (sa_family == AF_INET6 || sa_family == AF_INET)
        pid_tree = smith_get_pid_tree(PID_TREE_LIMIT);
    else
        pid_tree = smith_get_pid_tree(PID_TREE_LIMIT_LOW);

    // get stdin
    file = smith_fget_raw(0);
    if (file) {
        stdin_buf = smith_kzalloc(256, GFP_ATOMIC);
        tmp_stdin = smith_d_path(&(file->f_path), stdin_buf, 256);
        smith_fput(file);
    }

    //get stdout
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
                     data->ssh_connection, data->ld_preload,
                     rc);
    }
#if IS_ENABLED(CONFIG_IPV6)
    else if (sa_family == AF_INET6) {
		execve6_print(pname,
			      exe_path, data->argv,
			      tmp_stdin, tmp_stdout,
			      &dip6, dport, &sip6, sport,
			      pid_tree, tty_name, socket_pid,
			      data->ssh_connection, data->ld_preload,
			      rc);
	}
#endif
    else {
        execve_nosocket_print(pname,
                              exe_path, data->argv,
                              tmp_stdin, tmp_stdout,
                              pid_tree, tty_name,
                              data->ssh_connection, data->ld_preload,
                              rc);
    }

out:
    if (pname_buf)
        smith_kfree(pname_buf);
    if (stdin_buf)
        smith_kfree(stdin_buf);
    if (stdout_buf)
        smith_kfree(stdout_buf);
    if (pid_tree)
        smith_kfree(pid_tree);
    if (buffer)
        smith_kfree(buffer);
    if(tty)
        tty_kref_put(tty);

release_data:
    if (data->free_argv)
        smith_kfree(data->argv);
    if (data->free_ld_preload)
        smith_kfree(data->ld_preload);
    if (data->free_ssh_connection)
        smith_kfree(data->ssh_connection);

    return 0;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 0, 0)

struct user_arg_ptr {
#ifdef CONFIG_COMPAT
	bool is_compat;
#endif
	union {
		const char __user *const __user *native;
#ifdef CONFIG_COMPAT
		const compat_uptr_t __user *compat;
#endif
	} ptr;
};

static const char __user *get_user_arg_ptr(struct user_arg_ptr argv, int nr)
{
	const char __user *native;

#ifdef CONFIG_COMPAT
	if (argv.is_compat) {
		compat_uptr_t compat;

		if (smith_get_user(compat, argv.ptr.compat + nr))
		    return ERR_PTR(-EFAULT);

		return compat_ptr(compat);
	}
#endif

	if (smith_get_user(native, argv.ptr.native + nr))
	    return ERR_PTR(-EFAULT);

	return native;
}

//count execve argv num
static int execve_count_args(struct user_arg_ptr argv, int max)
{
	int i = 0;
	if (argv.ptr.native != NULL) {
		for (;;) {
			const char __user *p = get_user_arg_ptr(argv, i);
			if (!p)
				break;
			if (IS_ERR(p))
				return -EFAULT;
			if (++i >= max)
				break;
			if (fatal_signal_pending(current))
				return -ERESTARTNOHAND;
		}
	}
	return i;
}

//get execve syscall argv/LD_PRELOAD && SSH_CONNECTION env info
static void get_execve_data(struct user_arg_ptr argv_ptr,
                            struct user_arg_ptr env_ptr,
		                    struct execve_data *data)
{
	int argv_len = 0, argv_res_len = 0, i = 0, len = 0, offset = 0;
	int env_len = 0, free_argv = 0, res = 0;
	int ssh_connection_flag = 0, ld_preload_flag = 0;
	int free_ld_preload = 1, free_ssh_connection = 1;

	char *argv_res = NULL;
	char *ssh_connection = NULL;
	char *ld_preload = NULL;
	const char __user *native;

	env_len = execve_count_args(env_ptr, MAX_ARG_STRINGS);
	argv_len = execve_count_args(argv_ptr, SMITH_MAX_ARG_STRINGS);
	argv_res_len = 256 * argv_len;

	if (argv_len > 0) {
		argv_res = smith_kmalloc(argv_res_len + 1, GFP_ATOMIC);
		if (!argv_res) {
			argv_res = "-1";
		} else {
			free_argv = 1;
			for (i = 0; i < argv_len; i++) {
				native = get_user_arg_ptr(argv_ptr, i);
				if (IS_ERR(native))
					continue;

				len = smith_strnlen_user(native, MAX_ARG_STRLEN);
				if (len <= 0)
					continue;

				if (offset + len > argv_res_len) {
				    res = argv_res_len - offset;
				    offset += res - smith_copy_from_user(argv_res + offset, native, res);
				    break;
				}

				res = smith_copy_from_user(argv_res + offset, native, len);
				offset += len - res;
				if (res)
					continue;
				*(argv_res + offset - 1) = ' ';
			}
			if (offset > 0)
				*(argv_res + offset) = '\0';
			else
				smith_strcpy(argv_res, "<FAIL>");
			smith_strim(argv_res);
		}
	}

	ssh_connection = smith_kmalloc(255, GFP_ATOMIC);
	ld_preload = smith_kmalloc(255, GFP_ATOMIC);

	if (!ssh_connection)
		free_ssh_connection = 0;

	if (!ld_preload)
		free_ld_preload = 0;

	//get SSH_CONNECTION and LD_PRELOAD env info
	if (env_len > 0) {
		char buf[256];
		for (i = 0; i < env_len; i++) {
			if (ld_preload_flag == 1 && ssh_connection_flag == 1)
				break;

			native = get_user_arg_ptr(env_ptr, i);
			if (IS_ERR(native))
				continue;

			len = smith_strnlen_user(native, MAX_ARG_STRLEN);
			if (len > 14 && len < 256) {
				memset(buf, 0, 256);
				if (smith_copy_from_user(buf, native, len))
					break;
				else {
					if (strncmp("SSH_CONNECTION=", buf, 11) == 0) {
					    ssh_connection_flag = 1;
						if (free_ssh_connection == 1) {
							smith_strcpy(ssh_connection, buf + 15);
						} else {
							ssh_connection = "-1";
						}
					} else if (strncmp("LD_PRELOAD=", buf, 11) == 0) {
					    ld_preload_flag = 1;
						if (free_ld_preload == 1) {
							smith_strcpy(ld_preload, buf + 11);
						} else {
							ld_preload = "-1";
						}
					}
				}
			}
		}
	}

	if (ssh_connection_flag == 0) {
		if (free_ssh_connection == 0)
			ssh_connection = "-1";
		else
			smith_strcpy(ssh_connection, "-1");
	}
	data->ssh_connection = ssh_connection;
	data->free_ssh_connection = free_ssh_connection;

	if (ld_preload_flag == 0) {
		if (free_ld_preload == 0)
			ld_preload = "-1";
		else
			smith_strcpy(ld_preload, "-1");
	}
	data->ld_preload = ld_preload;
	data->free_ld_preload = free_ld_preload;

	data->argv = argv_res;
	data->len_argv = argv_res ? strlen(argv_res) : 0;
	data->free_argv = free_argv;
}

#ifdef CONFIG_COMPAT
static int compat_execve_entry_handler(
                  struct kretprobe_instance *ri,
			      struct pt_regs *regs)
{
	struct user_arg_ptr argv_ptr;
	struct user_arg_ptr env_ptr;
	struct execve_data *data;
	data = (struct execve_data *)ri->data;

    memset(&argv_ptr, 0, sizeof(argv_ptr));
    memset(&env_ptr, 0, sizeof(env_ptr));

	argv_ptr.is_compat = true;
	argv_ptr.ptr.compat = (const compat_uptr_t __user *)p_get_arg2_syscall(regs);

	env_ptr.is_compat = true;
	env_ptr.ptr.compat = (const compat_uptr_t __user *)p_get_arg3_syscall(regs);

	get_execve_data(argv_ptr, env_ptr, data);
	return 0;
}
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 19, 0)
#ifdef CONFIG_COMPAT
static int compat_execveat_entry_handler(
                struct kretprobe_instance *ri,
				struct pt_regs *regs)
{
	struct user_arg_ptr argv_ptr;
	struct user_arg_ptr env_ptr;
	struct execve_data *data;
	data = (struct execve_data *)ri->data;

    memset(&argv_ptr, 0, sizeof(argv_ptr));
    memset(&env_ptr, 0, sizeof(env_ptr));

	argv_ptr.is_compat = true;
	argv_ptr.ptr.compat = (const compat_uptr_t __user *)p_get_arg3_syscall(regs);

	env_ptr.is_compat = true;
	env_ptr.ptr.compat = (const compat_uptr_t __user *)p_get_arg4_syscall(regs);

	get_execve_data(argv_ptr, env_ptr, data);
	return 0;
}
#endif

static int execveat_entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct user_arg_ptr argv_ptr;
	struct user_arg_ptr env_ptr;
	struct execve_data *data;
	data = (struct execve_data *)ri->data;

    memset(&argv_ptr, 0, sizeof(argv_ptr));
    memset(&env_ptr, 0, sizeof(env_ptr));

	argv_ptr.ptr.native = (const char *const *)p_get_arg3_syscall(regs);
	env_ptr.ptr.native = (const char *const *)p_get_arg4_syscall(regs);

	get_execve_data(argv_ptr, env_ptr, data);
	return 0;
}
#endif

static int execve_entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct user_arg_ptr argv_ptr;
	struct user_arg_ptr env_ptr;
	struct execve_data *data;
	data = (struct execve_data *)ri->data;

    memset(&argv_ptr, 0, sizeof(argv_ptr));
    memset(&env_ptr, 0, sizeof(env_ptr));

	argv_ptr.ptr.native = (const char *const *)p_get_arg2_syscall(regs);
	env_ptr.ptr.native = (const char *const *)p_get_arg3_syscall(regs);

	get_execve_data(argv_ptr, env_ptr, data);
	return 0;
}

#else

//count execve argv num
static int execve_count(char __user * __user * argv, int max)
{
    int i = 0;

    if (argv != NULL) {
        for (;;) {
            char __user *p;
            if (smith_get_user(p, argv))
                return -EFAULT;
            if (!p)
                break;
            argv++;
            if (++i >= max)
                break;
            if (fatal_signal_pending(current))
                return -ERESTARTNOHAND;
        }
    }
    return i;
}

//get execve syscall argv/LD_PRELOAD && SSH_CONNECTION env info
static void get_execve_data(char **argv, char **env, struct execve_data *data)
{
    int argv_len = 0, argv_res_len = 0, i = 0, len = 0, offset = 0, res = 0;
    int env_len = 0, free_argv = 0, ssh_connection_flag = 0, ld_preload_flag = 0;
    int free_ssh_connection = 1, free_ld_preload = 1;

    char *argv_res = NULL;
    char *ssh_connection = NULL;
    char *ld_preload = NULL;
    const char __user * native;

    env_len = execve_count(env, MAX_ARG_STRINGS);
    argv_len = execve_count(argv, SMITH_MAX_ARG_STRINGS);
    argv_res_len = 256 * argv_len;

    //get execve args data
    if (argv_len > 0) {
        argv_res = smith_kmalloc(argv_res_len + 1, GFP_ATOMIC);
        if (!argv_res) {
            argv_res = "-1";
        } else {
            free_argv = 1;
            for (i = 0; i < argv_len; i++) {
                if (smith_get_user(native, argv + i))
                    continue;

                len = smith_strnlen_user(native, MAX_ARG_STRLEN);
                if (len <= 0)
                    continue;

                if (offset + len > argv_res_len) {
                    res = argv_res_len - offset;
                    offset += res - smith_copy_from_user(argv_res + offset, native, res);
                    break;
                }

                res = smith_copy_from_user(argv_res + offset, native, len);
                offset += len - res;
                if (res)
                    continue;
                *(argv_res + offset - 1) = ' ';
            }
            if (offset > 0)
                *(argv_res + offset) = '\0';
            else
                smith_strcpy(argv_res, "<FAIL>");
            smith_strim(argv_res);
        }
    }

    ssh_connection = smith_kmalloc(255, GFP_ATOMIC);
    ld_preload = smith_kmalloc(255, GFP_ATOMIC);

    if (!ssh_connection)
        free_ssh_connection = 0;

    if (!ld_preload)
        free_ld_preload = 0;

    //get SSH_CONNECTION and LD_PRELOAD env info
    if (env_len > 0) {
        char buf[256];
        for (i = 0; i < argv_len; i++) {
            if (ld_preload_flag == 1 && ssh_connection_flag == 1)
                break;

            if (smith_get_user(native, env + i))
                break;

            len = smith_strnlen_user(native, MAX_ARG_STRLEN);
            if (len <= 0 || len > MAX_ARG_STRLEN)
                break;

            if (len > 14 && len < 256) {
                memset(buf, 0, 256);
                if (smith_copy_from_user(buf, native, len))
                    break;
                else {
                    if (strncmp("SSH_CONNECTION=", buf, 11) == 0) {
                        ssh_connection_flag = 1;
                        if (free_ssh_connection == 1) {
                            smith_strcpy(ssh_connection, buf + 15);
                        } else {
                            ssh_connection = "-1";
                        }
                    } else if (strncmp("LD_PRELOAD=", buf, 11) == 0) {
                        ld_preload_flag = 1;
                        if (free_ld_preload == 1) {
                            smith_strcpy(ld_preload, buf + 11);
                        } else {
                            ld_preload = "-1";
                        }
                    }
                }
            }
        }
    }

    if (ssh_connection_flag == 0) {
        if (free_ssh_connection == 0)
            ssh_connection = "-1";
        else
            smith_strcpy(ssh_connection, "-1");
    }
    data->ssh_connection = ssh_connection;
    data->free_ssh_connection = free_ssh_connection;

    if (ld_preload_flag == 0) {
        if (free_ld_preload == 0)
            ld_preload = "-1";
        else
            smith_strcpy(ld_preload, "-1");
    }
    data->ld_preload = ld_preload;
    data->free_ld_preload = free_ld_preload;

    data->argv = argv_res;
    data->len_argv = argv_res ? strlen(argv_res) : 0;
    data->free_argv = free_argv;
}

static int compat_execve_entry_handler(
                              struct kretprobe_instance *ri,
                              struct pt_regs *regs)
{
    struct execve_data *data;
    char **argv = (char **)p_get_arg2_syscall(regs);
    char **env = (char **)p_get_arg3_syscall(regs);

    data = (struct execve_data *)ri->data;
    get_execve_data(argv, env, data);
    return 0;
}

static int execve_entry_handler(struct kretprobe_instance *ri,
                                struct pt_regs *regs)
{
    struct execve_data *data;
    char **argv = (char **)p_get_arg2_syscall(regs);
    char **env = (char **)p_get_arg3_syscall(regs);
    data = (struct execve_data *)ri->data;
    get_execve_data(argv, env, data);
    return 0;
}

#endif

//get create file info
static int security_inode_create_pre_handler(struct kprobe *p, struct pt_regs *regs)
{
    int sa_family = -1;
    int dport = 0, sport = 0;

    __be32 dip4;
    __be32 sip4;
    pid_t socket_pid = -1;

    char *pname_buf = NULL;
    char *buffer = NULL;
    char *pathstr = DEFAULT_RET_STR;
    char *exe_path = DEFAULT_RET_STR;
    char *s_id = DEFAULT_RET_STR;

    struct dentry * file = NULL;
    struct in6_addr dip6;
    struct in6_addr sip6;

    buffer = smith_kzalloc(PATH_MAX, GFP_ATOMIC);
    exe_path = smith_get_exe_file(buffer, PATH_MAX);

    //exe filter check
    if (execve_exe_check(exe_path, strlen(exe_path)))
        goto out;

    pname_buf = smith_kzalloc(PATH_MAX, GFP_ATOMIC);
    if (pname_buf) {
        file = (struct dentry *)p_regs_get_arg2(regs);
        if (IS_ERR_OR_NULL(file)) {
            smith_kfree(pname_buf);
            goto out;
        }
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 38)
        pathstr = dentry_path_raw(file, pname_buf, PATH_MAX);
#else
        pathstr = smith_dentry_path(file, pname_buf, PATH_MAX);
#endif

        if(!IS_ERR_OR_NULL(file->d_sb))
            s_id = file->d_sb->s_id;

        if(IS_ERR(pathstr))
            pathstr = NAME_TOO_LONG;
    }

    get_process_socket(&sip4, &sip6, &sport, &dip4, &dip6, &dport,
                       &socket_pid, &sa_family);

    if (sa_family == AF_INET) {
        security_inode4_create_print(exe_path, pathstr,
                                    dip4, dport, sip4, sport,
                                    socket_pid, s_id);
    }
#if IS_ENABLED(CONFIG_IPV6)
    else if (sa_family == AF_INET6) {
		security_inode6_create_print(exe_path, pathstr, &dip6,
                                     dport, &sip6, sport,
			                         socket_pid, s_id);
	}
#endif
    else {
        security_inode_create_nosocket_print(exe_path, pathstr, s_id);
    }

    if (pname_buf)
        smith_kfree(pname_buf);

out:
    if (buffer)
        smith_kfree(buffer);

    return 0;
}

static int ptrace_pre_handler(struct kprobe *p, struct pt_regs *regs)
{
    long request;
    request = (long)p_get_arg1_syscall(regs);

    //only get PTRACE_POKETEXT/PTRACE_POKEDATA ptrace
    //Read a word at the address addr in the tracee's memory,
    //returning the word as the result of the ptrace() call.  Linux
    //does not have separate text and data address spaces, so these
    //two requests are currently equivalent.  (data is ignored; but
    //see NOTES.)

    if (request == PTRACE_POKETEXT || request == PTRACE_POKEDATA) {
        long pid;
        void *addr;
        char *exe_path = DEFAULT_RET_STR;
        char *buffer = NULL;
        char *pid_tree = NULL;

        pid = (long)p_get_arg2_syscall(regs);
        addr = (void *)p_get_arg3_syscall(regs);

        if (IS_ERR_OR_NULL(addr))
            return 0;

        buffer = smith_kzalloc(PATH_MAX, GFP_ATOMIC);
        exe_path = smith_get_exe_file(buffer, PATH_MAX);

        pid_tree = smith_get_pid_tree(PID_TREE_LIMIT);
        ptrace_print(request, pid, addr, "-1", exe_path, pid_tree);

        if(buffer)
            smith_kfree(buffer);

        if(pid_tree)
            smith_kfree(pid_tree);
    }

    return 0;
}
/*
 * ip address manipulation routines
 */

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
    char *exe_path = DEFAULT_RET_STR;
    char *buffer = NULL;

    buffer = smith_kzalloc(PATH_MAX, GFP_ATOMIC);
    exe_path = smith_get_exe_file(buffer, PATH_MAX);

    //exe filter check
    if (execve_exe_check(exe_path, strlen(exe_path)))
        goto out;

    dns_print(dport, dip, exe_path, sip, sport, opcode, rcode, query);

out:
    if (buffer)
        smith_kfree(buffer);
}

#if IS_ENABLED(CONFIG_IPV6)
static void dns6_data_transport(char *query, struct in6_addr *dip,
                                struct in6_addr *sip, int dport, int sport,
                                int opcode, int rcode, int type)
{
	char *exe_path = DEFAULT_RET_STR;
	char *buffer = NULL;

	buffer = smith_kzalloc(PATH_MAX, GFP_ATOMIC);
	exe_path = smith_get_exe_file(buffer, PATH_MAX);

	//exe filter check
	if (execve_exe_check(exe_path, strlen(exe_path)))
		goto out;

	dns6_print(dport, dip, exe_path, sip, sport, opcode, rcode, query);

out:
	if (buffer)
		smith_kfree(buffer);
}
#endif

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

/*
 * dns threshold control for high udp traffic
 */

#define SMITH_DNS_THRESHOLD    (10)     /* threshold: 2^10 = 1024 ops/s */
#define SMITH_DNS_INTERVALS    (60)     /* 60 seconds */

static struct smith_dns_threshold {
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
        addr.dport != 53 && addr.dport != 5353)
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
        addr.dport != 53 && addr.dport != 5353)
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

#include <linux/tracepoint.h>
#include <linux/thread_info.h>
#include <asm/syscall.h> /* syscall_get_nr() */
#include <asm/unistd.h> /* __NR_syscall defintions */

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 35))
    #define TRACEPOINT_PROBE_REGISTER(p1, p2) tracepoint_probe_register(p1, p2)
    #define TRACEPOINT_PROBE_UNREGISTER(p1, p2) tracepoint_probe_unregister(p1, p2)
    #define TRACEPOINT_PROBE(probe, args...) static void probe(args)
#else
    #define TRACEPOINT_PROBE_REGISTER(p1, p2) tracepoint_probe_register(p1, p2, NULL)
    #define TRACEPOINT_PROBE_UNREGISTER(p1, p2) tracepoint_probe_unregister(p1, p2, NULL)
    #define TRACEPOINT_PROBE(probe, args...) static void probe(void *__data, args)
#endif

#if IS_ENABLED(CONFIG_X86) || IS_ENABLED(CONFIG_IA32_EMULATION)

/* only for x86 systems */
static void smith_trace_sysexit_x86(struct pt_regs *regs, long id, long ret)
{
    switch (id) {

        /*
         * socket related
         */

        case 102 /* __NR_ia32_socketcall */:
            if (CONNECT_HOOK && SYS_CONNECT == regs->bx) {
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
            } else if (ACCEPT_HOOK && (SYS_ACCEPT == regs->bx ||
                                       SYS_ACCEPT4 == regs->bx)) {
            }
            break;

        case 371 /* __NR_ia32_recvfrom */:
            if (DNS_HOOK && ret >= 20)
                smith_trace_sysret_recvdat(regs->bx, regs->cx, ret);
            break;
        case 372 /* __NR_ia32_recvmsg */:
            if (DNS_HOOK && ret >= 20)
                smith_trace_sysret_recvmsg(regs->bx, regs->cx, ret);
            break;
    }
}

#elif defined(CONFIG_ARM64) && defined(CONFIG_COMPAT)

/* only for ARM64 system */
static void smith_trace_sysexit_arm32(struct pt_regs *regs, long id, long ret)
{
    switch (id) {

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
    }
}
#endif

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
         * socket related
         */

#ifdef       __NR_socketcall
        case __NR_socketcall:
            if (CONNECT_HOOK && SYS_CONNECT == p_regs_get_arg1_of_syscall(regs)) {
            } else if (DNS_HOOK && SYS_RECV == p_regs_get_arg1_of_syscall(regs)) {
            } else if (DNS_HOOK && SYS_RECVFROM == p_regs_get_arg1_of_syscall(regs)) {
            } else if (DNS_HOOK && SYS_RECVMSG == p_regs_get_arg1_of_syscall(regs)) {
            } else if (DNS_HOOK && SYS_RECVMMSG == p_regs_get_arg1_of_syscall(regs)) {
            } else if (BIND_HOOK && SYS_BIND == p_regs_get_arg1_of_syscall(regs)) {
            } else if (ACCEPT_HOOK && (SYS_ACCEPT == p_regs_get_arg1_of_syscall(regs) ||
                                       SYS_ACCEPT4 == p_regs_get_arg1_syscall(regs))) {
            }
            break;
#endif

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

static struct smith_tracepoint {
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
    {.name = "sys_exit", .handler = smith_trace_sys_exit}
};
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

static int __init smith_sysret_init(void)
{
    int i, rc;

    /* skip raw tracepoint registration */
    if (!RAWTP_HOOK)
        return 0;

    /* check the tracepoints of our interest */
    rc = smith_assert_tracepoints();
    if (rc) {
        printk(KERN_INFO "[ELKEID] failed to register tracepoints: %d\n", rc);
        goto errorout;
    }

    /* check dns parameters */
    smith_check_dns_params();

    /* register callbacks for the tracepoints of our interest */
    for (i = 0; i < NUM_TRACE_POINTS; i++) {
        rc = smith_register_tracepoint(&g_smith_tracepoints[i]);
        if (rc)
            goto cleanup;
    }

errorout:
    return rc;

cleanup:
    while (--i >= 0)
        smith_unregister_tracepoint(&g_smith_tracepoints[i]);
    return rc;
}

static void smith_sysret_fini(void)
{
    int i;

    /* skip raw tracepoint unregistration */
    if (!RAWTP_HOOK)
        return;

    /* register callbacks for the tracepoints of our interest */
    for (i = NUM_TRACE_POINTS; i > 0; i--)
        smith_unregister_tracepoint(&g_smith_tracepoints[i - 1]);
}

/*
 * netfilter nf_hooks for port-scan attack detection
 */
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/tcp.h>

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
    int flags = TCP_FLAG_SYN;

    if (iph->protocol != IPPROTO_TCP)
        goto out;
    len = ntohs(iph->tot_len);
    if (len > skb->len || sizeof(*iph) + sizeof(*tcp) > skb->len)
        goto out;
    tcp = (struct tcphdr *)(iph + 1) /* tcp_hdr(skb) */;
    if (!tcp->syn)
        goto out;

    flags |= (tcp->fin ? TCP_FLAG_FIN : 0) |
             (tcp->rst ? TCP_FLAG_RST : 0) |
             (tcp->urg ? TCP_FLAG_URG : 0) |
             (tcp->ack ? TCP_FLAG_ACK : 0) |
             (tcp->psh ? TCP_FLAG_PSH : 0);
    psad4_print(iph->saddr, tcp->source, iph->daddr, tcp->dest, flags);

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
    int flags = TCP_FLAG_SYN;

    if (iph->version != 6)
        goto out;
    if (iph->nexthdr != 6 /* NEXTHDR_TCP */)
        goto out;
    len = ntohs(iph->payload_len);
    if (len + sizeof(*iph) > skb->len || sizeof(*iph) + sizeof(*tcp) > skb->len)
        goto out;
    tcp = (struct tcphdr *)(iph + 1) /* tcp_hdr(skb) */;
    if (!tcp->syn)
        goto out;

    flags |= (tcp->fin ? TCP_FLAG_FIN : 0) |
             (tcp->rst ? TCP_FLAG_RST : 0) |
             (tcp->urg ? TCP_FLAG_URG : 0) |
             (tcp->ack ? TCP_FLAG_ACK : 0) |
             (tcp->psh ? TCP_FLAG_PSH : 0);
    psad6_print(&iph->saddr, tcp->source, &iph->daddr, tcp->dest, flags);

out:
    return NF_ACCEPT;
}
#endif

static struct nf_hook_ops g_smith_nf_psad[] = {
        {
                .hook =           smith_nf_psad_v4_handler,
                .pf =             NFPROTO_IPV4,
                .hooknum =        NF_INET_PRE_ROUTING,
                .priority =       NF_IP_PRI_FIRST,
        },
#if IS_ENABLED(CONFIG_IPV6)
        {
                .hook =           smith_nf_psad_v6_handler,
                .pf =             NFPROTO_IPV6,
                .hooknum =        NF_INET_PRE_ROUTING,
                .priority =       NF_IP_PRI_FIRST,
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

static atomic_t g_nf_psad_regged = ATOMIC_INIT(0);

static int smith_nf_psad_reg(struct net *net)
{
    int rc = 0;

    /*
     * only do register for the 1st time. We need control the callings of
     * nf_register_hooks if we keep register_pernet_subsys for kernels < 4.3
     */
    if (1 == atomic_inc_return(&g_nf_psad_regged))
        rc = nf_register_hooks(g_smith_nf_psad, ARRAY_SIZE(g_smith_nf_psad));

    return rc;
}

static void smith_nf_psad_unreg(struct net *net)
{
    /* do cleanup for the last instance of net namespace */
    if (0 == atomic_dec_return(&g_nf_psad_regged))
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
static int smith_set_nf_psad_switch(const char *val, const struct kernel_param *kp)
{
    int rc = param_set_bool(val, kp);
    if (!rc)
        smith_switch_psad();
    return rc;
}
const struct kernel_param_ops smith_nf_psad_ops = {
    .set = smith_set_nf_psad_switch,
    .get = param_get_bool,
};
module_param_cb(psad_switch, &smith_nf_psad_ops, &g_nf_psad_switch, S_IRUGO|S_IWUSR);
#elif defined(module_param_call)
static int smith_set_nf_psad_switch(const char *val, struct kernel_param *kp)
{
    int rc = param_set_bool(val, kp);
    if (!rc)
        smith_switch_psad();
    return rc;
}
module_param_call(psad_switch, smith_set_nf_psad_switch, param_get_bool, &g_nf_psad_switch, S_IRUGO|S_IWUSR);
#else
# warning "moudle_param_cb or module_param_call are not supported by target kernel"
#endif
MODULE_PARM_DESC(psad_switch, "Set to 1 to enable detection of port-scanning, 0 otherwise");

static int mprotect_pre_handler(struct kprobe *p, struct pt_regs *regs)
{
    int target_pid = -1;
    unsigned long prot;

    char *file_path = "-1";
    char *file_buf = NULL;
    char *vm_file_path = "-1";
    char *vm_file_buff = NULL;
    char *exe_path = "-1";
    char *abs_buf = NULL;
    char *pid_tree = NULL;

    struct vm_area_struct *vma;

    //only get PROT_EXEC mprotect info
    //The memory can be used to store instructions which can then be executed. On most architectures,
    //this flag implies that the memory can be read (as if PROT_READ had been specified).
    prot = (unsigned long)p_regs_get_arg2(regs);
    if (prot & PROT_EXEC) {
        abs_buf = smith_kzalloc(PATH_MAX, GFP_ATOMIC);
        exe_path = smith_get_exe_file(abs_buf, PATH_MAX);

        vma = (struct vm_area_struct *)p_regs_get_arg1(regs);
        if (IS_ERR_OR_NULL(vma)) {
            mprotect_print(exe_path, prot, "-1", -1, "-1", "-1");
        } else {
            rcu_read_lock();
            if (!IS_ERR_OR_NULL(vma->vm_mm)) {
                if (!IS_ERR_OR_NULL(&vma->vm_mm->exe_file)) {
                    if (smith_get_file(vma->vm_mm->exe_file)) {
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
                if (smith_get_file(vma->vm_file)) {
                    vm_file_buff = smith_kzalloc(PATH_MAX, GFP_ATOMIC);
                    vm_file_path = smith_d_path(&vma->vm_file->f_path, vm_file_buff, PATH_MAX);
                    smith_fput(vma->vm_file);
                }
            }
            rcu_read_unlock();

            pid_tree = smith_get_pid_tree(PID_TREE_LIMIT);
            mprotect_print(exe_path, prot, file_path, target_pid, vm_file_path, pid_tree);
        }

        if (pid_tree)
            smith_kfree(pid_tree);

        if (file_buf)
            smith_kfree(file_buf);

        if (abs_buf)
            smith_kfree(abs_buf);

        if (vm_file_buff)
            smith_kfree(vm_file_buff);
    }
    return 0;
}

static int call_usermodehelper_exec_pre_handler(struct kprobe *p, struct pt_regs *regs)
{
    int wait = 0, argv_res_len = 0, argv_len = 0;
    int offset = 0, free_argv = 0, i;
    void *si_tmp;
    const char *path;
    char **argv;
    char *argv_res = NULL;
    struct subprocess_info *si;

    si_tmp = (void *)p_regs_get_arg1(regs);
    if (IS_ERR_OR_NULL(si_tmp))
        return 0;

    si = (struct subprocess_info *)si_tmp;
    wait = (int)p_regs_get_arg2(regs);

    path = si->path;
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
                int res = argv_res_len - offset, ret;
                ret = smith_strscpy(argv_res + offset, argv[i], res);
                if (ret < 0)
                    offset += res;
                else
                    offset += ret + 1;
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

static void rename_and_link_handler(int type, char * oldori, char * newori, char * s_id)
{
    char *buffer = NULL;
    char *exe_path = DEFAULT_RET_STR;

    buffer = smith_kzalloc(PATH_MAX, GFP_ATOMIC);
    exe_path = smith_get_exe_file(buffer, PATH_MAX);
    if (execve_exe_check(exe_path, strlen(exe_path)))
        goto out_free;

    if (type)
        rename_print(exe_path, oldori, newori, s_id);
    else
        link_print(exe_path, oldori, newori, s_id);

out_free:
    if (buffer)
        smith_kfree(buffer);
}

static int rename_pre_handler(struct kprobe *p, struct pt_regs *regs)
{
    char *old_path_str = DEFAULT_RET_STR;
    char *new_path_str = DEFAULT_RET_STR;
    char *s_id = DEFAULT_RET_STR;

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
        old_path_str = smith_dentry_path(old_dentry, old_buf, PATH_MAX);
#endif
    }

    if(new_buf) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 38)
        new_path_str = dentry_path_raw(new_dentry, new_buf, PATH_MAX);
#else
        new_path_str = smith_dentry_path(new_dentry, new_buf, PATH_MAX);
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

static int link_pre_handler(struct kprobe *p, struct pt_regs *regs)
{
    char *old_path_str = DEFAULT_RET_STR;
    char *new_path_str = DEFAULT_RET_STR;
    char *s_id = DEFAULT_RET_STR;

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
        old_path_str = smith_dentry_path(old_dentry, old_buf, PATH_MAX);
#endif
    }

    if(new_buf) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 38)
        new_path_str = dentry_path_raw(new_dentry, new_buf, PATH_MAX);
#else
        new_path_str = smith_dentry_path(new_dentry, new_buf, PATH_MAX);
#endif
    }

    if (IS_ERR(old_path_str))
        old_path_str = DEFAULT_RET_STR;

    if (IS_ERR(new_path_str))
        new_path_str = DEFAULT_RET_STR;

    if(!IS_ERR_OR_NULL(old_dentry->d_sb))
        s_id = old_dentry->d_sb->s_id;

    rename_and_link_handler(0, old_path_str, new_path_str, s_id);

    if(old_buf)
        smith_kfree(old_buf);

    if(new_buf)
        smith_kfree(new_buf);

    return 0;
}

static int setsid_pre_handler(struct kprobe *p, struct pt_regs *regs)
{
    char *exe_path = DEFAULT_RET_STR;
    char *buffer = NULL;

    buffer = smith_kzalloc(PATH_MAX, GFP_ATOMIC);
    exe_path = smith_get_exe_file(buffer, PATH_MAX);
    if (execve_exe_check(exe_path, strlen(exe_path)))
        goto out;

    setsid_print(exe_path);

out:
    if (buffer)
        smith_kfree(buffer);

    return 0;
}

static int prctl_pre_handler(struct kprobe *p, struct pt_regs *regs)
{
    char *exe_path = DEFAULT_RET_STR;
    char *buffer = NULL;
    int newname_len = 0;
    char __user *newname_ori;
    char *newname = NULL;


    //only get PS_SET_NAME data
    //PR_SET_NAME (since Linux 2.6.9)
    //Set the name of the calling thread, using the value in the lo‐
    //cation pointed to by (char *) arg2.  The name can be up to 16
    //bytes long, including the terminating null byte.  (If the
    //length of the string, including the terminating null byte, ex‐
    //ceeds 16 bytes, the string is silently truncated.)
    if (PR_SET_NAME != (int)p_get_arg1_syscall(regs))
        return 0;

    newname_ori = (void *)p_get_arg2_syscall(regs);
    if (IS_ERR_OR_NULL(newname_ori))
        return 0;

    newname_len = smith_strnlen_user((char __user *)newname_ori, PATH_MAX);
    if (newname_len <= 0 || newname_len > PATH_MAX)
        return 0;

    newname = smith_kmalloc(newname_len + 1, GFP_ATOMIC);
    if(!newname)
        return 0;

    if(smith_copy_from_user(newname, (char __user *)newname_ori, newname_len)) {
        smith_kfree(newname);
        return 0;
    }
    newname[newname_len] = '\0';

    if (strcmp(newname, current->comm) == 0) {
        smith_kfree(newname);
        return 0;
    }

    buffer = smith_kzalloc(PATH_MAX, GFP_ATOMIC);
    exe_path = smith_get_exe_file(buffer, PATH_MAX);
    if (execve_exe_check(exe_path, strlen(exe_path)))
        goto out;

    prctl_print(exe_path, PR_SET_NAME, newname);

out:
    if (buffer)
        smith_kfree(buffer);

    smith_kfree(newname);

    return 0;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 17, 0)
static int memfd_create_kprobe_pre_handler(struct kprobe *p, struct pt_regs *regs)
{
    int len;
    unsigned long flags;

    char *fdname = NULL;
    char __user *fdname_ori;
    char *exe_path = DEFAULT_RET_STR;
    char *exe_buffer = NULL;

    exe_buffer = smith_kzalloc(PATH_MAX, GFP_ATOMIC);
    exe_path = smith_get_exe_file(exe_buffer, PATH_MAX);

    fdname_ori = (void *)p_get_arg1_syscall(regs);
    if (IS_ERR_OR_NULL(fdname_ori))
        goto out;

    len = smith_strnlen_user((char __user *)fdname_ori, PATH_MAX);
    if (len <= 0 || len > PATH_MAX)
        goto out;

    fdname = smith_kmalloc(len + 1, GFP_ATOMIC);
    if(!fdname)
        goto out;

    if(smith_copy_from_user(fdname, (char __user *)fdname_ori, len))
        goto out;

    fdname[len] = '\0';

    flags = (unsigned long)p_get_arg2_syscall(regs);
    memfd_create_print(exe_path, fdname, flags);

out:
    if (exe_buffer)
        smith_kfree(exe_buffer);

    if (fdname)
        smith_kfree(fdname);

    return 0;
}
#endif

static int open_pre_handler(struct kprobe *p, struct pt_regs *regs)
{
    int filename_len = 0;

    char *exe_path = DEFAULT_RET_STR;
    char *buffer = NULL;
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

    buffer = smith_kzalloc(PATH_MAX, GFP_ATOMIC);
    exe_path = smith_get_exe_file(buffer, PATH_MAX);

    open_print(exe_path, filename, (int)p_get_arg2_syscall(regs),
               (umode_t)p_get_arg3_syscall(regs));

out:
    if (buffer)
        smith_kfree(buffer);

    smith_kfree(filename);

    return 0;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 9, 0)
static struct inode *file_inode(struct file * f)
{
    return f->f_path.dentry->d_inode;
}
#endif

static int write_pre_handler(struct kprobe *p, struct pt_regs *regs)
{
    struct file *file;
    const char __user *buf;
    char *exe_path = DEFAULT_RET_STR;
    char *kbuf = NULL;
    char *pname_buf = NULL;
    char *buffer = NULL;
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

    buffer = smith_kzalloc(PATH_MAX, GFP_ATOMIC);
    exe_path = smith_get_exe_file(buffer, PATH_MAX);

    pname_buf = smith_kzalloc(PATH_MAX, GFP_ATOMIC);
    file_path = smith_d_path(&(file)->f_path, pname_buf, PATH_MAX);

    write_print(exe_path, file_path, kbuf);

out:
    if (buffer)
        smith_kfree(buffer);
    if (pname_buf)
        smith_kfree(pname_buf);
    if (kbuf)
        smith_kfree(kbuf);

    return 0;
}

static int openat_pre_handler(struct kprobe *p, struct pt_regs *regs)
{
    int filename_len = 0;

    char *exe_path = DEFAULT_RET_STR;
    char *buffer = NULL;
    char *filename = NULL;
    char __user *filename_ori;

    filename_ori = (void *)p_get_arg2_syscall(regs);
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

    buffer = smith_kzalloc(PATH_MAX, GFP_ATOMIC);
    exe_path = smith_get_exe_file(buffer, PATH_MAX);

    open_print(exe_path, filename, (int)p_get_arg3_syscall(regs),
               (umode_t)p_get_arg4_syscall(regs));

    out:
    if (buffer)
        smith_kfree(buffer);

    smith_kfree(filename);

    return 0;
}

static int mount_pre_handler(struct kprobe *p, struct pt_regs *regs)
{
    unsigned long flags = 0;

    char *pid_tree = NULL;
    char *exe_path = DEFAULT_RET_STR;
    char *buffer = NULL;

    char *pname_buf = NULL;
    char *file_path = DEFAULT_RET_STR;

    const char *fstype = NULL;
    const char *dev_name = NULL;

    struct path *path = NULL;

    dev_name = (const char *)p_regs_get_arg1(regs);
    path = (struct path *)p_regs_get_arg2(regs);
    fstype = (const char *)p_regs_get_arg3(regs);
    flags = (unsigned long)p_regs_get_arg4(regs);

    if (IS_ERR_OR_NULL(path) || !dev_name || !*dev_name)
        return 0;

    pid_tree = smith_get_pid_tree(PID_TREE_LIMIT);

    pname_buf = smith_kzalloc(PATH_MAX, GFP_ATOMIC);
    file_path = smith_d_path(path, pname_buf, PATH_MAX);

    buffer = smith_kzalloc(PATH_MAX, GFP_ATOMIC);
    exe_path = smith_get_exe_file(buffer, PATH_MAX);
    if (!execve_exe_check(exe_path, strlen(exe_path)))
        mount_print(exe_path, pid_tree, dev_name, file_path, fstype, flags);

    if (buffer)
        smith_kfree(buffer);

    if (pname_buf)
        smith_kfree(pname_buf);

    if (pid_tree)
        smith_kfree(pid_tree);

    return 0;
}

static int nanosleep_pre_handler(struct kprobe *p, struct pt_regs *regs)
{
    char *exe_path = DEFAULT_RET_STR;
    char *buffer = NULL;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 18, 0)
    struct __kernel_timespec *ts;
    struct timespec64 tu = {0, 0};
#else
    struct timespec tu = {0, 0};
#endif
    void *tmp;

    tmp = (void *)p_get_arg1_syscall(regs);
    if (IS_ERR_OR_NULL(tmp))
        return 0;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 18, 0)
    ts = (struct __kernel_timespec __user *)tmp;
    if (get_timespec64(&tu, ts))
        return 0;

    if (!timespec64_valid(&tu))
        return 0;
#else
    if (smith_copy_from_user(&tu, (void __user *)tmp, sizeof(tu)))
        return 0;
    if (!timespec_valid(&tu))
        return 0;
#endif

    buffer = smith_kzalloc(PATH_MAX, GFP_ATOMIC);
    exe_path = smith_get_exe_file(buffer, PATH_MAX);

    /* Year-2038 issue: signed-32bit will overflow */
    nanosleep_print(exe_path, (long long)tu.tv_sec, tu.tv_nsec);

    if (buffer)
        smith_kfree(buffer);

    return 0;
}

static void kill_and_tkill_handler(int type, pid_t pid, int sig)
{
    char *exe_path = DEFAULT_RET_STR;
    char *buffer = NULL;

    buffer = smith_kzalloc(PATH_MAX, GFP_ATOMIC);
    exe_path = smith_get_exe_file(buffer, PATH_MAX);

    if (type)
        kill_print(exe_path, pid, sig);
    else
        tkill_print(exe_path, pid, sig);

    if (buffer)
        smith_kfree(buffer);
    return;
}

static int kill_pre_handler(struct kprobe *p, struct pt_regs *regs)
{
    pid_t pid = (pid_t)p_get_arg1_syscall(regs);
    int sig = (int)p_get_arg2_syscall(regs);
    kill_and_tkill_handler(0, pid, sig);
    return 0;
}

static int tkill_pre_handler(struct kprobe *p, struct pt_regs *regs)
{
    pid_t pid = (pid_t)p_get_arg1_syscall(regs);
    int sig = (int)p_get_arg2_syscall(regs);
    kill_and_tkill_handler(1, pid, sig);
    return 0;
}

static void delete_file_handler(int type, char *path)
{
    char *buffer = NULL;
    char *exe_path = DEFAULT_RET_STR;

    buffer = smith_kzalloc(PATH_MAX, GFP_ATOMIC);
    exe_path = smith_get_exe_file(buffer, PATH_MAX);

    if (type)
        security_path_rmdir_print(exe_path, path);
    else
        security_path_unlink_print(exe_path, path);

    if (buffer)
        smith_kfree(buffer);
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
        pathstr = smith_dentry_path(de, pname_buf, PATH_MAX);
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
        /*
         * security_path_rmdir and security_path_unlink are called before
         * the actual rmdir or unlink. Any return code other than 0 will
         * skip (prevent) the actual rmdir or unlink in file system.
         */
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
        pathstr = smith_dentry_path(de, pname_buf, PATH_MAX);
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
    char *exe_path = DEFAULT_RET_STR;
    char *buffer = NULL;

    buffer = smith_kzalloc(PATH_MAX, GFP_ATOMIC);
    exe_path = smith_get_exe_file(buffer, PATH_MAX);

    if (type)
        exit_print(exe_path);
    else
        exit_group_print(exe_path);

    if (buffer)
        smith_kfree(buffer);
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

static int do_init_module_pre_handler(struct kprobe *p, struct pt_regs *regs)
{
    char *pid_tree = NULL;
    char *buffer = NULL;
    char *exe_path = DEFAULT_RET_STR;
    char *pname_buf = NULL;
    char *pname = NULL;
    void *tmp_mod;
    struct module *mod;

    tmp_mod = (void *) p_regs_get_arg1(regs);
    if (IS_ERR_OR_NULL(tmp_mod))
        return 0;

    mod = (struct module *)tmp_mod;

    buffer = smith_kzalloc(PATH_MAX, GFP_ATOMIC);
    exe_path = smith_get_exe_file(buffer, PATH_MAX);

    pname_buf = smith_kzalloc(PATH_MAX, GFP_ATOMIC);
    pname = smith_d_path(&current->fs->pwd, pname_buf, PATH_MAX);

    pid_tree = smith_get_pid_tree(PID_TREE_LIMIT);
    do_init_module_print(exe_path, mod->name, pid_tree, pname);

    if (buffer)
        smith_kfree(buffer);

    if (pid_tree)
        smith_kfree(pid_tree);

    if (pname_buf)
        smith_kfree(pname_buf);

    return 0;
}

static int update_cred_pre_handler(struct kprobe *p, struct pt_regs *regs)
{
    char *exe_path = NULL;
    char *buffer = NULL;
    char *pid_tree = NULL;
    struct cred *cred;
    int new_uid, old_uid;

    cred = (void *)p_regs_get_arg1(regs);
    if (IS_ERR_OR_NULL(cred))
        return 0;

    new_uid = _XID_VALUE(cred->uid);
    old_uid = __get_current_uid();

    // only report if old uid ≠0 && new uid == 0
    if (new_uid != 0 || old_uid == 0)
        return 0;

    buffer = smith_kzalloc(PATH_MAX, GFP_ATOMIC);
    exe_path = smith_get_exe_file(buffer, PATH_MAX);

    pid_tree = smith_get_pid_tree(PID_TREE_LIMIT);
    update_cred_print(exe_path, pid_tree, old_uid, 0);

    if (buffer)
        smith_kfree(buffer);
    if (pid_tree)
        smith_kfree(pid_tree);

    return 0;
}

static int smith_usb_ncb(struct notifier_block *nb, unsigned long val, void *priv)
{
    char *exe_path = DEFAULT_RET_STR;
    char *buffer = NULL;
    struct usb_device *udev;

    if (IS_ERR_OR_NULL(priv))
        return 0;

    udev = (struct usb_device *)priv;
    if (USB_DEVICE_ADD == val) {
        buffer = smith_kzalloc(PATH_MAX, GFP_ATOMIC);
        exe_path = smith_get_exe_file(buffer, PATH_MAX);
        udev_print(exe_path, udev->product, udev->manufacturer, udev->serial, 1);
    } else if (USB_DEVICE_REMOVE == val){
        buffer = smith_kzalloc(PATH_MAX, GFP_ATOMIC);
        exe_path = smith_get_exe_file(buffer, PATH_MAX);
        udev_print(exe_path, udev->product, udev->manufacturer, udev->serial, 2);
    }

    if (buffer)
        smith_kfree(buffer);

    return NOTIFY_OK;
}

static int connect_syscall_entry_handler(struct kretprobe_instance *ri,
                                  struct pt_regs *regs)
{
    struct connect_syscall_data *data;
    data = (struct connect_syscall_data *)ri->data;
    data->fd = p_get_arg1_syscall(regs);
    data->dirp = (struct sockaddr *)p_get_arg2_syscall(regs);
    return 0;
}

static int tcp_v4_connect_entry_handler(struct kretprobe_instance *ri,
                                 struct pt_regs *regs)
{
    struct connect_data *data;
    data = (struct connect_data *)ri->data;
    data->sa_family = AF_INET;
    // type 1 for TCPv4
    data->type = 1;
    data->sk = (struct sock *)p_regs_get_arg1(regs);
    return 0;
}

#if IS_ENABLED(CONFIG_IPV6)
static int tcp_v6_connect_entry_handler(struct kretprobe_instance *ri,
				 struct pt_regs *regs)
{
	struct connect_data *data;
	data = (struct connect_data *)ri->data;
	data->sa_family = AF_INET6;
	// type 2 for TCPv6
	data->type = 2;
	data->sk = (struct sock *)p_regs_get_arg1(regs);
	return 0;
}
#endif

static int ip4_datagram_connect_entry_handler(struct kretprobe_instance *ri,
                                       struct pt_regs *regs)
{
    struct connect_data *data;
    data = (struct connect_data *)ri->data;
    data->sa_family = AF_INET;
    // type 3 for UDPv4
    data->type = 3;
    data->sk = (struct sock *)p_regs_get_arg1(regs);
    return 0;
}

#if IS_ENABLED(CONFIG_IPV6)
static int ip6_datagram_connect_entry_handler(struct kretprobe_instance *ri,
				       struct pt_regs *regs)
{
	struct connect_data *data;
	data = (struct connect_data *)ri->data;
	data->sa_family = AF_INET6;
	// type 4 for UDPv6
	data->type = 4;
	data->sk = (struct sock *)p_regs_get_arg1(regs);
	return 0;
}
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 19, 0)
static struct kretprobe execveat_kretprobe = {
	    .kp.symbol_name = P_GET_SYSCALL_NAME(execveat),
	    .entry_handler = execveat_entry_handler,
	    .data_size = sizeof(struct execve_data),
	    .handler = execve_handler,
};
#endif

static struct kretprobe execve_kretprobe = {
        .kp.symbol_name = P_GET_SYSCALL_NAME(execve),
        .entry_handler = execve_entry_handler,
        .data_size = sizeof(struct execve_data),
        .handler = execve_handler,
};

#ifdef CONFIG_COMPAT
static struct kretprobe compat_execve_kretprobe = {
	    .kp.symbol_name = P_GET_COMPAT_SYSCALL_NAME(execve),
	    .entry_handler = compat_execve_entry_handler,
	    .data_size = sizeof(struct execve_data),
	    .handler = execve_handler,
};

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,19,0)
static struct kretprobe compat_execveat_kretprobe = {
	    .kp.symbol_name = P_GET_COMPAT_SYSCALL_NAME(execveat),
	    .entry_handler = compat_execveat_entry_handler,
	    .data_size = sizeof(struct execve_data),
	    .handler = execve_handler,
};
#endif /* >= 3.19.0 */
#endif /* CONFIG_COMPAT */

static struct kprobe call_usermodehelper_exec_kprobe = {
        .symbol_name = "call_usermodehelper_exec",
        .pre_handler = call_usermodehelper_exec_pre_handler,
};

static struct kprobe mount_kprobe = {
        .symbol_name = "security_sb_mount",
        .pre_handler = mount_pre_handler,
};

static struct kprobe rename_kprobe = {
        .symbol_name = "security_inode_rename",
        .pre_handler = rename_pre_handler,
};

static struct kprobe link_kprobe = {
        .symbol_name = "security_inode_link",
        .pre_handler = link_pre_handler,
};

static struct kprobe ptrace_kprobe = {
        .symbol_name = P_GET_SYSCALL_NAME(ptrace),
        .pre_handler = ptrace_pre_handler,
};

#if IS_ENABLED(CONFIG_IPV6)
static struct kretprobe ip6_datagram_connect_kretprobe = {
	    .kp.symbol_name = "ip6_datagram_connect",
	    .data_size = sizeof(struct connect_data),
	    .handler = connect_handler,
	    .entry_handler = ip6_datagram_connect_entry_handler,
};

static struct kretprobe tcp_v6_connect_kretprobe = {
	    .kp.symbol_name = "tcp_v6_connect",
	    .data_size = sizeof(struct connect_data),
	    .handler = connect_handler,
	    .entry_handler = tcp_v6_connect_entry_handler,
};
#endif

static struct kretprobe ip4_datagram_connect_kretprobe = {
        .kp.symbol_name = "ip4_datagram_connect",
        .data_size = sizeof(struct connect_data),
        .handler = connect_handler,
        .entry_handler = ip4_datagram_connect_entry_handler,
};

static struct kretprobe tcp_v4_connect_kretprobe = {
        .kp.symbol_name = "tcp_v4_connect",
        .data_size = sizeof(struct connect_data),
        .handler = connect_handler,
        .entry_handler = tcp_v4_connect_entry_handler,
};

static struct kretprobe connect_syscall_kretprobe = {
        .kp.symbol_name = P_GET_SYSCALL_NAME(connect),
        .data_size = sizeof(struct connect_syscall_data),
        .handler = connect_syscall_handler,
        .entry_handler = connect_syscall_entry_handler,
};

static struct kretprobe accept_kretprobe = {
        .kp.symbol_name = P_GET_SYSCALL_NAME(accept),
        .data_size = sizeof(struct accept_data),
        .handler = accept_handler,
        .entry_handler = accept_entry_handler,
};

static struct kretprobe accept4_kretprobe = {
        .kp.symbol_name = P_GET_SYSCALL_NAME(accept4),
        .data_size = sizeof(struct accept_data),
        .handler = accept_handler,
        .entry_handler = accept4_entry_handler,
};

static struct kprobe do_init_module_kprobe = {
        .symbol_name = "do_init_module",
        .pre_handler = do_init_module_pre_handler,
};

static struct kprobe update_cred_kprobe = {
        .symbol_name = "commit_creds",
        .pre_handler = update_cred_pre_handler,
};

static struct kprobe security_inode_create_kprobe = {
        .symbol_name = "security_inode_create",
        .pre_handler = security_inode_create_pre_handler,
};

static struct kretprobe bind_kretprobe = {
        .kp.symbol_name = P_GET_SYSCALL_NAME(bind),
        .data_size = sizeof(struct bind_data),
        .handler = bind_handler,
        .entry_handler = bind_entry_handler,
};

static struct kprobe mprotect_kprobe = {
        .symbol_name = "security_file_mprotect",
        .pre_handler = mprotect_pre_handler,
};

static struct kprobe setsid_kprobe = {
        .symbol_name = P_GET_SYSCALL_NAME(setsid),
        .pre_handler = setsid_pre_handler,
};

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 17, 0)
static struct kprobe memfd_create_kprobe = {
        .symbol_name = P_GET_SYSCALL_NAME(memfd_create),
        .pre_handler = memfd_create_kprobe_pre_handler,
};
#endif

static struct kprobe prctl_kprobe = {
        .symbol_name = P_GET_SYSCALL_NAME(prctl),
        .pre_handler = prctl_pre_handler,
};

static struct kprobe open_kprobe = {
        .symbol_name = P_GET_SYSCALL_NAME(open),
        .pre_handler = open_pre_handler,
};

static struct kprobe openat_kprobe = {
        .symbol_name = P_GET_SYSCALL_NAME(openat),
        .pre_handler = openat_pre_handler,
};

static struct kprobe kill_kprobe = {
        .symbol_name = P_GET_SYSCALL_NAME(kill),
        .pre_handler = kill_pre_handler,
};

static struct kprobe tkill_kprobe = {
        .symbol_name = P_GET_SYSCALL_NAME(tkill),
        .pre_handler = tkill_pre_handler,
};

static struct kprobe nanosleep_kprobe = {
        .symbol_name = P_GET_SYSCALL_NAME(nanosleep),
        .pre_handler = nanosleep_pre_handler,
};

static struct kprobe write_kprobe = {
        .symbol_name = "vfs_write",
        .pre_handler = write_pre_handler,
};

static struct kprobe exit_kprobe = {
        .symbol_name = P_GET_SYSCALL_NAME(exit),
        .pre_handler = exit_pre_handler,
};

static struct kprobe exit_group_kprobe = {
        .symbol_name = P_GET_SYSCALL_NAME(exit_group),
        .pre_handler = exit_group_pre_handler,
};

static struct kretprobe security_path_rmdir_kprobe = {
        .kp.symbol_name = "security_path_rmdir",
        .handler = rm_handler,
        .entry_handler = security_path_rmdir_pre_handler,
};

static struct kretprobe security_path_unlink_kprobe = {
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

static int register_bind_kprobe(void)
{
    int ret;
    ret = smith_register_kretprobe(&bind_kretprobe);

    if (ret == 0)
        bind_kprobe_state = 0x1;

    return ret;
}

static void unregister_bind_kprobe(void)
{
    smith_unregister_kretprobe(&bind_kretprobe);
}

static int register_call_usermodehelper_exec_kprobe(void)
{
    int ret;
    ret = register_kprobe(&call_usermodehelper_exec_kprobe);

    if (ret == 0)
       call_usermodehelper_exec_kprobe_state= 0x1;

    return ret;
}

static void unregister_call_usermodehelper_exec_kprobe(void)
{
    unregister_kprobe(&call_usermodehelper_exec_kprobe);
}

static int register_rename_kprobe(void)
{
    int ret;
    ret = register_kprobe(&rename_kprobe);

    if (ret == 0)
        rename_kprobe_state = 0x1;

    return ret;
}

static void unregister_rename_kprobe(void)
{
    unregister_kprobe(&rename_kprobe);
}

static int register_exit_kprobe(void)
{
    int ret;
    ret = register_kprobe(&exit_kprobe);

    if (ret == 0)
        exit_kprobe_state = 0x1;

    return ret;
}

static void unregister_exit_kprobe(void)
{
    unregister_kprobe(&exit_kprobe);
}

static int register_exit_group_kprobe(void)
{
    int ret;
    ret = register_kprobe(&exit_group_kprobe);

    if (ret == 0)
        exit_group_kprobe_state = 0x1;

    return ret;
}

static void unregister_exit_group_kprobe(void)
{
    unregister_kprobe(&exit_group_kprobe);
}

static int register_link_kprobe(void)
{
    int ret;
    ret = register_kprobe(&link_kprobe);

    if (ret == 0)
        link_kprobe_state = 0x1;

    return ret;
}

static void unregister_link_kprobe(void)
{
    unregister_kprobe(&link_kprobe);
}

static int register_execve_kprobe(void)
{
    int ret;
    ret = smith_register_kretprobe(&execve_kretprobe);
    if (ret == 0)
        execve_kretprobe_state = 0x1;

    return ret;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 19, 0)
static int register_execveat_kprobe(void)
{
	int ret;
	ret = smith_register_kretprobe(&execveat_kretprobe);
	if (ret == 0)
		execveat_kretprobe_state = 0x1;

	return ret;
}
#endif

#ifdef CONFIG_COMPAT
static int register_compat_execve_kprobe(void)
{
	int ret;
	ret = smith_register_kretprobe(&compat_execve_kretprobe);
	if (ret == 0)
		compat_execve_kretprobe_state = 0x1;

	return ret;
}

static void unregister_compat_execve_kprobe(void)
{
	smith_unregister_kretprobe(&compat_execve_kretprobe);
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 19, 0)
static int register_compat_execveat_kprobe(void)
{
	int ret;
	ret = smith_register_kretprobe(&compat_execveat_kretprobe);
	if (ret == 0)
		compat_execveat_kretprobe_state = 0x1;

	return ret;
}

static void unregister_compat_execveat_kprobe(void)
{
	smith_unregister_kretprobe(&compat_execveat_kretprobe);
}
#endif
#endif

static void unregister_execve_kprobe(void)
{
    smith_unregister_kretprobe(&execve_kretprobe);
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 19, 0)
static void unregister_execveat_kprobe(void)
{
	smith_unregister_kretprobe(&execveat_kretprobe);
}
#endif

static int register_ptrace_kprobe(void)
{
    int ret;
    ret = register_kprobe(&ptrace_kprobe);

    if (ret == 0)
        ptrace_kprobe_state = 0x1;

    return ret;
}

static void unregister_ptrace_kprobe(void)
{
    unregister_kprobe(&ptrace_kprobe);
}

#if IS_ENABLED(CONFIG_IPV6)
static int register_ip6_datagram_connect_kprobe(void)
{
	int ret;
	ret = smith_register_kretprobe(&ip6_datagram_connect_kretprobe);

	if (ret == 0)
		ip6_datagram_connect_kprobe_state = 0x1;

	return ret;
}

static void unregister_ip6_datagram_connect_kprobe(void)
{
	smith_unregister_kretprobe(&ip6_datagram_connect_kretprobe);
}

static int register_tcp_v6_connect_kprobe(void)
{
	int ret;
	ret = smith_register_kretprobe(&tcp_v6_connect_kretprobe);

	if (ret == 0)
		tcp_v6_connect_kprobe_state = 0x1;

	return ret;
}

static void unregister_tcp_v6_connect_kprobe(void)
{
	smith_unregister_kretprobe(&tcp_v6_connect_kretprobe);
}
#endif

static int register_ip4_datagram_connect_kprobe(void)
{
    int ret;
    ret = smith_register_kretprobe(&ip4_datagram_connect_kretprobe);

    if (ret == 0)
        ip4_datagram_connect_kprobe_state = 0x1;

    return ret;
}

static void unregister_ip4_datagram_connect_kprobe(void)
{
    smith_unregister_kretprobe(&ip4_datagram_connect_kretprobe);
}

static int register_tcp_v4_connect_kprobe(void)
{
    int ret;
    ret = smith_register_kretprobe(&tcp_v4_connect_kretprobe);

    if (ret == 0)
        tcp_v4_connect_kprobe_state = 0x1;

    return ret;
}

static void unregister_tcp_v4_connect_kprobe(void)
{
    smith_unregister_kretprobe(&tcp_v4_connect_kretprobe);
}

static int register_connect_syscall_kprobe(void)
{
    int ret;
    ret = smith_register_kretprobe(&connect_syscall_kretprobe);

    if (ret == 0)
        connect_syscall_kprobe_state = 0x1;

    return ret;
}

static void unregister_connect_syscall_kprobe(void)
{
    smith_unregister_kretprobe(&connect_syscall_kretprobe);
}

static int register_accept_kprobe(void)
{
    int ret;
    ret = smith_register_kretprobe(&accept_kretprobe);

    if (ret == 0)
        accept_kretprobe_state = 0x1;

    return ret;
}

static void unregister_accept_kprobe(void)
{
    smith_unregister_kretprobe(&accept_kretprobe);
}

static int register_accept4_kprobe(void)
{
    int ret;
    ret = smith_register_kretprobe(&accept4_kretprobe);

    if (ret == 0)
        accept4_kretprobe_state = 0x1;

    return ret;
}

static void unregister_accept4_kprobe(void)
{
    smith_unregister_kretprobe(&accept4_kretprobe);
}

static int register_create_file_kprobe(void)
{
    int ret;
    ret = register_kprobe(&security_inode_create_kprobe);
    if (ret == 0)
        create_file_kprobe_state = 0x1;

    return ret;
}

static void unregister_create_file_kprobe(void)
{
    unregister_kprobe(&security_inode_create_kprobe);
}

static int register_mount_kprobe(void)
{
    int ret;
    ret = register_kprobe(&mount_kprobe);
    if (ret == 0)
        mount_kprobe_state = 0x1;

    return ret;
}

static void unregister_mount_kprobe(void)
{
    unregister_kprobe(&mount_kprobe);
}

static int register_do_init_module_kprobe(void)
{
    int ret;
    ret = register_kprobe(&do_init_module_kprobe);

    if (ret == 0)
        do_init_module_kprobe_state = 0x1;

    return ret;
}

static void unregister_do_init_module_kprobe(void)
{
    unregister_kprobe(&do_init_module_kprobe);
}

static int register_setsid_kprobe(void)
{
    int ret;
    ret = register_kprobe(&setsid_kprobe);

    if (ret == 0)
        setsid_kprobe_state = 0x1;

    return ret;
}

static void unregister_setsid_kprobe(void)
{
    unregister_kprobe(&setsid_kprobe);
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 17, 0)
static int register_memfd_create_kprobe(void)
{
    int ret;
    ret = register_kprobe(&memfd_create_kprobe);

    if (ret == 0)
        memfd_create_kprobe_state = 0x1;

    return ret;
}

static void unregister_memfd_create_kprobe(void)
{
    unregister_kprobe(&memfd_create_kprobe);
}
#endif

static int register_prctl_kprobe(void)
{
    int ret;
    ret = register_kprobe(&prctl_kprobe);

    if (ret == 0)
        prctl_kprobe_state = 0x1;

    return ret;
}

static void unregister_prctl_kprobe(void)
{
    unregister_kprobe(&prctl_kprobe);
}

static int register_update_cred_kprobe(void)
{
    int ret;
    ret = register_kprobe(&update_cred_kprobe);
    if (ret == 0)
        update_cred_kprobe_state = 0x1;

    return ret;
}

static void unregister_update_cred_kprobe(void)
{
    unregister_kprobe(&update_cred_kprobe);
}

static int register_mprotect_kprobe(void)
{
    int ret;
    ret = register_kprobe(&mprotect_kprobe);
    if (ret == 0)
        mprotect_kprobe_state = 0x1;

    return ret;
}

static void unregister_mprotect_kprobe(void)
{
    unregister_kprobe(&mprotect_kprobe);
}

static int register_open_kprobe(void)
{
    int ret;
    ret = register_kprobe(&open_kprobe);
    if (ret == 0)
        open_kprobe_state = 0x1;

    return ret;
}

static void unregister_open_kprobe(void)
{
    unregister_kprobe(&open_kprobe);
}

static int register_openat_kprobe(void)
{
    int ret;
    ret = register_kprobe(&openat_kprobe);
    if (ret == 0)
        openat_kprobe_state = 0x1;

    return ret;
}

static void unregister_openat_kprobe(void)
{
    unregister_kprobe(&openat_kprobe);
}

static int register_nanosleep_kprobe(void)
{
    int ret;
    ret = register_kprobe(&nanosleep_kprobe);
    if (ret == 0)
        nanosleep_kprobe_state = 0x1;

    return ret;
}

static void unregister_nanosleep_kprobe(void)
{
    unregister_kprobe(&nanosleep_kprobe);
}

static int register_security_path_rmdir_kprobe(void)
{
    int ret;
    ret = smith_register_kretprobe(&security_path_rmdir_kprobe);
    if (ret == 0)
        security_path_rmdir_kprobe_state = 0x1;

    return ret;
}

static void unregister_security_path_rmdir_kprobe(void)
{
    smith_unregister_kretprobe(&security_path_rmdir_kprobe);
}

static int register_security_path_unlink_kprobe(void)
{
    int ret;
    ret = smith_register_kretprobe(&security_path_unlink_kprobe);
    if (ret == 0)
        security_path_unlink_kprobe_state = 0x1;

    return ret;
}

static void unregister_security_path_unlink_kprobe(void)
{
    smith_unregister_kretprobe(&security_path_unlink_kprobe);
}

static int register_kill_kprobe(void)
{
    int ret;
    ret = register_kprobe(&kill_kprobe);
    if (ret == 0)
        kill_kprobe_state = 0x1;

    return ret;
}

static void unregister_kill_kprobe(void)
{
    unregister_kprobe(&kill_kprobe);
}

static int register_tkill_kprobe(void)
{
    int ret;
    ret = register_kprobe(&tkill_kprobe);
    if (ret == 0)
        tkill_kprobe_state = 0x1;

    return ret;
}

static void unregister_tkill_kprobe(void)
{
    unregister_kprobe(&tkill_kprobe);
}

static int register_write_kprobe(void)
{
    int ret;
    ret = register_kprobe(&write_kprobe);
    if (ret == 0)
        write_kprobe_state = 0x1;

    return ret;
}

static void unregister_write_kprobe(void)
{
    unregister_kprobe(&write_kprobe);
}

static void uninstall_kprobe(void)
{
    if (UDEV_HOOK == 1) {
        static void (*smith_usb_unregister_notify) (struct notifier_block * nb);
        smith_usb_unregister_notify = (void *)__symbol_get("usb_unregister_notify");
        if (smith_usb_unregister_notify) {
            smith_usb_unregister_notify(&smith_usb_notifier);
            __symbol_put("usb_unregister_notify");
        }
    }

    if (bind_kprobe_state == 0x1)
        unregister_bind_kprobe();

    if (connect_syscall_kprobe_state == 0x1)
        unregister_connect_syscall_kprobe();

    if (call_usermodehelper_exec_kprobe_state == 0x1)
        unregister_call_usermodehelper_exec_kprobe();

    if (mprotect_kprobe_state == 0x1)
        unregister_mprotect_kprobe();

    if (execve_kretprobe_state == 0x1)
        unregister_execve_kprobe();

    if (ptrace_kprobe_state == 0x1)
        unregister_ptrace_kprobe();

    if (create_file_kprobe_state == 0x1)
        unregister_create_file_kprobe();

    if (do_init_module_kprobe_state == 0x1)
        unregister_do_init_module_kprobe();

    if (update_cred_kprobe_state == 0x1)
        unregister_update_cred_kprobe();

    if (setsid_kprobe_state == 0x1)
        unregister_setsid_kprobe();

    if (tcp_v4_connect_kprobe_state == 0x1)
        unregister_tcp_v4_connect_kprobe();

    if (tcp_v6_connect_kprobe_state == 0x1)
        unregister_tcp_v6_connect_kprobe();

    if (ip4_datagram_connect_kprobe_state == 0x1)
        unregister_ip4_datagram_connect_kprobe();

    if (ip6_datagram_connect_kprobe_state == 0x1)
        unregister_ip6_datagram_connect_kprobe();

    if (mount_kprobe_state == 0x1)
        unregister_mount_kprobe();

    if (write_kprobe_state == 0x1)
        unregister_write_kprobe();

    if (rename_kprobe_state == 0x1)
        unregister_rename_kprobe();

    if (prctl_kprobe_state == 0x1)
        unregister_prctl_kprobe();

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 17, 0)
    if (memfd_create_kprobe_state == 0x1)
        unregister_memfd_create_kprobe();
#endif

    if (accept_kretprobe_state == 0x1)
        unregister_accept_kprobe();

    if (accept4_kretprobe_state == 0x1)
        unregister_accept4_kprobe();

    if (open_kprobe_state == 0x1)
        unregister_open_kprobe();

    if (openat_kprobe_state == 0x1)
        unregister_openat_kprobe();

    if (nanosleep_kprobe_state == 0x1)
        unregister_nanosleep_kprobe();

    if (kill_kprobe_state == 0x1)
        unregister_kill_kprobe();

    if (tkill_kprobe_state == 0x1)
        unregister_tkill_kprobe();

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

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 19, 0)
    if (execveat_kretprobe_state == 0x1)
		unregister_execveat_kprobe();
#endif

#ifdef CONFIG_COMPAT
    if (compat_execve_kretprobe_state == 0x1)
        unregister_compat_execve_kprobe();
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 19, 0)
    if (compat_execveat_kretprobe_state == 0x1)
	    unregister_compat_execveat_kprobe();
#endif
#endif
}

static void __init install_kprobe(void)
{
    int ret;

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

    if (ACCEPT_HOOK == 1) {
        ret = register_accept_kprobe();
        if (ret < 0)
            printk(KERN_INFO "[ELKEID] open accept_kprobe failed, returned %d\n", ret);

        ret = register_accept4_kprobe();
        if (ret < 0)
            printk(KERN_INFO "[ELKEID] open accept4_kprobe failed, returned %d\n", ret);
    }

    if (OPEN_HOOK == 1) {
        ret = register_open_kprobe();
        if (ret < 0)
            printk(KERN_INFO "[ELKEID] open register_kprobe failed, returned %d\n", ret);

        ret = register_openat_kprobe();
        if (ret < 0)
            printk(KERN_INFO "[ELKEID] openat register_kprobe failed, returned %d\n", ret);
    }

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 17, 0)
    if (MEMFD_CREATE_HOOK == 1) {
        ret = register_memfd_create_kprobe();
        if (ret < 0)
            printk(KERN_INFO "[ELKEID] memfd_create register_kprobe failed, returned %d\n", ret);
    }
#endif

    if (KILL_HOOK == 1) {
        ret = register_kill_kprobe();
        if (ret < 0)
            printk(KERN_INFO "[ELKEID] kill register_kprobe failed, returned %d\n", ret);

        ret = register_tkill_kprobe();
        if (ret < 0)
            printk(KERN_INFO "[ELKEID] tkill register_kprobe failed, returned %d\n", ret);
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

    if (NANOSLEEP_HOOK == 1) {
        ret = register_nanosleep_kprobe();
        if (ret < 0)
            printk(KERN_INFO "[ELKEID] nanosleep register_kprobe failed, returned %d\n", ret);
    }

    if (CONNECT_HOOK == 1) {
        ret = register_connect_syscall_kprobe();
        if (ret < 0)
            printk(KERN_INFO "[ELKEID] connect register_kprobe failed, returned %d\n", ret);

        if (!connect_syscall_kprobe_state) {
            ret = register_tcp_v4_connect_kprobe();
            if (ret < 0)
                printk(KERN_INFO "[ELKEID] connect register_kprobe failed, returned %d\n", ret);

            ret = register_ip4_datagram_connect_kprobe();
            if (ret < 0)
                printk(KERN_INFO "[ELKEID] ip4_datagram_connect register_kprobe failed, returned %d\n", ret);

#if IS_ENABLED(CONFIG_IPV6)
            ret = register_tcp_v6_connect_kprobe();
            if (ret < 0)
                printk(KERN_INFO "[ELKEID] tcp_v6_connect register_kprobe failed, returned %d\n", ret);

            ret = register_ip6_datagram_connect_kprobe();
            if (ret < 0)
                printk(KERN_INFO "[ELKEID] ip6_datagram_connect register_kprobe failed, returned %d\n", ret);
#endif
        }
    }

    if (MPROTECT_HOOK == 1) {
        ret = register_mprotect_kprobe();
        if (ret < 0)
            printk(KERN_INFO "[ELKEID] mprotect register_kprobe failed, returned %d\n", ret);
    }

    if (PRCTL_HOOK == 1) {
        ret = register_prctl_kprobe();
        if (ret < 0)
            printk(KERN_INFO "[ELKEID] prctl register_kprobe failed, returned %d\n", ret);
    }

    if (SETSID_HOOK == 1) {
        ret = register_setsid_kprobe();
        if (ret < 0)
            printk(KERN_INFO "[ELKEID] setsid register_kprobe failed, returned %d\n", ret);
    }

    if (BIND_HOOK == 1) {
        ret = register_bind_kprobe();
        if (ret < 0)
            printk(KERN_INFO "[ELKEID] bind register_kprobe failed, returned %d\n", ret);
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

    if (EXECVE_HOOK == 1) {
        ret = register_execve_kprobe();
        if (ret < 0)
            printk(KERN_INFO "[ELKEID] execve register_kprobe failed, returned %d\n", ret);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 19, 0)
        ret = register_execveat_kprobe();
		if (ret < 0)
			printk(KERN_INFO "[ELKEID] execveat register_kprobe failed, returned %d\n", ret);
#endif

#ifdef CONFIG_COMPAT
        ret = register_compat_execve_kprobe();
		if (ret < 0)
			printk(KERN_INFO "[ELKEID] compat_sys_execve register_kprobe failed, returned %d\n", ret);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 19, 0)
		ret = register_compat_execveat_kprobe();
		if (ret < 0)
			printk(KERN_INFO "[ELKEID] compat_sys_execveat register_kprobe failed, returned %d\n", ret);
#endif
#endif
    }

    if (USERMODEHELPER_HOOK == 1) {
        ret = register_call_usermodehelper_exec_kprobe();
        if (ret < 0)
            printk(KERN_INFO "[ELKEID] call_usermodehelper_exec register_kprobe failed, returned %d\n", ret);
    }

    if (PTRACE_HOOK == 1) {
        ret = register_ptrace_kprobe();
        if (ret < 0)
            printk(KERN_INFO "[ELKEID] ptrace register_kprobe failed, returned %d\n", ret);
    }

    if (MODULE_LOAD_HOOK == 1) {
        ret = register_do_init_module_kprobe();
        if (ret < 0)
            printk(KERN_INFO "[ELKEID] do_init_module register_kprobe failed, returned %d\n", ret);
    }

    if (UPDATE_CRED_HOOK == 1) {
        ret = register_update_cred_kprobe();
        if (ret < 0)
            printk(KERN_INFO "[ELKEID] update_cred register_kprobe failed, returned %d\n", ret);
    }
}

#define SMITH_SRCID(name)                           \
    #name;                                          \
    static char *sid_##name = #name;                \
    module_param(sid_##name, charp, S_IRUSR|S_IRGRP|S_IROTH)

/* latest commit id */
static char *smith_srcid = SMITH_SRCID(ff8c8c100f9cd9d0aa1e0bb96031f45ef17dccf6_17024);

static int __init kprobe_hook_init(void)
{
    int ret;

#if defined(MODULE)
    printk(KERN_INFO "[ELKEID] kmod: %s (%s / %s) loaded\n",
           THIS_MODULE->name, THIS_MODULE->version, THIS_MODULE->srcversion);
#endif
    printk(KERN_INFO "[ELKEID] srcid: %s\n", smith_srcid);

    ret = kernel_symbols_init();
    if (ret)
        return ret;

    /* prepare delayed-put thread for async put_files_struct */
    ret = smith_start_delayed_put();
    if (ret)
        return ret;

    ret = filter_init();
    if (ret) {
        smith_stop_delayed_put();
        return ret;
    }

    printk(KERN_INFO "[ELKEID] Filter Init Success \n");

#if (EXIT_PROTECT == 1)
    exit_protect_action();
#endif

    __init_root_pid_ns_inum();

    /* register tracepoints for dns query */
    ret = smith_sysret_init();
    if (ret) {
        filter_cleanup();
        smith_stop_delayed_put();
        return ret;
    }

    /* install kprobe/kretprobe hookproints */
    install_kprobe();

    printk( KERN_INFO "[ELKEID] SANDBOX: %d\n", SANDBOX);
    printk( KERN_INFO "[ELKEID] register_kprobe success: connect_hook: %d, load_module_hook:  %d, execve_hook: %d, "
            "call_usermodehekoer_hook: %d, bind_hook: %d, create_file_hook: %d, ptrace_hook: %d, update_cred_hook: %d, "
            "dns_hook: %d, accept_hook:%d, mprotect_hook: %d, mount_hook: %d, link_hook: %d, memfd_create: %d, "
            "rename_hook: %d, setsid_hook:%d, prctl_hook:%d, open_hook:%d, udev_hook:%d, nanosleep_hook:%d, kill_hook: %d, "
            "rm_hook: %d, exit_hook: %d, write_hook: %d, EXIT_PROTECT: %d\n",
            CONNECT_HOOK, MODULE_LOAD_HOOK, EXECVE_HOOK, USERMODEHELPER_HOOK, BIND_HOOK, CREATE_FILE_HOOK, PTRACE_HOOK,
            UPDATE_CRED_HOOK, DNS_HOOK, ACCEPT_HOOK, MPROTECT_HOOK, MOUNT_HOOK, LINK_HOOK, MEMFD_CREATE_HOOK, RENAME_HOOK,
            SETSID_HOOK, PRCTL_HOOK, OPEN_HOOK, UDEV_HOOK, NANOSLEEP_HOOK, KILL_HOOK, RM_HOOK, EXIT_HOOK, WRITE_HOOK,
            EXIT_PROTECT);
    return 0;
}

static void kprobe_hook_exit(void)
{
    /* clean nf_hooks of psad if hooked */
    mutex_lock(&g_nf_psad_lock);
    if (g_nf_psad_status)
        unregister_pernet_subsys(&smith_psad_net_ops);
    mutex_unlock(&g_nf_psad_lock);

    /* cleaning up kprobe hook points */
    uninstall_kprobe();
    smith_sysret_fini();
    filter_cleanup();
    smith_stop_delayed_put();

    printk(KERN_INFO "[ELKEID] uninstall_kprobe success\n");
}

KPROBE_INITCALL(kprobe_hook, kprobe_hook_init, kprobe_hook_exit);

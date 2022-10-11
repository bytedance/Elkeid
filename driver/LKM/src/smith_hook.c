// SPDX-License-Identifier: GPL-2.0
/*
 * smith_hook.c
 *
 * Hook some kernel function
 */
#include "../include/smith_hook.h"

/* mount_ns and pid_ns id for systemd process */
static void *ROOT_MNT_NS;
static void *ROOT_MNT_SB;
static uint64_t ROOT_MNT_NS_ID;

#define __SD_XFER_SE__
#include "../include/xfer.h"
#include "../include/kprobe_print.h"

#include <linux/kthread.h>
#include <linux/moduleparam.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_ipv6.h>

#define EXIT_PROTECT 0
#define SANDBOX 0

#define SMITH_MAX_ARG_STRINGS (16)

// Hook on-off
int CONNECT_HOOK = 1;
int BIND_HOOK = 1;
int EXECVE_HOOK = 1;
int CREATE_FILE_HOOK = 1;
int FILE_PERMISSION_HOOK = 0;
int PTRACE_HOOK = 1;
int DO_INIT_MODULE_HOOK = 1;
int UPDATE_CRED_HOOK = 1;
int RENAME_HOOK = 1;
int LINK_HOOK = 1;
int SETSID_HOOK = 1;
int PRCTL_HOOK = 1;
int MEMFD_CREATE_HOOK = 1;
int MOUNT_HOOK = 1;
int DNS_HOOK = 1;
int CALL_USERMODEHELPER = 1;
int UDEV_NOTIFIER = 1;
int CHMOD_HOOK = 1;

int WRITE_HOOK = 0;
int ACCEPT_HOOK = 0;
int OPEN_HOOK = 0;
int MPROTECT_HOOK = 0;
int NANOSLEEP_HOOK = 0;
int KILL_HOOK = 0;
int RM_HOOK = 0;
int EXIT_HOOK = 0;

int FAKE_SLEEP = 0;
int FAKE_RM = 0;

int PID_TREE_LIMIT = 12;
int PID_TREE_LIMIT_LOW = 8;
int EXECVE_GET_SOCK_PID_LIMIT = 4;
int EXECVE_GET_SOCK_FD_LIMIT = 12;  /* maximum fd numbers to be queried */

char create_file_kprobe_state = 0x0;
char do_init_module_kprobe_state = 0x0;
char update_cred_kprobe_state = 0x0;
char mprotect_kprobe_state = 0x0;
char mount_kprobe_state = 0x0;
char rename_kprobe_state = 0x0;
char link_kprobe_state = 0x0;
char open_kprobe_state = 0x0;
char openat_kprobe_state = 0x0;
char exit_kprobe_state = 0x0;
char exit_group_kprobe_state = 0x0;
char security_path_rmdir_kprobe_state = 0x0;
char security_path_unlink_kprobe_state = 0x0;
char call_usermodehelper_exec_kprobe_state = 0x0;
char file_permission_kprobe_state = 0x0;
char inode_permission_kprobe_state = 0x0;
char write_kprobe_state = 0x0;

#if (EXIT_PROTECT == 1) && defined(MODULE)
void exit_protect_action(void)
{
	__module_get(THIS_MODULE);
}
#endif

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

static void (*put_files_struct_sym) (struct files_struct * files);
static void smith_put_files_struct(struct files_struct *files)
{
    put_files_struct_sym(files);
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 11, 0)
#define smith_lookup_fd          files_lookup_fd_rcu
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
        fput(exe);
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
    fput(filp);

    return path;
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
    struct path root;
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
    root = task->fs->root;
    task_unlock(task);

    /* get superblock of root fs, using as mnt namespace id */
    sb = root.mnt ? root.mnt->mnt_sb : NULL;
    mntns = sb ? (unsigned long)sb : -1;
    mntns = (~mntns) << 16; /* canonical address */
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

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 11, 0)
    ptr = (void *)smith_kallsyms_lookup_name("ktime_get_real_seconds");
    if (ptr)
        smith_ktime_get_real_seconds = ptr;
    smith_init_get_seconds();
#endif

    ptr = (void *)smith_kallsyms_lookup_name("d_absolute_path");
    if (ptr)
        smith_d_absolute_path = ptr;
    else
        smith_d_absolute_path = (void *)d_path;

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

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 17, 0)

static int smith_get_sock_v4(struct socket *sock, struct sockaddr *sa)
{
    struct sock *sk	= sock->sk;
    struct inet_sock *inet = inet_sk(sk);
    DECLARE_SOCKADDR(struct sockaddr_in *, sin, sa);
    __be32 addr;

    sin->sin_family = AF_INET;
    addr = inet->inet_rcv_saddr;
    if (!addr)
        addr = inet->inet_saddr;
    sin->sin_port = inet->inet_sport;
    sin->sin_addr.s_addr = addr;
    return sizeof(*sin);
}

static int smith_get_peer_v4(struct socket *sock, struct sockaddr *sa)
{
    struct sock *sk	= sock->sk;
    struct inet_sock *inet = inet_sk(sk);
    DECLARE_SOCKADDR(struct sockaddr_in *, sin, sa);

    sin->sin_family = AF_INET;
    if (!inet->inet_dport ||
        (((1 << sk->sk_state) & (TCPF_CLOSE | TCPF_SYN_SENT))))
        return -ENOTCONN;
    sin->sin_port = inet->inet_dport;
    sin->sin_addr.s_addr = inet->inet_daddr;
    return sizeof(*sin);
}

#if IS_ENABLED(CONFIG_IPV6)
static int smith_get_sock_v6(struct socket *sock, struct sockaddr *sa)
{
    struct sockaddr_in6 *sin = (struct sockaddr_in6 *)sa;
    struct sock *sk = sock->sk;
    struct inet_sock *inet = inet_sk(sk);
    struct ipv6_pinfo *np = inet6_sk(sk);

    sin->sin6_family = AF_INET6;
    if (ipv6_addr_any(&sk->sk_v6_rcv_saddr))
        sin->sin6_addr = np->saddr;
    else
        sin->sin6_addr = sk->sk_v6_rcv_saddr;
    sin->sin6_port = inet->inet_sport;
    return sizeof(*sin);
}

static int smith_get_peer_v6(struct socket *sock, struct sockaddr *sa)
{
    struct sockaddr_in6 *sin = (struct sockaddr_in6 *)sa;
    struct sock *sk = sock->sk;
    struct inet_sock *inet = inet_sk(sk);

    sin->sin6_family = AF_INET6;
    if (!inet->inet_dport)
        return -ENOTCONN;
    if ((1 << sk->sk_state) & (TCPF_CLOSE | TCPF_SYN_SENT))
        return -ENOTCONN;
    sin->sin6_port = inet->inet_dport;
    sin->sin6_addr = sk->sk_v6_daddr;
    return sizeof(*sin);
}
#endif

#else /* < 4.17.0 */

static int smith_get_sock_v4(struct socket *sock, struct sockaddr *sa)
{
    int len = 0;
    return kernel_getsockname(sock, sa, &len);
}
static int smith_get_peer_v4(struct socket *sock, struct sockaddr *sa)
{
    int len = 0;
    return kernel_getpeername(sock, sa, &len);
}

#if IS_ENABLED(CONFIG_IPV6)
static int smith_get_sock_v6(struct socket *sock, struct sockaddr *sa)
{
    int len = 0;
    return kernel_getsockname(sock, sa, &len);
}
static int smith_get_peer_v6(struct socket *sock, struct sockaddr *sa)
{
    int len = 0;
    return kernel_getpeername(sock, sa, &len);
}
#endif

#endif /* LINUX_VERSION_CODE >= KERNEL_VERSION(4, 17, 0) */

//get task tree first AF_INET/AF_INET6 socket info
void get_process_socket(__be32 *sip4, struct in6_addr *sip6, int *sport,
                        __be32 *dip4, struct in6_addr *dip6, int *dport,
                        pid_t *socket_pid, int *sa_family)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 6, 0)

    /* fput() can not be called in atomic context */
    *sip4 = *dip4 = 0;
    *sport = *dport = 0;
    memset(sip6, 0, sizeof(*sip6));
    memset(dip6, 0, sizeof(*dip6));
    *socket_pid = 0;
    *sa_family = 0;

#else

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

#endif

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
        if (execve_exe_check(exe_path))
            goto out;
    }

    if (AF_INET == sock->sk->sk_family) {
        struct in_addr *sip4;
        if (smith_get_sock_v4(sock, &sa.sa) < 0)
            goto out;
        sip4 = &sa.si4.sin_addr;
        sport = ntohs(sa.si4.sin_port);
        bind_print(exe_path, sip4, sport, sockfd);
#if IS_ENABLED(CONFIG_IPV6)
    } else if (AF_INET6 == sock->sk->sk_family) {
        struct in6_addr *sip6;

        if (smith_get_sock_v6(sock, &sa.sa) < 0)
            goto out;
        sip6 = &sa.si6.sin6_addr;
        sport = ntohs(sa.si6.sin6_port);
        bind6_print(exe_path, sip6, sport, sockfd);
#endif
    }

out:
    if (!IS_ERR_OR_NULL(sock))
        sockfd_put(sock);
    if (tid)
        smith_put_tid(tid);
}

static void smith_trace_sysret_connect(long sockfd, int retval)
{
    struct socket *sock = NULL;

    char *exe_path = DEFAULT_RET_STR;
    struct smith_tid *tid = NULL;

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
        if (execve_exe_check(exe_path))
            goto out;
    }

    if (AF_INET == sock->sk->sk_family) {
        __be32 dip4, sip4;

        if (smith_get_sock_v4(sock, &sa.sa) < 0)
            goto out;
        sip4 = sa.si4.sin_addr.s_addr;
        sport = ntohs(sa.si4.sin_port);

        if (smith_get_peer_v4(sock, &sa.sa) < 0)
            goto out;
        dip4 = sa.si4.sin_addr.s_addr;
        dport = ntohs(sa.si4.sin_port);
        connect4_print(dport, dip4, exe_path, sip4, sport, retval);

#if IS_ENABLED(CONFIG_IPV6)
    } else if (AF_INET6 == sock->sk->sk_family) {
        struct in6_addr sip6, *dip6;

        if (smith_get_sock_v6(sock, &sa.sa) < 0)
            goto out;
        sport = ntohs(sa.si6.sin6_port);
        memcpy(&sip6, &sa.si6.sin6_addr, sizeof(struct in6_addr));

        if (smith_get_sock_v6(sock, &sa.sa) < 0)
            goto out;
        dport = ntohs(sa.si6.sin6_port);
        dip6 = &sa.si6.sin6_addr;
        connect6_print(dport, dip6, exe_path, &sip6, sport, retval);
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
        if (execve_exe_check(exe_path))
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
};

static int smith_trace_process_exec(struct execve_data *data, int rc)
{
    int sa_family = -1, dport = 0, sport = 0;
    __be32 dip4, sip4;
    pid_t socket_pid = -1;

    char *pname = DEFAULT_RET_STR;
    char *tmp_stdin = DEFAULT_RET_STR;
    char *tmp_stdout = DEFAULT_RET_STR;
    char *pname_buf = NULL;
    char *pid_tree = NULL;
    char *tty_name = "-1";
    char *exe_path = DEFAULT_RET_STR;
    struct smith_tid *tid = NULL;
    char *stdin_buf = NULL;
    char *stdout_buf = NULL;

    struct in6_addr dip6;
    struct in6_addr sip6;
    struct file *file;
    struct tty_struct *tty = NULL;

    // argv filter check
    if (execve_argv_check(data->argv))
        goto out;

    tty = get_current_tty();
    if(tty && strlen(tty->name) > 0)
        tty_name = tty->name;

    tid = smith_lookup_tid(current);
    if (tid) {
        exe_path = tid->st_img->si_path;
        // exe filter check
        if (execve_exe_check(exe_path))
            goto out;
        pid_tree = tid->st_pid_tree;
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
        fput(file);
    }

    // get stdout
    file = smith_fget_raw(1);
    if (file) {
        stdout_buf = smith_kzalloc(256, GFP_ATOMIC);
        tmp_stdout = smith_d_path(&(file->f_path), stdout_buf, 256);
        fput(file);
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
                     rc);
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
                      rc);
#endif
    } else {
        execve_nosocket_print(pname,
                              exe_path, data->argv,
                              tmp_stdin, tmp_stdout,
                              pid_tree, tty_name,
                              data->ssh_connection,
                              data->ld_preload,
                              data->ld_library_path,
                              rc);
    }

out:
    if (pname_buf)
        smith_kfree(pname_buf);
    if (stdin_buf)
        smith_kfree(stdin_buf);
    if (stdout_buf)
        smith_kfree(stdout_buf);
    if(tty)
        tty_kref_put(tty);
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
    char *parg = NULL, *penv = NULL;

    /* query arg and env mmap sections */
    if (!task->mm)
        return;
    task_lock(task);
    args = task->mm->arg_start;
    larg = task->mm->arg_end - args;
    envs = task->mm->env_start;
    lenv = task->mm->env_end - envs;
    task_unlock(task);

    /* query argv of current task */
    if (larg > 1024)
        larg = 1024;
    if (!larg || !args)
        goto proc_env;
    parg = smith_kzalloc(larg, GFP_ATOMIC);
    if (!parg)
        goto proc_env;
    data->argv= parg;
    i = larg - 1 - smith_copy_from_user(parg, (void *)args, larg - 1);
    if (i <= 1) {
        strcpy(parg, "-1");
    } else {
        while(--i > 0)
            if (!parg[i]) parg[i] = ' ';
    }

proc_env:

    /* now query envion of current task */
    if (lenv > PAGE_SIZE)
        lenv = PAGE_SIZE;
    if (!lenv || !envs)
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
    int sa_family = -1;
    int dport = 0, sport = 0;

    __be32 dip4;
    __be32 sip4;
    pid_t socket_pid = -1;

    char *pname_buf = NULL;
    struct smith_tid *tid = NULL;
    char *pathstr = DEFAULT_RET_STR;
    char *exe_path = DEFAULT_RET_STR;
    char *s_id = DEFAULT_RET_STR;

    struct dentry * file = NULL;
    struct in6_addr dip6;
    struct in6_addr sip6;

    tid = smith_lookup_tid(current);
    if (tid) {
        exe_path = tid->st_img->si_path;
        // exe filter check
        if (execve_exe_check(exe_path))
            goto out;
    }

    pname_buf = smith_kzalloc(PATH_MAX, GFP_ATOMIC);
    if (pname_buf) {
        file = (struct dentry *)p_regs_get_arg2(regs);
        if (IS_ERR_OR_NULL(file))
            goto out;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 38)
        pathstr = dentry_path_raw(file, pname_buf, PATH_MAX);
#else
        pathstr = __dentry_path(file, pname_buf, PATH_MAX);
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
            if (execve_exe_check(exe_path))
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

    tid = smith_lookup_tid(current);
    if (tid)
        exe_path = tid->st_img->si_path;

    dns_print(dport, dip, exe_path, sip, sport, opcode, rcode, query, type);

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

    tid = smith_lookup_tid(current);
    if (tid)
        exe_path = tid->st_img->si_path;

    dns6_print(dport, dip, exe_path, sip, sport, opcode, rcode, query, type);

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

        __get_dns_query(recv_data, query_len, query, &type);
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
        if (smith_get_sock_v6(sock, &sa.sa) >= 0) {
            addr->dport = ntohs(sa.si6.sin6_port);
            memcpy(&addr->dip6, &sa.si6.sin6_addr, sizeof(struct in6_addr));
        } else {
            addr->dport = 0;
            memset(&addr->dip6, 0, sizeof(struct in6_addr));
        }
#endif
    }

    return 0;
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
    if (smith_query_ip_addr(sock, &addr))
        goto out;

    /* we only care port 53 or 5353 */
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
    if (smith_query_ip_addr(sock, &addr))
        goto out;

    /* we only care port 53 or 5353 */
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
        if (execve_exe_check(exe_path))
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
                        fput(vma->vm_mm->exe_file);
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
                    fput(vma->vm_file);
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
        if (execve_exe_check(exe_path))
            goto out;
    }

    if (type)
        rename_print(exe_path, oldori, newori, s_id);
    else
        link_print(exe_path, oldori, newori, s_id);

out:
    if (tid)
        smith_put_tid(tid);
}

int rename_pre_handler(struct kprobe *p, struct pt_regs *regs)
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

    rename_and_link_handler(0, old_path_str, new_path_str, s_id);

    if(old_buf)
        smith_kfree(old_buf);

    if(new_buf)
        smith_kfree(new_buf);

    return 0;
}

/* create new session id (-1 if got errors) */
static void smith_trace_sysret_setsid(int ret)
{
    char *exe_path = DEFAULT_RET_STR;
    struct smith_tid *tid = NULL;

    tid = smith_lookup_tid(current);
    if (tid) {
        exe_path = tid->st_img->si_path;
        // exe filter check
        if (execve_exe_check(exe_path))
            goto out;
    }

    setsid_print(exe_path, ret);

out:
    if (tid)
        smith_put_tid(tid);
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
        if (execve_exe_check(exe_path))
            goto out;
    }

    prctl_print(exe_path, PR_SET_NAME, newname);

out:
    smith_kfree(newname);
    if (tid)
        smith_put_tid(tid);
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
    if (!len || len > PATH_MAX)
        goto out;

    tid = smith_lookup_tid(current);
    if (tid) {
        exe_path = tid->st_img->si_path;
        // exe filter check
        if (execve_exe_check(exe_path))
            goto out;
    }

    fdname = smith_kmalloc((len + 1) * sizeof(char), GFP_ATOMIC);
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
    if (!filename_len || filename_len > PATH_MAX)
        return 0;

    filename = smith_kmalloc((filename_len + 1) * sizeof(char), GFP_ATOMIC);
    if(!filename)
        return 0;

    if(smith_copy_from_user(filename, (char __user *)filename_ori, filename_len))
        goto out;

    filename[filename_len] = '\0';

    tid = smith_lookup_tid(current);
    if (tid) {
        exe_path = tid->st_img->si_path;
        // exe filter check
        if (execve_exe_check(exe_path))
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
        if (execve_exe_check(exe_path))
            goto out;
    }

    pname_buf = smith_kzalloc(PATH_MAX, GFP_ATOMIC);
    file_path = smith_d_path(&(file)->f_path, pname_buf, PATH_MAX);

    write_print(exe_path, file_path, kbuf);

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
    int filename_len = 0;

    char *exe_path = DEFAULT_RET_STR;
    struct smith_tid *tid = NULL;
    char *filename = NULL;
    char __user *filename_ori;

    filename_ori = (void *)p_get_arg2_syscall(regs);
    if (IS_ERR_OR_NULL(filename_ori))
        return 0;

    filename_len = smith_strnlen_user((char __user *)filename_ori, PATH_MAX);
    if (!filename_len || filename_len > PATH_MAX)
        return 0;

    filename = smith_kmalloc((filename_len + 1) * sizeof(char), GFP_ATOMIC);
    if(!filename)
        return 0;

    if(smith_copy_from_user(filename, (char __user *)filename_ori, filename_len))
    goto out;

    filename[filename_len] = '\0';

    tid = smith_lookup_tid(current);
    if (tid) {
        exe_path = tid->st_img->si_path;
        // exe filter check
        if (execve_exe_check(exe_path))
            goto out;
    }

    open_print(exe_path, filename, (int)p_get_arg3_syscall(regs),
               (umode_t)p_get_arg4_syscall(regs));

out:
    if (tid)
        smith_put_tid(tid);
    smith_kfree(filename);

    return 0;
}

int file_permission_handler(struct kprobe *p, struct pt_regs *regs)
{
    int mask = 0;
    char *pname_buf = NULL;
    struct smith_tid *tid = NULL;
    char *file_path = DEFAULT_RET_STR;
    char *exe_path = DEFAULT_RET_STR;
    struct file *file = NULL;
    struct dentry *parent = NULL;
    struct dentry *self = NULL;

    if (!current->mm || irq_count())
        return 0;

    file = (struct file *)p_regs_get_arg1(regs);
    if (IS_ERR_OR_NULL(file))
        return 0;

    if (S_ISDIR(file_inode(file)->i_mode))
        return 0;

    mask = (int)p_regs_get_arg2(regs);
    if(mask == WRITE || mask == MAY_WRITE)
        mask = 2;
    else if (mask == READ || mask == MAY_READ)
        mask = 4;
    else
        return 0;

    self = file->f_path.dentry;
    if(IS_ERR_OR_NULL(self) || IS_ERR_OR_NULL(self->d_sb))
        return 0;

    parent = self->d_parent;
    if(!parent)
        return 0;

    tid = smith_lookup_tid(current);
    if (tid) {
        exe_path = tid->st_img->si_path;
        // exe filter check
        if (execve_exe_check(exe_path))
            goto out;
    }

    if (file_notify_check(smith_query_sb_uuid(self->d_sb), parent->d_inode->i_ino, "*", 1, mask) || 
        file_notify_check(smith_query_sb_uuid(self->d_sb), parent->d_inode->i_ino, self->d_name.name, self->d_name.len, mask)) {
        pname_buf = smith_kzalloc(PATH_MAX, GFP_ATOMIC);
        file_path = smith_d_path(&(file)->f_path, pname_buf, PATH_MAX);

        if (mask == 2)
            file_permission_write_print(exe_path, file_path, self->d_sb->s_id);
        else
            file_permission_read_print(exe_path, file_path, self->d_sb->s_id);
    }

out:
    if (tid)
        smith_put_tid(tid);
    if (pname_buf)
        smith_kfree(pname_buf);

    return 0;
}

//int inode_permission_handler(struct kprobe *p, struct pt_regs *regs)
//{
//    int mask;
//    char *pname_buf = NULL;
//    char *buffer = NULL;
//    char *file_path = DEFAULT_RET_STR;
//    char *exe_path = DEFAULT_RET_STR;
//    struct dentry* tmp_dentry = NULL;
//    struct inode *inode = NULL;
//    struct dentry *parent = NULL;
//
//    if (!current->mm || irq_count())
//        return 0;
//
//    inode = (struct inode *)p_regs_get_arg1(regs);
//    if (IS_ERR_OR_NULL(inode))
//        return 0;
//
//    if (S_ISDIR(inode->i_mode))
//        return 0;
//
//    mask = (int)p_regs_get_arg2(regs);
//    if(mask & WRITE || mask & MAY_WRITE)
//        mask = 2;
//    else if (mask & READ || mask & MAY_READ)
//        mask = 4;
//    else
//        return 0;
//
///*
// * d_alias could be a member of dentry or dentry.d_u after v3.2
// * existing kernels are always updated to latest, so here we're
// * using dentry.d_u.d_alias instead of dentry.d_alias
// *
// * possible option (assuming hardlinks are rare things):
// *     don't enum all entries, just grab one with d_find_alias
// */
//
//#ifdef CENTOS_CHECK
//#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 18, 0)
//    if (!hlist_empty(&inode->i_dentry)) {
//        hlist_for_each_entry(tmp_dentry, &inode->i_dentry, d_u.d_alias)
//#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
//    if (!hlist_empty(&inode->i_dentry)) {
//        hlist_for_each_entry(tmp_dentry, &inode->i_dentry, d_alias)
//#else
//    if (!list_empty(&inode->i_dentry)) {
//        list_for_each_entry(tmp_dentry, &inode->i_dentry, d_alias)
//#endif
//#else
//#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 6, 0)
//    if (!hlist_empty(&inode->i_dentry)) {
//        hlist_for_each_entry(tmp_dentry, &inode->i_dentry, d_u.d_alias)
//#else
//    if (!list_empty(&inode->i_dentry)) {
//# if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 2, 66)
//        list_for_each_entry(tmp_dentry, &inode->i_dentry, d_u.d_alias)
//# else
//        list_for_each_entry(tmp_dentry, &inode->i_dentry, d_alias)
//# endif
//#endif
//#endif
//        {
//            parent = tmp_dentry->d_parent;
//            if(!parent)
//                continue;
//
//            if (file_notify_check(smith_query_sb_uuid(tmp_dentry->d_sb), parent->d_inode->i_ino, "*", 1, mask) ||
//                file_notify_check(smith_query_sb_uuid(tmp_dentry->d_sb), parent->d_inode->i_ino, tmp_dentry->d_name.name, tmp_dentry->d_name.len, mask)) {
//                buffer = smith_kzalloc(PATH_MAX, GFP_ATOMIC);
//                exe_path = smith_get_exe_file(buffer, PATH_MAX);
//
//                pname_buf = smith_kzalloc(PATH_MAX, GFP_ATOMIC);
//                if(pname_buf) {
//#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 38)
//                    file_path = dentry_path_raw(tmp_dentry, pname_buf, PATH_MAX);
//#else
//                    file_path = __dentry_path(tmp_dentry, pname_buf, PATH_MAX);
//#endif
//                }
//
//                if(IS_ERR(file_path))
//                    file_path = DEFAULT_RET_STR;
//
//                if (mask == 2)
//                    file_permission_write_print(exe_path, file_path, inode->i_sb->s_id);
//                else
//                    file_permission_read_print(exe_path, file_path, inode->i_sb->s_id);
//            }
//        }
//    }
//
//    if (buffer)
//        smith_kfree(buffer);
//
//    if (pname_buf)
//        smith_kfree(pname_buf);
//
//    return 0;
//}


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
        if (execve_exe_check(exe_path))
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

#if defined(__NR_chmod) || IS_ENABLED(CONFIG_IA32_EMULATION)
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
        if (execve_exe_check(exe_path))
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

static void smith_trace_sysent_nanosleep(long tsu)
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
        if (execve_exe_check(exe_path))
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
        if (execve_exe_check(exe_path))
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
        if (execve_exe_check(exe_path))
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
        if (execve_exe_check(exe_path))
            goto out;
    }

    tgkill_print(exe_path, tgid, pid, sig, ret);

out:
    if (tid)
        smith_put_tid(tid);
}


void delete_file_handler(int type, char *path)
{
    struct smith_tid *tid = NULL;
    char *exe_path = DEFAULT_RET_STR;

    tid = smith_lookup_tid(current);
    if (tid) {
        exe_path = tid->st_img->si_path;
        // exe filter check
        if (execve_exe_check(exe_path))
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

int security_path_rmdir_pre_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
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

int rm_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    int uid = 0;
    uid = __get_current_uid();
    if (FAKE_RM && uid != 0) {
        smith_regs_set_return_value(regs, 1);
    }
    return 0;
}

int security_path_unlink_pre_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
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

void exit_handler(int type)
{
    struct smith_tid *tid = NULL;
    char *exe_path = DEFAULT_RET_STR;

    tid = smith_lookup_tid(current);
    if (tid) {
        exe_path = tid->st_img->si_path;
        // exe filter check
        if (execve_exe_check(exe_path))
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

int exit_pre_handler(struct kprobe *p, struct pt_regs *regs)
{
    exit_handler(1);
    return 0;
}

int exit_group_pre_handler(struct kprobe *p, struct pt_regs *regs)
{
    exit_handler(0);
    return 0;
}

int do_init_module_pre_handler(struct kprobe *p, struct pt_regs *regs)
{
    char *pid_tree = NULL;
    struct smith_tid *tid = NULL;
    char *exe_path = DEFAULT_RET_STR;
    char *pname_buf = NULL;
    char *pname = NULL;
    void *tmp_mod;
    struct module *mod;

    tmp_mod = (void *) p_regs_get_arg1(regs);
    if (IS_ERR_OR_NULL(tmp_mod))
        return 0;
    mod = (struct module *)tmp_mod;

    tid = smith_lookup_tid(current);
    if (tid) {
        exe_path = tid->st_img->si_path;
        // exe filter check
        if (execve_exe_check(exe_path))
            goto out;
        pid_tree = tid->st_pid_tree;
    }

    pname_buf = smith_kzalloc(PATH_MAX, GFP_ATOMIC);
    pname = smith_d_path(&current->fs->pwd, pname_buf, PATH_MAX);

    smith_check_privilege_escalation(PID_TREE_LIMIT, pid_tree);
    do_init_module_print(exe_path, mod->name, pid_tree, pname);

out:
    if (tid)
        smith_put_tid(tid);
    if (pname_buf)
        smith_kfree(pname_buf);
    return 0;
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
        if (execve_exe_check(exe_path))
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
        if (execve_exe_check(exe_path))
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

struct kprobe do_init_module_kprobe = {
        .symbol_name = "do_init_module",
        .pre_handler = do_init_module_pre_handler,
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

struct kprobe file_permission_kprobe = {
        .symbol_name = "security_file_permission",
        .pre_handler = file_permission_handler,
};

//struct kprobe inode_permission_kprobe = {
//        .symbol_name = "security_inode_permission",
//        .pre_handler = inode_permission_handler,
//};

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

int register_do_init_module_kprobe(void)
{
    int ret;
    ret = register_kprobe(&do_init_module_kprobe);

    if (ret == 0)
        do_init_module_kprobe_state = 0x1;

    return ret;
}

void unregister_do_init_module_kprobe(void)
{
    unregister_kprobe(&do_init_module_kprobe);
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

int register_file_permission_kprobe(void)
{
    int ret;
    ret = register_kprobe(&file_permission_kprobe);
    if (ret == 0)
        file_permission_kprobe_state = 0x1;

    return ret;
}

void unregister_file_permission_kprobe(void)
{
    unregister_kprobe(&file_permission_kprobe);
}

//int register_inode_permission_kprobe(void)
//{
//    int ret;
//    ret = register_kprobe(&inode_permission_kprobe);
//    if (ret == 0)
//        inode_permission_kprobe_state = 0x1;
//
//    return ret;
//}
//
//void unregister_inode_permission_kprobe(void)
//{
//    unregister_kprobe(&inode_permission_kprobe);
//}

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
    if (UDEV_NOTIFIER == 1) {
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

    if (do_init_module_kprobe_state == 0x1)
        unregister_do_init_module_kprobe();

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

    if (file_permission_kprobe_state == 0x1)
        unregister_file_permission_kprobe();

//    if (inode_permission_kprobe_state == 0x1)
//        unregister_inode_permission_kprobe();

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
        CALL_USERMODEHELPER = 1;
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

    if (UDEV_NOTIFIER == 1) {
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

    if (FILE_PERMISSION_HOOK == 1) {
        ret = register_file_permission_kprobe();
        if (ret < 0)
            printk(KERN_INFO "[ELKEID] file_permission register_kprobe failed, returned %d\n", ret);

//        ret = register_inode_permission_kprobe();
//        if (ret < 0)
//            printk(KERN_INFO "[ELKEID] inode_permission register_kprobe failed, returned %d\n", ret);
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

    if (CALL_USERMODEHELPER == 1) {
        ret = register_call_usermodehelper_exec_kprobe();
        if (ret < 0)
            printk(KERN_INFO "[ELKEID] call_usermodehelper_exec register_kprobe failed, returned %d\n", ret);
    }

    if (DO_INIT_MODULE_HOOK == 1) {
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

/*
 * rbtree defs for exectuable images
 */
struct tt_rb g_rb_img;  /* rbtree of cached images */
LIST_HEAD(g_lru_img);   /* lru list of cached images */

#define SMITH_IMG_REAPER_TIMEOUT  (600)     /* 10 minutes */
#define SMITH_IMG_MAX_INSTANCES   (2048)    /* max cached imgs */

/*
 * callbacks for img-cache
 */

static char *smith_build_path(struct smith_img *img)
{
    char *buf = img->si_buf, *path;
    int len = 256;

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
    img->si_cts = de->d_inode->i_ctime;
    img->si_path = smith_build_path(img);
    if (!img->si_path)
        return -ENOMEM;

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
    if (img2->si_cts.tv_sec > img1->si_cts.tv_sec)
        return 1;
    if (img2->si_cts.tv_sec < img1->si_cts.tv_sec)
        return -1;
    if (img2->si_cts.tv_nsec > img1->si_cts.tv_nsec)
        return 1;
    if (img2->si_cts.tv_nsec < img1->si_cts.tv_nsec)
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
    } while (--count > SMITH_IMG_MAX_INSTANCES);
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
        img->si_age = smith_get_seconds() + SMITH_IMG_REAPER_TIMEOUT;
        atomic_dec(&img->si_node.refs);
        return;
    }

    if (atomic_add_unless(&img->si_node.refs, -1, 1))
        return;

    write_lock(&g_rb_img.lock);
    list_del_init(&img->si_link);
    if (0 == atomic_dec_return(&img->si_node.refs)) {
        img->si_age = smith_get_seconds() + SMITH_IMG_REAPER_TIMEOUT;
        list_add_tail(&img->si_link, &g_lru_img);
    }
    write_unlock(&g_rb_img.lock);

    smith_drop_head_imgs(&g_rb_img);
}

static int smith_build_key(struct task_struct *task, struct smith_img *img)
{
    struct dentry *de;

    img->si_exe = smith_get_task_exe_file(task);
    if (!img->si_exe)
        return -ENOENT;

    de = img->si_exe->f_path.dentry;
    img->si_sb = de->d_sb;
    img->si_ino = de->d_inode->i_ino;
    img->si_cts = de->d_inode->i_ctime;

    return 0;
}

struct smith_img *smith_find_img(struct task_struct *task)
{
    struct smith_img img, *si = NULL;
    struct tt_node *tnod = NULL;
    int rc = 0;

    /* if succeeds, will return with si_exe grabbed */
    rc = smith_build_key(task, &img);
    if (rc)
        goto errorout;

    /* check whether the image was already inserted ? */
    read_lock(&g_rb_img.lock);
    tnod = tt_rb_lookup_nolock(&g_rb_img, &img);
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
    tnod = tt_rb_insert_key_nolock(&g_rb_img, &img.si_node);
    if (tnod) {
        atomic_inc(&tnod->refs);
        si = container_of(tnod, struct smith_img, si_node);
    }
    write_unlock(&g_rb_img.lock);

errorout:
    if (img.si_exe)
        fput(img.si_exe);
    return si;
}

static void smith_show_img(struct tt_node *tnod)
{
    struct smith_img *img;

    if (!tnod)
        return;

    img = container_of(tnod, struct smith_img, si_node);
    printk("img: %px (%s) sb: %px ino: %lu refs: %d nimgs: %u.\n",
            img, img->si_path, img->si_sb, img->si_ino,
            atomic_read(&img->si_node.refs),
            atomic_read(&g_rb_img.count));
}

void smith_enum_img(void)
{
    printk("enum all imgs:\n");
    tt_rb_enum(&g_rb_img, smith_show_img);
}

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

#define PID_TREE_MATEDATA_LEN (10 /* len of max uint32_t */ + 2 + TASK_COMM_LEN)
static char *smith_get_pid_tree(struct task_struct *task)
{
    char *tree = NULL;
    char pid[24];
    int n;

    get_task_struct(task);
    n = smith_query_parents(task);
    if (n > PID_TREE_LIMIT)
        n = PID_TREE_LIMIT;
    if (n <= 0)
        n = 1;

    tree = smith_kzalloc(n * PID_TREE_MATEDATA_LEN, GFP_ATOMIC);
    if (!tree)
        goto out;

    snprintf(pid, 24, "%d", task->tgid);
    strcat(tree, pid);
    strcat(tree, ".");
    strcat(tree, current->comm);

    while (--n > 0) {

        struct task_struct *old_task = task;
        rcu_read_lock();
        task = smith_get_task_struct(rcu_dereference(task->real_parent));
        rcu_read_unlock();
        smith_put_task_struct(old_task);
        if (!task || task->pid == 0)
            break;

        snprintf(pid, 24, "%d", task->tgid);
        strcat(tree, "<");
        strcat(tree, pid);
        strcat(tree, ".");
        strcat(tree, task->comm);
    }

out:
    if (task)
        smith_put_task_struct(task);

    return tree;
}

static void smith_update_pid_tree(char *pid_tree, char *comm_new)
{
    char *s = NULL;
    int o = 0, i = 1, n;

    if (!pid_tree)
        return;

    /* locate 1st '.' in pid-tree */
    while (!s && pid_tree[i]) {
        if (pid_tree[i++] == '.')
            s = &pid_tree[i];
    }
    if (!s)
        return;
    while (s[++o] != '<' && s[o]);

    n = strlen(comm_new);
    if (o != n) {
        int l = strlen(pid_tree) - o - (int)(s - pid_tree);
        memmove(s + n, s + o, l + 1); /* extra tailing 0 */
    }
    memcpy(s, comm_new, n);
}

static int smith_build_tid(struct smith_tid *tid, struct task_struct *task)
{
    tid->st_start = smith_task_start_time(task);
    tid->st_pid = task->pid;
    /* flags was already inited during allocation */
    tid->st_node.flag_newsid = smith_is_anchor(task->parent);
    tid->st_sid = task_session_nr_ns(task, &init_pid_ns);
    tid->st_img = smith_find_img(task);
    if (!tid->st_img)
        return -ENOMEM;
    tid->st_pid_tree = smith_get_pid_tree(task);
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
    return !(tid->st_start == smith_task_start_time(task) &&
             tid->st_pid == task->pid);
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
    printk("pid: %u sid: %u task: %s mnt: %llu refs: %d\n",
            tid->st_pid, tid->st_sid, tid->st_pid_tree,
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
    return (task->pid & hr->nlists);
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
    smith_update_pid_tree(tid->st_pid_tree, task->comm);

    /* build img for execed task */
    exe = smith_find_img(task);
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
 * Here we are using process_exec tracepoint as a suppliment to handle exec events.
 * Lucily that kernels with ARM64 support are newer than 3.4.
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

    /* try to cleanup current taks's tid record */
    smith_drop_tid(task);
}

#include <linux/thread_info.h>
#include <asm/syscall.h> /* syscall_get_nr() */
#include <asm/unistd.h> /* __NR_syscall defintions */

TRACEPOINT_PROBE(smith_trace_sys_exit, struct pt_regs *regs, long ret)
{
    long id = syscall_get_nr(current, regs);

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
             * create new session id
             */
            case 66 /*__NR_ia32_setsid */:
                if (SETSID_HOOK)
                    smith_trace_sysret_setsid(ret);
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
                    smith_trace_sysent_nanosleep(regs->bx);
                break;

            /*
             * prctl: PR_SET_NAME
             */
            case 172 /* __NR_ia32_prctl */:
                if (PRCTL_HOOK)
                    smith_trace_sysent_prctl(regs->bx, (char *)regs->cx);
                break;

            /*
             * memfd_create
             */
            case 356 /* __NR_ia32_memfd_create */:
                if (MEMFD_CREATE_HOOK)
                    smith_trace_sysret_memfd_create((char __user *)regs->bx, regs->cx, ret);

                break;

            /*
             * socket related
             */

            case 102 /* __NR_ia32_socketcall */:
                if (CONNECT_HOOK && SYS_CONNECT == regs->bx) {
                    int32_t sockfd;
                    if (copy_from_user(&sockfd, (void *)regs->cx, sizeof(sockfd)))
                        break;
                    smith_trace_sysret_connect(sockfd, ret);
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
                    smith_trace_sysret_connect(regs->bx, ret);
                break;

            case 364 /* __NR_ia32_accept4 */:
                if (ACCEPT_HOOK)
                    smith_trace_sysret_accept(ret);
                break;

#ifdef           __NR_ia32_recv
            case __NR_ia32_recv:
#endif
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

        return;
    }
#endif

#if defined(CONFIG_ARM64) && defined(CONFIG_COMPAT)
    if (ESR_ELx_EC_SVC32 == ESR_ELx_EC(read_sysreg(esr_el1))) {
        /* just ignore syscalls from ARM32 apps for now */
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
         * create new session id
         */
        case __NR_setsid:
            if (SETSID_HOOK)
                smith_trace_sysret_setsid(ret);
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
                smith_trace_sysent_nanosleep(p_regs_get_arg1_of_syscall(regs));
            break;

        /*
         * prctl: PR_SET_NAME
         */
        case __NR_prctl:
            if (PRCTL_HOOK)
                smith_trace_sysent_prctl(p_regs_get_arg1_of_syscall(regs),
                                         (char __user *)p_regs_get_arg2_syscall(regs));
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
         * socket related
         */

#ifdef       __NR_socketcall
        case __NR_socketcall:
            if (CONNECT_HOOK && SYS_CONNECT == p_regs_get_arg1_of_syscall(regs)) {
                long sockfd;
                if (copy_from_user(&sockfd, p_regs_get_arg2_syscall(regs), sizeof(sockfd)))
                    break;
                smith_trace_sysret_connect(sockfd, ret);
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
                smith_trace_sysret_connect(p_regs_get_arg1_of_syscall(regs), ret);
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
                smith_trace_sysret_recvmsg(p_regs_get_arg1_syscall(regs),
                                           p_regs_get_arg2_syscall(regs), ret);
            break;

        default:
            break;
    }
}

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
    {.name = "sys_exit", .handler = smith_trace_sys_exit},

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
    if (ntids > (SMITH_IMG_MAX_INSTANCES << 1))
        ntids = SMITH_IMG_MAX_INSTANCES << 1;
    nimgs = SMITH_IMG_MAX_INSTANCES;
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

    /* register callbacks for the tracepoints of our interest */
    for (i = 0; i < NUM_TRACE_POINTS; i++) {
        rc = smith_register_tracepoint(&g_smith_tracepoints[i]);
        if (rc)
            goto clean_trace;
    }

    /* enum active tasks and build tid for each user task */
    smith_process_tasks(&g_hlist_tid);

errorout:
    return rc;

clean_trace:
    while (--i >= 0)
        smith_unregister_tracepoint(&g_smith_tracepoints[i]);
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

    hlist_fini(&g_hlist_tid);
    tt_rb_fini(&g_rb_img);
}

static void __init smith_init_systemd_ns(void)
{
    struct pid *pid_struct;
    struct task_struct *task;
    struct path root;

    pid_struct = find_get_pid(1);
    task = pid_task(pid_struct,PIDTYPE_PID);

    smith_get_task_struct(task);
    root = task->fs->root;
    if (root.mnt)
        ROOT_MNT_SB = root.mnt->mnt_sb;
    if (task->nsproxy)
        ROOT_MNT_NS = task->nsproxy->mnt_ns;
    ROOT_MNT_NS_ID = smith_query_mntns_id(task);
    smith_put_task_struct(task);
    put_pid(pid_struct);
}

static int __init kprobe_hook_init(void)
{
    int ret;

#if defined(MODULE)
    printk(KERN_INFO "[ELKEID] kmod %s (%s) loaded.\n",
           THIS_MODULE->name, THIS_MODULE->version);
#endif

    ret = kernel_symbols_init();
    if (ret)
        return ret;

    smith_init_systemd_ns();

    /* need ROOT_MNT_NS inited by smith_init_systemd_ns */
    ret = smith_tid_init();
    if (ret)
        return ret;

    ret = filter_init();
    if (ret) {
        smith_tid_fini();
        return ret;
    }

    printk(KERN_INFO "[ELKEID] Filter Init Success \n");

#if (EXIT_PROTECT == 1) && defined(MODULE)
    exit_protect_action();
#endif

    install_kprobe();

    printk(KERN_INFO "[ELKEID] SANDBOX: %d\n", SANDBOX);
    printk(KERN_INFO
    "[ELKEID] register_kprobe success: connect_hook: %d,load_module_hook:"
    " %d,execve_hook: %d,call_usermodehekoer_hook: %d,bind_hook: %d,create_file_hook: %d,file_permission_hook: %d, ptrace_hook: %d, update_cred_hook:"
    " %d, dns_hook: %d, accept_hook:%d, mprotect_hook: %d, chmod_hook: %d, mount_hook: %d, link_hook: %d, memfd_create: %d, rename_hook: %d,"
    "setsid_hook:%d, prctl_hook:%d, open_hook:%d, udev_notifier:%d, nanosleep_hook:%d, kill_hook: %d, rm_hook: %d, "
    " exit_hook: %d, write_hook: %d, EXIT_PROTECT: %d\n",
            CONNECT_HOOK, DO_INIT_MODULE_HOOK, EXECVE_HOOK, CALL_USERMODEHELPER, BIND_HOOK,
            CREATE_FILE_HOOK, FILE_PERMISSION_HOOK, PTRACE_HOOK, UPDATE_CRED_HOOK, DNS_HOOK,
            ACCEPT_HOOK, MPROTECT_HOOK, CHMOD_HOOK, MOUNT_HOOK, LINK_HOOK, MEMFD_CREATE_HOOK, RENAME_HOOK, SETSID_HOOK,
            PRCTL_HOOK, OPEN_HOOK, UDEV_NOTIFIER, NANOSLEEP_HOOK, KILL_HOOK, RM_HOOK, EXIT_HOOK, WRITE_HOOK,
            EXIT_PROTECT);

    return 0;
}

static void kprobe_hook_exit(void)
{
    /* cleaning up kprobe hook points */
    uninstall_kprobe();
    filter_cleanup();

    /* cleaning up tid & img cache */
    smith_tid_fini();

    printk(KERN_INFO "[ELKEID] uninstall_kprobe success\n");
}

KPROBE_INITCALL(kprobe_hook, kprobe_hook_init, kprobe_hook_exit);

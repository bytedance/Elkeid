/* SPDX-License-Identifier: GPL-2.0 */
#ifndef UTIL_H
#define UTIL_H

#include <linux/version.h>
#include <linux/sched.h>
#include <linux/preempt.h>
#include <linux/fsnotify.h>
#include <linux/slab.h>
#include <linux/mm_types.h>
#include <linux/dcache.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/nsproxy.h>
#include <linux/pid_namespace.h>
#include <linux/ctype.h>
#include <linux/cred.h>
#include <linux/kthread.h>

/*
 * constants & globals
 */

#define DEFAULT_RET_STR "-2"
#define NAME_TOO_LONG "-4"
#define PID_TREE_MATEDATA_LEN  32

static unsigned int ROOT_PID_NS_INUM;

/*
 * wrapper of kernel memory allocation routines
 */

#define smith_kmalloc(size, flags)  kmalloc(size, (flags) | __GFP_NOWARN)
#define smith_kzalloc(size, flags)  kmalloc(size, (flags) | __GFP_NOWARN | __GFP_ZERO)
#define smith_kfree(ptr)            do { void * _ptr = (ptr); if (_ptr) kfree(_ptr);} while(0)

/*
 * common routines
 */
extern unsigned long smith_kallsyms_lookup_name(const char *);

extern char *__dentry_path(struct dentry *dentry, char *buf, int buflen);

extern u8 *smith_query_sb_uuid(struct super_block *sb);

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
extern void (*__smith_put_task_struct)(struct task_struct *t);
static inline void smith_put_task_struct(struct task_struct *t)
{
	if (atomic_dec_and_test(&t->usage))
		__smith_put_task_struct(t);
}
#else
#define smith_put_task_struct(tsk)  put_task_struct(tsk)
#endif

#if defined(KGID_STRUCT_CHECK) && (!defined(KGID_CONFIG_CHECK) || \
    (defined(KGID_CONFIG_CHECK) && defined(CONFIG_UIDGID_STRICT_TYPE_CHECKS)))
/* vanilla kernels >= 3.5.0, but ubuntu backported for 3.4 */
# define _XID_VALUE(x)  (x).val
#else
# ifndef GLOBAL_ROOT_UID
# define GLOBAL_ROOT_UID (0)
# endif
# ifndef GLOBAL_ROOT_GID
# define GLOBAL_ROOT_GID (0)
# endif
# ifndef uid_eq
# define uid_eq(o, n) ((o) == (n))
# endif
# ifndef gid_eq
# define gid_eq(o, n) ((o) == (n))
# endif
# define _XID_VALUE(x)  (x)
#endif

static __always_inline int check_cred(const struct cred *current_cred, const struct cred *parent_cred)
{
    if (uid_eq(current_cred->uid, GLOBAL_ROOT_UID) ||
        uid_eq(current_cred->euid, GLOBAL_ROOT_UID) ||
        uid_eq(current_cred->suid, GLOBAL_ROOT_UID) ||
        uid_eq(current_cred->fsuid, GLOBAL_ROOT_UID) ||
        gid_eq(current_cred->gid, GLOBAL_ROOT_GID) ||
        gid_eq(current_cred->sgid, GLOBAL_ROOT_GID) ||
        gid_eq(current_cred->egid, GLOBAL_ROOT_GID) ||
        gid_eq(current_cred->fsgid, GLOBAL_ROOT_GID))
        if(!uid_eq(current_cred->uid,  parent_cred->uid)  ||
            !uid_eq(current_cred->euid,  parent_cred->euid) ||
            !uid_eq(current_cred->suid,  parent_cred->suid) ||
            !uid_eq(current_cred->fsuid, parent_cred->fsuid) ||
            !gid_eq(current_cred->gid, parent_cred->gid) ||
            !gid_eq(current_cred->sgid, parent_cred->sgid) ||
            !gid_eq(current_cred->egid, parent_cred->egid) ||
            !gid_eq(current_cred->fsgid, parent_cred->fsgid))
            if(!(uid_eq(parent_cred->uid, GLOBAL_ROOT_UID) &&
                uid_eq(parent_cred->euid, GLOBAL_ROOT_UID) &&
                uid_eq(parent_cred->suid, GLOBAL_ROOT_UID) &&
                uid_eq(parent_cred->fsuid, GLOBAL_ROOT_UID) &&
                gid_eq(parent_cred->gid, GLOBAL_ROOT_GID) &&
                gid_eq(parent_cred->sgid, GLOBAL_ROOT_GID) &&
                gid_eq(parent_cred->egid, GLOBAL_ROOT_GID) &&
                gid_eq(parent_cred->fsgid, GLOBAL_ROOT_GID)))
                return 1;
    return 0;
}

static __always_inline void save_cred_info(unsigned int p_cred_info[], const struct cred *parent_cred)
{
    p_cred_info[0] = _XID_VALUE(parent_cred->uid);
    p_cred_info[1] = _XID_VALUE(parent_cred->euid);
    p_cred_info[2] = _XID_VALUE(parent_cred->suid);
    p_cred_info[3] = _XID_VALUE(parent_cred->fsuid);

    p_cred_info[4] = _XID_VALUE(parent_cred->gid);
    p_cred_info[5] = _XID_VALUE(parent_cred->egid);
    p_cred_info[6] = _XID_VALUE(parent_cred->sgid);
    p_cred_info[7] = _XID_VALUE(parent_cred->fsgid);
}

static inline int __get_current_uid(void) {
    return _XID_VALUE(current->real_cred->uid);
}

static inline int __get_current_euid(void) {
    return _XID_VALUE(current->real_cred->euid);
}

/*
 * WARNING:
 *     s must be null-terminated
 */
static inline char *smith_strim(char *s)
{
    size_t size = strlen(s);
    char *end, *first = s;

    if (!size)
        return s;

    end = s + size - 1;
    while (end >= s && isspace(*end))
        end--;
    *(++end) = '\0';

    while (isspace(*first))
        first++;

    if (first > s)
        memmove(s, first, end + 1 - first);

    return s;
}

/*
 * Kernel >= 4.2 (4.2.0 included):
 *     current->pagefault_disabled introduced, __do_page_fault will cease
 *     the process of user-mode address if this value is non-zero or the
 *     context is in irq (in_atomic)
 *
 * Kernel < 4.2:
 *     __do_page_fault just cease when atomic-context is detected when
 *     processing page fault due to user-mode address
 *
 *     WARNING: pagefault_enable could trigger re-schedulinga, that's not
 *     allowed under atomic-context of kprobe callback
 */
static inline void smith_pagefault_disable(void)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 2, 0)
    pagefault_disable();
#else
    preempt_disable();
#endif
#if 0
    preempt_count_inc();
    /*
     * make sure to have issued the store before a pagefault
     * can hit.
     */
    barrier();
#endif
}

/* from kernel 3.14.0, preempt_enable_no_resched() only defined for kernel */
static inline void smith_pagefault_enable(void)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 2, 0)
    pagefault_enable();
#elif defined(CONFIG_PREEMPT)
#ifdef preempt_enable_no_resched
    preempt_enable_no_resched();
#else
    /*
     * make sure to issue those last loads/stores before enabling
     * the pagefault handler again.
     */
    barrier();
    preempt_count_dec();
#endif
#else /* < 4.2.0 && !CONFIG_PREEMPT */
    preempt_enable();
#endif
}

static __always_inline long __must_check smith_strnlen_user(const char __user *str, long count)
{
    long res;
    smith_pagefault_disable();
    res = strnlen_user(str,count);
    smith_pagefault_enable();
    return res;
}

static __always_inline unsigned long __must_check smith_copy_from_user(void *to, const void __user *from, unsigned long n)
{
    unsigned long res;
    smith_pagefault_disable();
    res = __copy_from_user_inatomic(to, from, n);
    smith_pagefault_enable();
    return res;
}

/* get_user() will call might_fault(), which violates
   the rules of atomic context (introdcued by kprobe) */
#define smith_get_user(x, ptr)                                  \
({                                                              \
    unsigned long __val = 0;                                    \
    int __ret;                                                  \
    smith_pagefault_disable();                                  \
    __ret = __copy_from_user_inatomic(&__val, ptr,              \
                                      sizeof(*(ptr)));          \
    smith_pagefault_enable();                                   \
    (x) = (__typeof__(*(ptr)))__val;                            \
    __ret;                                                      \
})

static inline void *__get_dns_query(unsigned char *data, int index, char *res) {
    int i;
    int flag = -1;
    int len;
    len = strlen(data + index);

    for (i = 0; i < len; i++) {
        if (flag == -1) {
            flag = (data + index)[i];
        } else if (flag == 0) {
            flag = (data + index)[i];
            res[i - 1] = 46;
        } else {
            res[i - 1] = (data + index)[i];
            flag = flag - 1;
        }
    }
    return 0;
}

static inline unsigned int __get_sessionid(void) {
    unsigned int sessionid = 0;
#ifdef CONFIG_AUDITSYSCALL
    sessionid = current->sessionid;
#endif
    return sessionid;
}

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

static inline unsigned int __get_pid_ns_inum(void) {
    unsigned int inum;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 19, 0)
    inum = current->nsproxy->pid_ns_for_children->ns.inum;
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3, 11, 0)
    inum = current->nsproxy->pid_ns_for_children->proc_inum;
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3, 8, 0)
    inum = current->nsproxy->pid_ns->proc_inum;
#else
    /*
     * For kernels < 3.8.0, id for pid namespaces isn't defined.
     * So here we are using fixed values, no emulating any more,
     * previously we were using image file's inode number.
     */
    inum = 0xEFFFFFFCU /* PROC_PID_INIT_INO */;
#endif
    return inum;
}

static inline int __get_pgid(void) {
    return task_pgrp_nr_ns(current, &init_pid_ns);
}

static inline int __get_sid(void) {
    return task_session_nr_ns(current, &init_pid_ns);
}

#endif /* UTIL_H */

/* SPDX-License-Identifier: GPL-3.0 */
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
#include <linux/delay.h>

#ifdef CONFIG_X86
#if LINUX_VERSION_CODE > KERNEL_VERSION(4, 7, 0)
#include <asm/paravirt.h>
#endif
#endif

#define DEFAULT_RET_STR "-2"
#define NAME_TOO_LONG "-4"
#define PID_TREE_MATEDATA_LEN  32

static unsigned int ROOT_PID_NS_INUM;

extern unsigned long smith_kallsyms_lookup_name(const char *);

extern char *__dentry_path(struct dentry *dentry, char *buf, int buflen);

extern u64 GET_PPIN(void);

static __always_inline char *smith_get_pid_tree(int limit)
{
    int real_data_len = PID_TREE_MATEDATA_LEN;
    int limit_index = 0;
    char *tmp_data = NULL;
    char pid[24];
    struct task_struct *task;
    struct task_struct *old_task;

    task = current;
    get_task_struct(task);

    snprintf(pid, 24, "%d", task->tgid);
    tmp_data = kzalloc(1024, GFP_ATOMIC);

    if (!tmp_data) {
        put_task_struct(task);
        return tmp_data;
    }

    strcat(tmp_data, pid);
    strcat(tmp_data, ".");
    strcat(tmp_data, current->comm);

    while (1) {
        limit_index = limit_index + 1;
        if (limit_index >= limit) {
            put_task_struct(task);
            break;
        }

        old_task = task;
        rcu_read_lock();
        task = rcu_dereference(task->real_parent);
        put_task_struct(old_task);
        if (!task || task->pid == 0) {
            rcu_read_unlock();
            break;
        }

        get_task_struct(task);
        rcu_read_unlock();

        real_data_len = real_data_len + PID_TREE_MATEDATA_LEN;
        if (real_data_len > 1024) {
            put_task_struct(task);
            break;
        }

        snprintf(pid, 24, "%d", task->tgid);
        strcat(tmp_data, "<");
        strcat(tmp_data, pid);
        strcat(tmp_data, ".");
        strcat(tmp_data, task->comm);
    }

    return tmp_data;
}

static inline char *smith_strim(char *s)
{
	size_t size = strlen(s);
	char *end, *first = s;

	if (!size)
		return s;

	end = s + size - 1;
	while (end >= s && isspace(*end))
		end--;
	*(end + 1) = '\0';

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

static __always_inline char *smith_d_path(const struct path *path, char *buf, int buflen)
{
    char *name = DEFAULT_RET_STR;
    if (buf) {
        name = d_path(path, buf, buflen);
        if (IS_ERR(name))
            name = NAME_TOO_LONG;
    }
    return name;
}

#if LINUX_VERSION_CODE > KERNEL_VERSION(5, 8, 0)
#include <linux/mmap_lock.h>
#elif !defined(_LINUX_MMAP_LOCK_H)
static inline bool mmap_read_trylock(struct mm_struct *mm)
{
    return down_read_trylock(&mm->mmap_sem) != 0;
}
static inline void mmap_read_unlock(struct mm_struct *mm)
{
    up_read(&mm->mmap_sem);
}
#endif

//get task exe file full path && only current can use it
static __always_inline char *smith_get_exe_file(char *buffer, int size)
{
    char *exe_file_str = DEFAULT_RET_STR;

    if (!buffer || !current->mm)
        return exe_file_str;

    if (mmap_read_trylock(current->mm)) {
        if (current->mm->exe_file) {
            exe_file_str =
                    smith_d_path(&current->mm->exe_file->f_path, buffer,
                                 size);
        }
        mmap_read_unlock(current->mm);
    }

    return exe_file_str;
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


static inline int __get_current_uid(void) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 5, 0)
    return current->real_cred->uid.val;
#else
    return current->real_cred->uid;
#endif
}

static inline int __get_current_euid(void) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 5, 0)
    return current->real_cred->euid.val;
#else
    return current->real_cred->euid;
#endif
}

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

    get_task_struct(task);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 19, 0)
    ROOT_PID_NS_INUM = task->nsproxy->pid_ns_for_children->ns.inum;
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3, 11, 0)
    ROOT_PID_NS_INUM = task->nsproxy->pid_ns_for_children->proc_inum;
#else
    ROOT_PID_NS_INUM = task->nsproxy->pid_ns->proc_inum;
#endif
    put_task_struct(task);
    put_pid(pid_struct);
}

static inline unsigned int __get_pid_ns_inum(void) {
    unsigned int inum = 0;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 19, 0)
    inum = current->nsproxy->pid_ns_for_children->ns.inum;
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3, 11, 0)
    inum = current->nsproxy->pid_ns_for_children->proc_inum;
#else
    inum = current->nsproxy->pid_ns->proc_inum;
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

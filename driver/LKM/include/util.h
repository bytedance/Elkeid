/* SPDX-License-Identifier: GPL-2.0 */
#ifndef UTIL_H
#define UTIL_H

#include <linux/version.h>
#include <linux/sched.h>
#include <linux/fsnotify.h>
#include <linux/slab.h>
#include <linux/mm_types.h>
#include <linux/dcache.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/uaccess.h>

#ifdef CONFIG_X86
#if LINUX_VERSION_CODE > KERNEL_VERSION(4, 7, 0)
#include <asm/paravirt.h>
#endif
#endif

extern unsigned long smith_kallsyms_lookup_name(const char *);

extern char *get_exe_file(struct task_struct *task, char *buffer, int size);

extern char *get_pid_tree(int limit);

extern char *__dentry_path(struct dentry *dentry, char *buf, int buflen);

extern u64 GET_PPIN(void);

static __always_inline unsigned long __must_check smith_copy_from_user(void *to, const void __user *from, unsigned long n)
{
    unsigned long res;
    pagefault_disable();
    res = copy_from_user(to, from, n);
    pagefault_enable();
    return res;
}

#define smith_get_user(x, ptr)		\
({					\
	int __ret;			\
	pagefault_disable();		\
	__ret = get_user(x, ptr);	\
	pagefault_enable();		\
	__ret;				\
})

#endif /* UTIL_H */

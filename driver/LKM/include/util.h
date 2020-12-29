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

#endif /* UTIL_H */

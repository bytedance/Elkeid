/* SPDX-License-Identifier: GPL-3.0 */
#ifndef __ANTI_ROOTKIT_H
#define __ANTI_ROOTKIT_H
#include <asm/asm-offsets.h>
#include <linux/syscalls.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/workqueue.h>
#include <linux/fs.h>
#include <linux/version.h>
#include <linux/kernel.h>
#include <linux/kallsyms.h>

#define PROC_FILE_HOOK "700"
#define SYSCALL_HOOK "701"
#define LKM_HIDDEN "702"
#define INTERRUPTS_HOOK "703"


#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
static void analyze_syscalls(void);

static void analyze_interrupts(void);

static void analyze_modules(void);

static void analyze_fops(void);

#else
static inline void analyze_syscalls(void) { }
static inline void analyze_interrupts(void) { }
static inline void analyze_modules(void) { }
static inline void analyze_fops(void) { }
#endif  //LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)

#endif //__ANTI_ROOTKIT_H

/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __ANTI_ROOTKIT_H
#define __ANTI_ROOTKIT_H

#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/workqueue.h>
#include <linux/fs.h>
#include <linux/version.h>
#include <linux/kernel.h>
#include <linux/kallsyms.h>
#include <asm/syscall.h> /* NR_syscalls */

#define PROC_FILE_HOOK "700"
#define SYSCALL_HOOK "701"
#define LKM_HIDDEN "702"
#define INTERRUPTS_HOOK "703"

#endif //__ANTI_ROOTKIT_H
/* SPDX-License-Identifier: GPL-2.0 */

#ifndef SMITH_HOOK_H
#define SMITH_HOOK_H

#include <linux/version.h>

#if(LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 32))
#error ******************************************************************************
#error * Elkeid works on kernel 2.6.32 or newer. Please update your kernel          *
#error ******************************************************************************
#endif

#include "kprobe.h"
#include "util.h"
#include "filter.h"
#include "struct_wrap.h"

#include <linux/usb.h>
#include <linux/uio.h>
#include <linux/kprobes.h>
#include <linux/binfmts.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/fs_struct.h>
#include <linux/init.h>
#include <linux/interrupt.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/net.h>
#include <linux/sched.h>
#include <linux/skbuff.h>
#include <linux/utsname.h>
#include <linux/types.h>
#include <linux/ptrace.h>
#include <linux/fsnotify.h>
#include <net/inet_sock.h>
#include <net/tcp.h>
#include <linux/namei.h>
#include <linux/tty.h>
#include <linux/mman.h>
#include <linux/kallsyms.h>
#include <linux/fdtable.h>
#include <linux/prctl.h>
#include <linux/kmod.h>
#include <linux/dcache.h>

#ifndef get_file_rcu
#define get_file_rcu(x) atomic_long_inc_not_zero(&(x)->f_count)
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 1, 0)
#define __ARG_PLACEHOLDER_1 0,
#define config_enabled(cfg) _config_enabled(cfg)
#define _config_enabled(value) __config_enabled(__ARG_PLACEHOLDER_##value)
#define __config_enabled(arg1_or_junk) ___config_enabled(arg1_or_junk 1, 0)
#define ___config_enabled(__ignored, val, ...) val
#define IS_ENABLED(option) \
        (config_enabled(option) || config_enabled(option##_MODULE))
#endif

#define NIPQUAD(addr) \
    ((unsigned char *)&addr)[0], \
    ((unsigned char *)&addr)[1], \
    ((unsigned char *)&addr)[2], \
    ((unsigned char *)&addr)[3]

#define NIP6(addr) \
    ntohs((addr).s6_addr16[0]), \
    ntohs((addr).s6_addr16[1]), \
    ntohs((addr).s6_addr16[2]), \
    ntohs((addr).s6_addr16[3]), \
    ntohs((addr).s6_addr16[4]), \
    ntohs((addr).s6_addr16[5]), \
    ntohs((addr).s6_addr16[6]), \
    ntohs((addr).s6_addr16[7])

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 17, 0) && defined(CONFIG_ARCH_HAS_SYSCALL_WRAPPER)
#ifdef CONFIG_X86_64
#define P_SYSCALL_PREFIX(x) P_TO_STRING(__x64_sys_ ## x)
#define P_GET_IA32_COMPAT_SYSCALL_NAME(x) P_IA32_COMPAT_SYSCALL_PREFIX(x)
#define P_IA32_COMPAT_SYSCALL_PREFIX(x) P_TO_STRING(__ia32_compat_sys_ ## x)
#define P_COMPAT_SYSCALL_PREFIX(x) P_IA32_COMPAT_SYSCALL_PREFIX(x)
#elif defined(CONFIG_ARM64)
#define P_SYSCALL_PREFIX(x) P_TO_STRING(__arm64_sys_ ## x)
#define P_GET_IA32_COMPAT_SYSCALL_NAME(x) P_IA32_COMPAT_SYSCALL_PREFIX(x)
#define P_IA32_COMPAT_SYSCALL_PREFIX(x) P_TO_STRING(__arm64_compat_sys_ ## x)
#define P_COMPAT_SYSCALL_PREFIX(x) P_IA32_COMPAT_SYSCALL_PREFIX(x)
#else
#define P_SYSCALL_PREFIX(x) P_TO_STRING(sys_ ## x)
#endif
#else
#define P_SYSCALL_PREFIX(x) P_TO_STRING(sys_ ## x)
#define P_COMPAT_SYSCALL_PREFIX(x) P_TO_STRING(compat_sys_ ## x)
#endif

#define P_TO_STRING(x) # x
#define P_GET_SYSCALL_NAME(x) P_SYSCALL_PREFIX(x)
#define P_GET_COMPAT_SYSCALL_NAME(x) P_COMPAT_SYSCALL_PREFIX(x)

#endif /* SMITH_HOOK_H */

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

/*
 * tracing id related definitions
 */

/* cache of executable images, managed by rbtree and lru list */
#define SI_IMG_LENGTH  (256)
#define SI_IMG_BUFLEN  (SI_IMG_LENGTH - offsetof(struct smith_img, si_buf))

struct smith_img {
    struct tt_node      si_node;    /* rbtree of cached img */
    struct list_head    si_link;    /* lru list for reaper */
    struct file        *si_exe;     /* executable image */
    void               *si_sb;      /* superblock pointer of target volume */
    ino_t               si_ino;     /* inode number of the executable image */
    typeof(((struct inode *)0)->i_ctime) si_cts; /* inode creation time */
    uint32_t            si_age;     /* time stamp in seconds */
    uint16_t            si_max;
    uint16_t            si_len;
    char               *si_path;

    union {
        char           *si_alloc;
        char            si_buf[0];
    };
};

struct smith_img *smith_find_img(struct task_struct *task);
struct smith_img *smith_get_img(struct smith_img *img);
void smith_put_img(struct smith_img *img);
void smith_enum_img(void);

/*
 * per-task record, managed by hash-list
 */
struct smith_tid {
    struct hlist_hnod   st_node;
    uint64_t            st_start;   /* start time of current task */
    uint32_t            st_pid;     /* thread id (per task) */
    uint32_t            st_sid;     /* session id (when being created) */
    char               *st_pid_tree;/* pid tree strings */
    struct smith_img   *st_img;     /* cache of exe path */
    unsigned long       st_root;    /* ~ superblock of root filesystem */
};

static inline uint64_t smith_task_start_time(struct task_struct *task) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 17, 0)
    return task->start_time;
#else
    return timespec_to_ns(&task->start_time);
#endif
}

struct smith_tid *smith_lookup_tid(struct task_struct *task);
int smith_query_tid(struct task_struct *task);
static inline int smith_query_sid(void)
{
    return smith_query_tid(current);
}
unsigned long smith_query_mntns(void);
int smith_put_tid(struct smith_tid *tid);
int smith_drop_tid(struct task_struct *task);
void smith_enum_tid(void);

#endif /* SMITH_HOOK_H */

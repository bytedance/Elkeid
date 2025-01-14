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

struct smith_img;

/*
 * per-task record, managed by hash-list
 */
struct smith_tid {
    struct hlist_hnod   st_node;
    uint64_t            st_start;   /* start time of current task */
    uint32_t            st_tgid;    /* process id / thread group id */
    uint32_t            st_sid;     /* session id (when being created) */
    char               *st_pid_tree;/* pid tree strings */
    struct smith_img   *st_img;     /* cache of exe path */
    uint64_t            st_root;    /* root fs & mnt_namespace id */
    uint16_t            st_size_pidtree; /* buffer size of pidtree */
    uint16_t            st_len_pidtree; /* real string size of pidtree */
    uint16_t            st_len_current_pid; /* string size of current item */
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

uint64_t smith_query_mntns(void);
int smith_put_tid(struct smith_tid *tid);
int smith_drop_tid(struct task_struct *task);

/*
 * cache list of newly created files, to be managed by by rbtree and lru list
 * lifecycle controlling:
 * 1) new item to be inserted when being created: security_inode_create
 * 2) lru controlled: to be discarded from list head when list is full
 */
#define SE_ENT_LENGTH  (256)
#define SE_ENT_BUFLEN  (SE_ENT_LENGTH - offsetof(struct smith_ent, se_buf))

struct smith_ent {
    struct tt_node      se_node;    /* rbtree of cached path */
    struct list_head    se_link;    /* lru list for reaper */
    uint64_t            se_hash;
    char               *se_path;
    uint32_t            se_tgid;
    uint32_t            se_age;     /* time stamp in seconds */
    uint16_t            se_len;
    uint16_t            se_max;
    char                se_buf[0];
};

int smith_insert_ent(char *path);
int smith_remove_ent(char *path);


/*
 * LRU cache list for tcp connections (for MaaS tcp connection auditing)
 */
struct smith_conn {
    struct tt_node      sc_node;    /* rbtree of cached path */
    struct list_head    sc_link;    /* lru list for reaper */
    struct smith_tid   *sc_tid;
    struct sock        *sc_sock;
    uint32_t            sc_flags:31;
    uint32_t            sc_flag_ipv6:1;
    uint32_t            sc_sid;
    int                 sc_uid;
    uint32_t            sc_pid;
    uint32_t            sc_ppid;
    uint32_t            sc_pgid;
    char                sc_comm[TASK_COMM_LEN];
    char                sc_utsname[__NEW_UTS_LEN];
    uint64_t            sc_mntns;
    uint32_t            sc_age;     /* timestamp for LRU */
    uint16_t            sc_sport;
    uint16_t            sc_dport;
    union {
        struct {
            uint32_t sip4;
            uint32_t dip4;
        };
        struct {
            struct in6_addr sip6;
            struct in6_addr dip6;
        };
    } sc_ip;
};

#endif /* SMITH_HOOK_H */

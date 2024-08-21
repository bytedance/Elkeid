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

/*
 * macro definitions for legacy kernels
 */

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 1, 0)
#define __ARG_PLACEHOLDER_1 0,
#define config_enabled(cfg) _config_enabled(cfg)
#define _config_enabled(value) __config_enabled(__ARG_PLACEHOLDER_##value)
#define __config_enabled(arg1_or_junk) ___config_enabled(arg1_or_junk 1, 0)
#define ___config_enabled(__ignored, val, ...) val
#define IS_ENABLED(option) \
        (config_enabled(option) || config_enabled(option##_MODULE))
#endif

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

extern u8 *smith_query_sb_uuid(struct super_block *sb);

extern uint64_t hash_murmur_OAAT64(char *s, int len);

static inline struct task_struct *smith_get_task_struct(struct task_struct *tsk)
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

/*
 * CONFIG_UIDGID_STRICT_TYPE_CHECKS introducted frmo 3.5.0 and
 * removed after 3.14.0
 * New gid/uid supported by vanilla kernels >= 3.5.0, but ubuntu
 * has it backported for 3.4
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 14, 0) || \
    defined(CONFIG_UIDGID_STRICT_TYPE_CHECKS) || \
    (defined(KGID_STRUCT_CHECK) && !defined(KGID_CONFIG_CHECK))
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

static inline char *smith_strim(char *s, int size)
{
    char *end, *first = s;

    if (!s || size <= 0)
        return s;

    end = s + size - 1;
    while (end >= s && isspace(*end)) {
        *end = 0;
        end--;
    }

    while (first < end && isspace(*first))
        first++;

    if (first > s && end > first) {
        memmove(s, first, end - first);
        s[(int)(end - first)] = 0;
    }

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
 *     WARNING: pagefault_enable could trigger re-scheduling, that's not
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

/*
 * WARNING:
 *
 * access_ok() might sleep as it 's said, but actaully what it does
 * is just a comparison between user addr and current's TASK_SIZE_MAX.
 */
static __always_inline int smith_access_ok(const void __user *from, unsigned long n)
{
#if defined(UACCESS_TYPE_SUPPORT)
    return access_ok(VERIFY_READ, from, n);
#else
    return access_ok(from, n);
#endif
}

static __always_inline unsigned long __must_check smith_copy_from_user(void *to, const void __user *from, unsigned long n)
{
    unsigned long res;
    smith_pagefault_disable();
    /* validate user-mode buffer: ['from' - 'from' + 'n') */
    if (smith_access_ok(from, n))
        res = __copy_from_user_inatomic(to, from, n);
    else
        res = n;
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
    /* validate user-mode buffer: ['from' - 'from' + 'n') */    \
    __ret = sizeof(*(ptr));                                     \
    if (smith_access_ok(ptr, __ret))                            \
        __ret = __copy_from_user_inatomic(&__val, ptr, __ret);  \
    smith_pagefault_enable();                                   \
    (x) = (__typeof__(*(ptr)))__val;                            \
    __ret;                                                      \
})

static inline int __get_pgid(void) {
    return task_pgrp_nr_ns(current, &init_pid_ns);
}

static inline int __get_sid(void) {
    return task_session_nr_ns(current, &init_pid_ns);
}

#define CLASSERT(cond) do {switch('x') {case ((cond)): case 0: break;}} while (0)
size_t smith_strnlen (const char *str, size_t maxlen);

/*
 * lru + rbtree implementation with object pool
 */

#include "../include/memcache.h"

struct tt_node {
    struct rb_node  node;
    atomic_t        refs;
    union {
        uint32_t    flags;
        struct {
          uint32_t  flag_pool:1;
          uint32_t  flag_newsid:1;
          uint32_t  flag_usr1:1;
          uint32_t  flag_usr2:1;
          uint32_t  flag_usr3:1;
          uint32_t  flag_usr4:1;
          uint32_t  flag_usr5:1;
          uint32_t  flag_usr6:1;
        };
    };
};

static inline void tt_memcpy(void *t, void *p, int s)
{
    memcpy(t + sizeof(struct tt_node),
           p + sizeof(struct tt_node),
           s - sizeof(struct tt_node));
}

struct tt_rb {
    struct rb_root  root;
    rwlock_t        lock;
    void           *data;
    int             node;
    gfp_t           gfp;
    atomic_t        count;
    struct memcache_head pool;
    struct tt_node * (*init)(struct tt_rb *, void *);
    int (*cmp)(struct tt_rb *, struct tt_node *, void *);
    void (*release)(struct tt_rb *, struct tt_node *);
};

int tt_rb_init(struct tt_rb *rb, void *data, int ns, int sz,
               gfp_t gfp_node, gfp_t gfp_cache,
               struct tt_node *(*init)(struct tt_rb *, void *),
               int (*cmp)(struct tt_rb *, struct tt_node *, void *),
               void (*release)(struct tt_rb *, struct tt_node *));
void tt_rb_fini(struct tt_rb *rb);
struct tt_node *tt_rb_alloc_node(struct tt_rb *rb);
void tt_rb_free_node(struct tt_rb *rb, struct tt_node *node);

int tt_rb_remove_node_nolock(struct tt_rb *rb, struct tt_node *node);
int tt_rb_remove_node(struct tt_rb *rb, struct tt_node *node);
struct tt_node *tt_rb_lookup_nolock(struct tt_rb *rb, void *key);
int tt_rb_remove_key(struct tt_rb *rb, void *key);
int tt_rb_deref_key(struct tt_rb *rb, void *key);
int tt_rb_deref_node(struct tt_rb *rb, struct tt_node *node);
struct tt_node *tt_rb_insert_key_nolock(struct tt_rb *rb, void *key);
int tt_rb_insert_key(struct tt_rb *rb, void *key);
struct tt_node *tt_rb_lookup_key(struct tt_rb *rb, void *key);
int tt_rb_query_key(struct tt_rb *rb, void *key);
struct tt_node *tt_rb_find_key(struct tt_rb *rb, void *key);
void tt_rb_enum(struct tt_rb *rb, void (*cb)(struct tt_node *));

/*
 * hash list implementation with rcu lock
 */

struct hlist_hnod {
    struct list_head    link;
    struct rcu_head	    rcu;
    struct hlist_root  *hash;
    atomic_t            refs;
    union {
        uint32_t        flags;
        struct {
          uint32_t      flag_pool:1;
          uint32_t      flag_newsid:1;
          uint32_t      flag_rcu:1;
        };
    };
};

static inline void hlist_memcpy(void *t, void *p, int s)
{
    memcpy(t + sizeof(struct hlist_hnod),
           p + sizeof(struct hlist_hnod),
           s - sizeof(struct hlist_hnod));
}

struct hlist_root {
    spinlock_t      lock;
    void           *data;
    uint16_t        node;
    uint16_t        nlists;
    gfp_t           gfp;
    atomic_t        count;
    atomic_t        allocs;
    struct list_head  *lists;
    struct memcache_head pool;
    struct hlist_hnod * (*init)(struct hlist_root *, void *);
    int (*hash)(struct hlist_root *, void *);
    int (*cmp)(struct hlist_root *, struct hlist_hnod *, void *);
    void (*release)(struct hlist_root *, struct hlist_hnod *);
};

int hlist_init(struct hlist_root *hr, void *data, int ns, int sz,
               gfp_t gfp_node, gfp_t gfp_cache,
               struct hlist_hnod *(*init)(struct hlist_root *, void *),
               int (*hash)(struct hlist_root *, void *),
               int (*cmp)(struct hlist_root *, struct hlist_hnod *, void *),
               void (*release)(struct hlist_root *, struct hlist_hnod *));
void hlist_fini(struct hlist_root *hr);
struct hlist_hnod *hlist_alloc_node(struct hlist_root *hr);
void hlist_free_node(struct hlist_root *hr, struct hlist_hnod *node);

#define hlist_lock(hr, flags) spin_lock_irqsave(&(hr)->lock, (flags))
#define hlist_unlock(hr, flags) spin_unlock_irqrestore(&(hr)->lock, (flags))

int hlist_remove_node(struct hlist_root *hr, struct hlist_hnod *node);
int hlist_remove_key(struct hlist_root *hr, void *key);
int hlist_deref_key(struct hlist_root *hr, void *key);
int hlist_deref_node(struct hlist_root *hr, struct hlist_hnod *node);
struct hlist_hnod *hlist_insert_key_nolock(struct hlist_root *hr, void *key);
struct hlist_hnod *hlist_insert_key(struct hlist_root *hr, void *key);
struct hlist_hnod *hlist_lookup_key(struct hlist_root *hr, void *key);
int hlist_query_key(struct hlist_root *hr, void *key, void *node);
void hlist_enum(struct hlist_root *hr, void (*cb)(struct hlist_hnod *));

char *smith_strstr(char *s, int sl, char *t);
int smith_is_trusted_agent(char *agents[]);

#endif /* UTIL_H */

// SPDX-License-Identifier: GPL-2.0
/*
 * util.c
 *
 */
#include "../include/util.h"
#include <linux/version.h>
#include <linux/vmalloc.h>
#include <linux/kallsyms.h>
#include <linux/prefetch.h>

/*
 * rbtree support routines
 */

struct tt_node *tt_rb_alloc_node(struct tt_rb *rb)
{
    struct tt_node *tnod;
    int size = rb->node ? rb->node : sizeof(struct tt_node);

    tnod = memcache_pop(&rb->pool);
    if (tnod) {
        memset((s8 *)tnod + offsetof(struct tt_node, node),
                0, size - offsetof(struct tt_node, node));
        tnod->flag_pool = 1;
        return tnod;
    }
    return smith_kzalloc(size, rb->gfp);
}

void tt_rb_free_node(struct tt_rb *rb, struct tt_node *node)
{
    if (node->flag_pool)
        memcache_push(node, &rb->pool);
    else
        smith_kfree(node);
}

/* one-time call, to init objs just after pool allocation */
static int tt_rb_init_node(void *context, void *nod)
{
    struct tt_node *tnod = nod;

    return 0;
    tnod = tnod;
}

int tt_rb_init(struct tt_rb *rb, void *data, int nobjs, int objsz,
               gfp_t gfp_node, gfp_t gfp_op,
               struct tt_node *(*init)(struct tt_rb *, void *),
               int (*cmp)(struct tt_rb *, struct tt_node *, void *),
               void (*release)(struct tt_rb *, struct tt_node *))
{
    /* initialize rbtree */
    memset(rb, 0, sizeof(struct tt_rb));
    rwlock_init(&rb->lock);
    rb->data = data;
    rb->node = objsz;
    rb->gfp = gfp_node | __GFP_ZERO;
    rb->init = init;
    rb->release = release;
    rb->cmp = cmp;

    /* initialize memory cache for tt_node, errors are to be ignored,
       then new nodes are to be allocated from memory pool */
    memcache_init(&rb->pool, nobjs, objsz, gfp_op, rb,
                  tt_rb_init_node, NULL);

    return 0;
}

struct tt_node *tt_rb_lookup_nolock(struct tt_rb *rb, void *key)
{
    struct tt_node *tnod = NULL;
    struct rb_node *node;

    node = rb->root.rb_node;
    while (node && !tnod) {
        struct tt_node *nod;
        int rc;
        nod = container_of(node, struct tt_node, node);
        rc = rb->cmp(rb, nod, key);
        if (rc < 0)
            node = node->rb_left;
        else if (rc > 0)
            node = node->rb_right;
        else
            tnod = nod;
    }

    return tnod;
}

int tt_rb_remove_node_nolock(struct tt_rb *rb, struct tt_node *tnod)
{
    rb_erase(&tnod->node, &rb->root);

    if (rb->release)
        rb->release(rb, tnod);
    else
        tt_rb_free_node(rb, tnod);
    atomic_dec(&rb->count);

    return 0;
}

int tt_rb_remove_node(struct tt_rb *rb, struct tt_node *node)
{
    unsigned long flags;
    int rc;

    write_lock_irqsave(&rb->lock, flags);
    rc = tt_rb_remove_node_nolock(rb, node);
    write_unlock_irqrestore(&rb->lock, flags);
    return rc;
}

int tt_rb_remove_key(struct tt_rb *rb, void *key)
{
    struct tt_node *tnod;
    unsigned long flags;
    int rc = -ENOENT;

    write_lock_irqsave(&rb->lock, flags);
    tnod = tt_rb_lookup_nolock(rb, key);
    if (tnod)
        rb_erase(&tnod->node, &rb->root);
    write_unlock_irqrestore(&rb->lock, flags);

    if (tnod && !atomic_dec_return(&tnod->refs)) {
        if (rb->release)
            rb->release(rb, tnod);
        else
            tt_rb_free_node(rb, tnod);
        atomic_dec(&rb->count);
        return 0;
    }

    return rc;
}

int tt_rb_deref_node(struct tt_rb *rb, struct tt_node *tnod)
{
    unsigned long flags;
    int rc = atomic_add_unless(&tnod->refs, -1, 1);

    if (rc)
        return 0;

    write_lock_irqsave(&rb->lock, flags);
    if (0 == atomic_dec_return(&tnod->refs))
        rc = tt_rb_remove_node_nolock(rb, tnod);
    write_unlock_irqrestore(&rb->lock, flags);

    return rc;
}

int tt_rb_deref_key(struct tt_rb *rb, void *key)
{
    struct tt_node *tnod;
    unsigned long flags;
    int rc = -ENOENT;

    write_lock_irqsave(&rb->lock, flags);
    tnod = tt_rb_lookup_nolock(rb, key);
    if (tnod) {
        if (atomic_dec_return(&tnod->refs)) {
            tnod = NULL;
            rc = -EEXIST;
        } else {
            rb_erase(&tnod->node, &rb->root);
        }
    }
    write_unlock_irqrestore(&rb->lock, flags);

    if (tnod) {
        if (rb->release)
            rb->release(rb, tnod);
        else
            tt_rb_free_node(rb, tnod);
        atomic_dec(&rb->count);
        return 0;
    }

    return rc;
}

static struct tt_node *tt_rb_insert_node_nolock(struct tt_rb *rb, struct tt_node *tnod)
{
    struct rb_node **anchor, *parent = NULL;

    anchor = &(rb->root.rb_node);
    while (*anchor) {
        struct tt_node *tanod;
        int rc;
        tanod = container_of(*anchor, struct tt_node, node);
        rc = rb->cmp(rb, tanod, tnod);
        parent = *anchor;
        if (rc < 0)
            anchor = &(*anchor)->rb_left;
        else if (rc > 0)
            anchor = &(*anchor)->rb_right;
        else
            return tanod;
    }

    rb_link_node(&tnod->node, parent, anchor);
    rb_insert_color(&tnod->node, &rb->root);
    return tnod;
}

struct tt_node *tt_rb_insert_key_nolock(struct tt_rb *rb, void *key)
{
    struct tt_node *tnod, *nnod = ERR_PTR(-ENOMEM);

    /* initialize tnod from key */
    tnod = rb->init(rb, key);
    if (!tnod)
        goto errorout;

    /* insert newly allocated node into rbtree */
    nnod = tt_rb_insert_node_nolock(rb, tnod);
    if (nnod == tnod) {
        atomic_inc(&rb->count);
    } else {
        rb->release(rb, tnod);
    }

errorout:
    return nnod;
}

int tt_rb_insert_key(struct tt_rb *rb, void *key)
{
    struct tt_node *tnod;
    unsigned long flags;

    write_lock_irqsave(&rb->lock, flags);
    tnod = tt_rb_insert_key_nolock(rb, key);
    write_unlock_irqrestore(&rb->lock, flags);
    if (IS_ERR(tnod)) {
        return PTR_ERR(tnod);
    } else if (!tnod) {
        return -ENOMEM;
    }
    return 0;
}

struct tt_node *tt_rb_lookup_key(struct tt_rb *rb, void *key)
{
    struct tt_node *tnod;
    unsigned long flags;

    read_lock_irqsave(&rb->lock, flags);
    tnod = tt_rb_lookup_nolock(rb, key);
    if (tnod)
        atomic_inc(&tnod->refs);
    read_unlock_irqrestore(&rb->lock, flags);

    return tnod;
}

int tt_rb_query_key(struct tt_rb *rb, void *key)
{
    struct tt_node *tnod;
    unsigned long flags;

    read_lock_irqsave(&rb->lock, flags);
    tnod = tt_rb_lookup_nolock(rb, key);
    if (tnod)
        memcpy(key, tnod, rb->node);
    read_unlock_irqrestore(&rb->lock, flags);

    return !tnod;
}

struct tt_node *tt_rb_find_key(struct tt_rb *rb, void *key)
{
    struct tt_node *tnod;
    unsigned long flags;

    /* do lookup first to check whether it's in rbtree */
    read_lock_irqsave(&rb->lock, flags);
    tnod = tt_rb_lookup_nolock(rb, key);
    if (tnod)
        atomic_inc(&tnod->refs);
    read_unlock_irqrestore(&rb->lock, flags);

    if (tnod)
        return tnod;

    /* try to alloc new key and attach it to rbtree */
    write_lock_irqsave(&rb->lock, flags);
    tnod = tt_rb_insert_key_nolock(rb, key);
    if (tnod)
        atomic_inc(&tnod->refs);
    write_unlock_irqrestore(&rb->lock, flags);

    return tnod;
}

static void tt_rb_clear_node(struct tt_rb *rb, struct rb_node *node)
{
    struct tt_node *tnod;

    if (!node)
        return;

    tt_rb_clear_node(rb, node->rb_left);
    tt_rb_clear_node(rb, node->rb_right);

    tnod = container_of(node, struct tt_node, node);
    rb->release(rb, tnod);
}

void tt_rb_fini(struct tt_rb *rb)
{
    unsigned long flags;

    write_lock_irqsave(&rb->lock, flags);
    tt_rb_clear_node(rb, rb->root.rb_node);
    write_unlock_irqrestore(&rb->lock, flags);

    /* cleanup objects pool */
    memcache_fini(&rb->pool);
}

void tt_rb_enum(struct tt_rb *rb, void (*cb)(struct tt_node *))
{
    struct rb_node *nod;
    unsigned long flags;

    read_lock_irqsave(&rb->lock, flags);
    for (nod = rb_first(&rb->root); nod; nod = rb_next(nod)) {
        cb(container_of(nod, struct tt_node, node));
    }
    read_unlock_irqrestore(&rb->lock, flags);
}

/*
 * hash list support routines (with rcu locking)
 */

struct hlist_hnod *hlist_alloc_node(struct hlist_root *hr)
{
    struct hlist_hnod *hnod;
    int size = hr->node ? hr->node : sizeof(struct hlist_hnod);

    hnod = memcache_pop(&hr->pool);
    if (hnod) {
        memset((s8 *)hnod + offsetof(struct hlist_hnod, link),
                0, size - offsetof(struct hlist_hnod, link));
        hnod->flag_pool = 1;
        hnod->hash = hr;
        atomic_inc(&hr->allocs);
    } else {
        hnod = (struct hlist_hnod *)smith_kzalloc(size, hr->gfp);
        if (hnod) {
            hnod->hash = hr;
            atomic_inc(&hr->allocs);
        }
    }
    return hnod;
}

/* one-time call, to init objs just after pool allocation */
static int hlist_init_node(void *context, void *nod)
{
    struct hlist_hnod *hnod = nod;

    return 0;
    hnod = hnod;
}

/* one-time call, to init objs just after pool allocation */
void hlist_free_node(struct hlist_root *hr, struct hlist_hnod *node)
{
    if (node->flag_pool)
        memcache_push(node, &hr->pool);
    else
        smith_kfree(node);
    atomic_dec(&hr->allocs);
}

static void hlist_free_node_rcu(struct rcu_head *rcu)
{
    struct hlist_hnod *hnod = container_of(rcu, struct hlist_hnod, rcu);
    if (hnod->hash->release)
        hnod->hash->release(hnod->hash, hnod);
    else
        hlist_free_node(hnod->hash, hnod);
}

int hlist_init(struct hlist_root *hr, void *data, int nobjs,
               int objsz, gfp_t gfp_node, gfp_t gfp_op,
               struct hlist_hnod *(*init)(struct hlist_root *, void *),
               int (*hash)(struct hlist_root *, void *),
               int (*cmp)(struct hlist_root *, struct hlist_hnod *, void *),
               void (*release)(struct hlist_root *, struct hlist_hnod *))
{
    int i, n;

    /* initialize hash list */
    memset(hr, 0, sizeof(struct hlist_root));
    spin_lock_init(&hr->lock);
    hr->data = data;
    hr->node = objsz;
    hr->gfp = gfp_node | __GFP_ZERO;

    /* initialize callbacks */
    hr->init = init;
    hr->hash = hash;
    hr->release = release;
    hr->cmp = cmp;

    /* initialize hash lists */
    n = rounddown_pow_of_two(PAGE_SIZE / sizeof(struct list_head));
    if (num_present_cpus() > 50)
        n = n << 1;
    hr->nlists = n - 1;
    hr->lists = vmalloc(sizeof(struct list_head) * n);
    if (!hr->lists)
        return -ENOMEM;
    for (i = 0; i < n; i++)
        INIT_LIST_HEAD(&hr->lists[i]);

    /* initialize memory cache for hnod, errors to be ignored,
       if fails, new node will be allocated from system slab */
    memcache_init(&hr->pool, nobjs, objsz, gfp_op, hr,
                  hlist_init_node, NULL);
    return 0;
}

void hlist_fini(struct hlist_root *hr)
{
    int i;

    if (!hr->lists)
        return;

    /*
     * WARNING:
     * loadable module must call rcu_barrier() in its exit function
     * to make sure all pended call_rcu callbacks to finish. Calling
     * synchronize_rcu() can NOT guarantee, though it waits a grace
     * period to elapse.
     */
    rcu_barrier();

    /*
     * cleanup all nodes in the hash lists
     *
     * it's safe here calling list_for_each_entry_safe
     * since tracepoints and kprobes are all disabled
     */
    for (i = 0; i <= hr->nlists; i++) {
        struct hlist_hnod *hnod, *next;
        list_for_each_entry_safe(hnod, next, &hr->lists[i], link) {
            if (hr->release)
                hr->release(hr, hnod);
            else
                hlist_free_node(hr, hnod);
        }
    }
    vfree(hr->lists);

    /* cleanup objects pool */
    memcache_fini(&hr->pool);
}

static struct hlist_hnod *hlist_lookup_key_noref(struct hlist_root *hr, void *key)
{
    struct hlist_hnod *hnod = NULL, *e;
    int id = hr->hash(hr, key);

    list_for_each_entry_rcu(e, &hr->lists[id], link) {
        if (hr->cmp(hr, e, key) == 0) {
            hnod = e;
            break;
        }
    }

    return hnod;
}

struct hlist_hnod *hlist_lookup_key(struct hlist_root *hr, void *key)
{
    struct hlist_hnod *hnod = NULL, *e;
    int id = hr->hash(hr, key);

    rcu_read_lock();
    list_for_each_entry_rcu(e, &hr->lists[id], link) {
        if (hr->cmp(hr, e, key) == 0) {
            atomic_inc(&e->refs);
            hnod = e;
            break;
        }
    }
    rcu_read_unlock();

    return hnod;
}

static int hlist_remove_node_nolock(struct hlist_root *hr, struct hlist_hnod *hnod)
{
    list_del_rcu(&hnod->link);
    atomic_dec(&hr->count);
    return atomic_dec_return(&hnod->refs);
}

int hlist_remove_node(struct hlist_root *hr, struct hlist_hnod *hnod)
{
    unsigned long flags;
    int rc;

    spin_lock_irqsave(&hr->lock, flags);
    rc = hlist_remove_node_nolock(hr, hnod);
    if (0 == rc && !hnod->flag_rcu) {
        hnod->flag_rcu = 1;
        call_rcu(&hnod->rcu, hlist_free_node_rcu);
    }
    spin_unlock_irqrestore(&hr->lock, flags);

    return 0;
}

int hlist_remove_key(struct hlist_root *hr, void *key)
{
    struct hlist_hnod *hnod;
    unsigned long flags;
    int rc;

    spin_lock_irqsave(&hr->lock, flags);
    hnod = hlist_lookup_key_noref(hr, key);
    if (hnod) {
        rc = hlist_remove_node_nolock(hr, hnod);
        if (0 == rc && !hnod->flag_rcu) {
            hnod->flag_rcu = 1;
            call_rcu(&hnod->rcu, hlist_free_node_rcu);
        }
    } else {
        rc = -ENOENT;
    }
    spin_unlock_irqrestore(&hr->lock, flags);

    return rc;
}

int hlist_deref_node(struct hlist_root *hr, struct hlist_hnod *hnod)
{
    unsigned long flags;
    int rc = atomic_dec_return(&hnod->refs);

    if (0 == rc) {
        spin_lock_irqsave(&hr->lock, flags);
        if (!hnod->flag_rcu) {
            hnod->flag_rcu = 1;
            call_rcu(&hnod->rcu, hlist_free_node_rcu);
        }
        spin_unlock_irqrestore(&hr->lock, flags);
    }
    return rc;
}

int hlist_deref_key(struct hlist_root *hr, void *key)
{
    struct hlist_hnod *hnod;
    int rc = -ENOENT;

    rcu_read_lock();
    hnod = hlist_lookup_key_noref(hr, key);
    if (hnod)
        rc = hlist_deref_node(hr, hnod);
    rcu_read_unlock();

    return rc;
}

static struct hlist_hnod *
hlist_insert_node_nolock(struct hlist_root *hr, void *key, struct hlist_hnod *hnod)
{
    int id = hr->hash(hr, key);

    list_add_tail_rcu(&hnod->link, &hr->lists[id]);
    atomic_inc(&hnod->refs);
    atomic_inc(&hr->count);
    return hnod;
}

struct hlist_hnod *
hlist_insert_key_nolock(struct hlist_root *hr, void *key)
{
    struct hlist_hnod *hnod;

    /* make sure it isn't in the hash list */
    hnod = hlist_lookup_key_noref(hr, key);
    if (hnod)
        goto errorout;

    /* initialize hnod from key */
    hnod = hr->init(hr, key);
    if (!hnod)
        goto errorout;

    /* insert new hnod into hash list */
    hnod = hlist_insert_node_nolock(hr, key, hnod);

errorout:
    return hnod;
}

struct hlist_hnod *hlist_insert_key(struct hlist_root *hr, void *key)
{
    struct hlist_hnod *hnod;
    unsigned long flags;

    spin_lock_irqsave(&hr->lock, flags);
    hnod = hlist_insert_key_nolock(hr, key);
    spin_unlock_irqrestore(&hr->lock, flags);
    return hnod;
}

int hlist_query_key(struct hlist_root *hr, void *key, void *node)
{
    struct hlist_hnod *hnod;

    rcu_read_lock();
    hnod = hlist_lookup_key_noref(hr, key);
    if (hnod)
        memcpy(node, hnod, hr->node);
    rcu_read_unlock();
    return !hnod;
}

void hlist_enum(struct hlist_root *hr, void (*cb)(struct hlist_hnod *))
{
    struct hlist_hnod *e;
    int i;

    rcu_read_lock();
    for (i = 0; i <= hr->nlists; i++) {
        list_for_each_entry_rcu(e, &hr->lists[i], link) {
            cb(e);
        }
    }
    rcu_read_unlock();
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 7, 0) || \
    LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 33)

#include <linux/kprobes.h>

static unsigned long (*kallsyms_lookup_name_sym)(const char *name);

static int _kallsyms_lookup_kprobe(struct kprobe *p, struct pt_regs *regs)
{
        return 0;
}

static unsigned long get_kallsyms_func(void)
{
        struct kprobe probe;
        int ret;
        unsigned long addr;

        memset(&probe, 0, sizeof(probe));
        probe.pre_handler = _kallsyms_lookup_kprobe;
        probe.symbol_name = "kallsyms_lookup_name";
        ret = register_kprobe(&probe);
        if (ret)
                return 0;
        addr = (unsigned long)probe.addr;
        unregister_kprobe(&probe);
        return addr;
}

unsigned long smith_kallsyms_lookup_name(const char *name)
{
        /* singleton */
        if (!kallsyms_lookup_name_sym) {
                kallsyms_lookup_name_sym = (void *)get_kallsyms_func();
                if(!kallsyms_lookup_name_sym)
                        return 0;
        }
        return kallsyms_lookup_name_sym(name);
}

#else

unsigned long smith_kallsyms_lookup_name(const char *name)
{
    return kallsyms_lookup_name(name);
}

#endif

u8 *smith_query_sb_uuid(struct super_block *sb)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 39)
    /* s_uuid not defined, using fixed zone of this sb */
    return (u8 *)sb + offsetof(struct super_block, s_dev);
#else
    /* u8 s_uuid[16] or uuid_t s_uuid */
    return (u8 *)sb + offsetof(struct super_block, s_uuid);
#endif
}

size_t smith_strnlen (const char *str, size_t maxlen)
{
    const char *char_ptr, *end_ptr = str + maxlen;
    const char *aligned;
    unsigned long longword, himagic, lomagic;

    if (!str || maxlen == 0)
        return 0;

    if (unlikely (end_ptr < str)) {
        end_ptr = (const char *) ~0UL;
        aligned = (const char *) ~(sizeof(longword) - 1UL);
    } else {
        unsigned long end = (unsigned long)end_ptr;
        aligned = (const char *)(end & ~(sizeof(longword) - 1UL));
    }

    /* Handle the first few characters by reading one character at a time.
       Do this until CHAR_PTR is aligned on a longword boundary.  */
    for (char_ptr = str; ((unsigned long)char_ptr & (sizeof(longword) - 1)) != 0;
         ++char_ptr) {
        if (char_ptr >= end_ptr)
            return end_ptr - str;
        else if (*char_ptr == 0)
            return char_ptr - str;
    }

    /* Bits 31, 24, 16, and 8 of this number are zero.  Call these bits
       the "holes."  Note that there is a hole just to the left of
       each byte, with an extra at the end:

       bits:  01111110 11111110 11111110 11111111
       bytes: AAAAAAAA BBBBBBBB CCCCCCCC DDDDDDDD

       The 1-bits make sure that carries propagate to the next 0-bit.
       The 0-bits provide holes for carries to fall into.  */
    himagic = 0x80808080L;
    lomagic = 0x01010101L;
    if (sizeof(longword) > 4) {
        /* 64-bit version of the magic.  */
        /* Do the shift in two steps to avoid a warning if long has 32 bits.  */
        himagic = ((himagic << 16) << 16) | himagic;
        lomagic = ((lomagic << 16) << 16) | lomagic;
    }
    CLASSERT(sizeof(longword) <= 8);

    /* Instead of the traditional loop which tests each character,
       we will test a longword at a time.  The tricky part is testing
       if *any of the four* bytes in the longword in question are zero.  */
    while (char_ptr < aligned) {
        /* We tentatively exit the loop if adding MAGIC_BITS to
	       LONGWORD fails to change any of the hole bits of LONGWORD.

	       1) Is this safe?  Will it catch all the zero bytes?
	       Suppose there is a byte with all zeros.  Any carry bits
	       propagating from its left will fall into the hole at its
	       least significant bit and stop.  Since there will be no
	       carry from its most significant bit, the LSB of the
	       byte to the left will be unchanged, and the zero will be
	       detected.

	       2) Is this worthwhile?  Will it ignore everything except
	       zero bytes?  Suppose every byte of LONGWORD has a bit set
	       somewhere.  There will be a carry into bit 8.  If bit 8
	       is set, this will carry into bit 16.  If bit 8 is clear,
	       one of bits 9-15 must be set, so there will be a carry
	       into bit 16.  Similarly, there will be a carry into bit
	       24.  If one of bits 24-30 is set, there will be a carry
	       into bit 31, so all of the hole bits will be changed.

	       The one misfire occurs when bits 24-30 are clear and bit
	       31 is set; in this case, the hole at bit 31 is not
	       changed.  If we had access to the processor carry flag,
	       we could close this loophole by putting the fourth hole
	       at bit 32!

	       So it ignores everything except 128's, when they're aligned
	       properly.  */
        longword = *((unsigned long *)char_ptr);
        if ((longword - lomagic) & himagic)	{
            int i;
            /* Is there a zero byte ? Continue search if misfires. */
            for (i = 0; i < sizeof(longword); i++) {
                if (char_ptr[i] == 0)
                    return char_ptr + i - str;

            }
        }
        char_ptr += sizeof(longword);
    }

    while (char_ptr < end_ptr) {
        if (!*char_ptr)
            break;
        char_ptr++;
    }

    return char_ptr - str;
}

#ifdef SMITH_STRNLEN_TESTING
#define TEST_STRNLEN_STR0  "123456"
#define TEST_STRNLEN_STR1  "_123456"
#define TEST_STRNLEN_STR2  "__123456"
#define TEST_STRNLEN_STR3  "___123456"
#define TEST_STRNLEN_STR4  "____123456"
#define TEST_STRNLEN_STR5  "_____123456"
#define TEST_STRNLEN_STR6  "123456789012345678"
#define TEST_STRNLEN_STR7  "_123456789012345678"
#define TEST_STRNLEN_STR8  "__123456789012345678"
#define TEST_STRNLEN_STR9  "___123456789012345678"
#define TEST_STRNLEN_STRA  "___123456789012345\000 6"
void smith_strnlen_test(void)
{
    printk("STR0: %px %ld\n", TEST_STRNLEN_STR0, smith_strnlen(&TEST_STRNLEN_STR0[0], 128));
    printk("STR1: %px %ld\n", TEST_STRNLEN_STR1, smith_strnlen(&TEST_STRNLEN_STR1[1], 128));
    printk("STR2: %px %ld\n", TEST_STRNLEN_STR2, smith_strnlen(&TEST_STRNLEN_STR2[2], 128));
    printk("STR3: %px %ld\n", TEST_STRNLEN_STR3, smith_strnlen(&TEST_STRNLEN_STR3[3], 128));
    printk("STR4: %px %ld\n", TEST_STRNLEN_STR4, smith_strnlen(&TEST_STRNLEN_STR4[4], 128));
    printk("STR5: %px %ld\n", TEST_STRNLEN_STR5, smith_strnlen(&TEST_STRNLEN_STR5[5], 128));
    printk("STR6: %px %ld\n", TEST_STRNLEN_STR6, smith_strnlen(&TEST_STRNLEN_STR6[0], 128));
    printk("STR7: %px %ld\n", TEST_STRNLEN_STR7, smith_strnlen(&TEST_STRNLEN_STR7[1], 128));
    printk("STR8: %px %ld\n", TEST_STRNLEN_STR8, smith_strnlen(&TEST_STRNLEN_STR8[2], 128));
    printk("STR9: %px %ld\n", TEST_STRNLEN_STR9, smith_strnlen(&TEST_STRNLEN_STR9[3], 128));
    printk("STRA: %px %ld\n", TEST_STRNLEN_STRA, smith_strnlen(&TEST_STRNLEN_STRA[0], 128));
    printk("STRB: %px %ld\n", TEST_STRNLEN_STRA, smith_strnlen(&TEST_STRNLEN_STRA[1], 128));
    printk("STRC: %px %ld\n", TEST_STRNLEN_STRA, smith_strnlen(&TEST_STRNLEN_STRA[2], 128));
    printk("STRD: %px %ld\n", TEST_STRNLEN_STRA, smith_strnlen(&TEST_STRNLEN_STRA[3], 128));
    printk("STRE: %px %ld\n", TEST_STRNLEN_STRA, smith_strnlen(&TEST_STRNLEN_STRA[4], 128));
    printk("STRF: %px %ld\n", TEST_STRNLEN_STRA, smith_strnlen(&TEST_STRNLEN_STRA[5], 128));
    printk("STRG: %px %ld\n", TEST_STRNLEN_STRA, smith_strnlen(&TEST_STRNLEN_STRA[6], 128));
}
#endif

char *smith_strstr(char *s, int sl, char *t)
{
    int start = 0, tl = (int)strlen(t);

    while (start + tl < sl) {
        if (!memcmp(s + start, t, tl))
            return s + start;
        start++;
    }

    return NULL;
}

uint64_t hash_murmur_OAAT64(char *s, int len)
{
    uint64_t h = 525201411107845655ull;
    int i;

    for (i = 0; i < len; i++) {
        h ^= (uint64_t)(s[i]);
        h *= 0x5bd1e9955bd1e995;
        h ^= h >> 47;
    }
    return h;
}

int smith_is_trusted_agent(char *agents[])
{
    int i;

    for (i = 0; agents[i]; i++) {
        if (strcmp(current->comm, agents[i]) == 0)
            return 1;
    }
    return 0;
}

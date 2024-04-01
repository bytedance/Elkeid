// SPDX-License-Identifier: GPL-2.0
/*
 * filter.c
 *
 * Data allowlist for hook
 */

#include "../include/kprobe.h"
#include "../include/filter.h"
#include "../include/util.h"
#include "../include/trace.h"

#define ALLOWLIST_NODE_MIN 4
#define ALLOWLIST_NODE_MAX 4090
#define ALLOWLIST_LIMIT 128

static struct rb_root execve_exe_allowlist = RB_ROOT;
static struct rb_root execve_argv_allowlist = RB_ROOT;
static int execve_exe_allowlist_limit = 0;
static int execve_argv_allowlist_limit = 0;
static DEFINE_RWLOCK(exe_allowlist_lock);
static DEFINE_RWLOCK(argv_allowlist_lock);

struct allowlist_node {
    struct rb_node node;
    char *data;
    uint64_t value;
    int len;
};

static int exist_rb_value(struct rb_root *root, uint64_t value)
{
    struct rb_node *node = root->rb_node;

    while (node) {
        struct allowlist_node *data = container_of(node, struct allowlist_node, node);
        if (value < data->value) {
            node = node->rb_left;
        } else if (value > data->value) {
            node = node->rb_right;
        } else {
            return 1;
        }
    }
    return 0;
}

static struct allowlist_node *search_rb(struct rb_root *root, char *string)
{
    struct rb_node *node = root->rb_node;
    uint64_t value;

    value = hash_murmur_OAAT64(string, strlen(string));

    while (node) {
        struct allowlist_node *data = container_of(node, struct allowlist_node, node);
        if (value < data->value) {
            node = node->rb_left;
        } else if (value > data->value) {
            node = node->rb_right;
        } else {
            return data;
        }
    }
    return NULL;
}

/*
 * return value description for insert_rb():
 *  0: succeeded to insert node to rbtree
 *  1: same record was already inserted
 */
static int insert_rb(struct rb_root *root, struct allowlist_node *data)
{
    struct rb_node **nod = &(root->rb_node), *parent = NULL;

    while (*nod) {
        struct allowlist_node *node = container_of(*nod, struct allowlist_node, node);
        parent = *nod;
        if (data->value < node->value) {
            nod = &((*nod)->rb_left);
        } else if (data->value > node->value) {
            nod = &((*nod)->rb_right);
        } else {
            return 1;
        }
    }

    rb_link_node(&data->node, parent, nod);
    rb_insert_color(&data->node, root);
    return 0;
}

static void rbtree_clear(struct rb_node *this_node)
{
    struct allowlist_node *node;

    if(!this_node)
        return;

    rbtree_clear(this_node->rb_left);
    rbtree_clear(this_node->rb_right);

    node = rb_entry(this_node, struct allowlist_node, node);
    smith_kfree(node->data);
    smith_kfree(node);
}

/**
 * description of return value:
 * 0: success, the new record was just added to rbtree
 * 1: failed, the record was already in the rbtree
 * < 0: error code
 */
static int add_execve_exe_allowlist(char *data)
{
    struct allowlist_node *node;
    int rc = 0;

    if (!data)
        return -EINVAL;

    node = smith_kzalloc(sizeof(struct allowlist_node), GFP_KERNEL);
    if (!node)
        return -ENOMEM;
    node->data = data;
    node->len = strlen(data);
    node->value = hash_murmur_OAAT64(data, node->len);

    write_lock(&exe_allowlist_lock);
    rc = insert_rb(&execve_exe_allowlist, node);
    if (!rc) {
        execve_exe_allowlist_limit++;
        write_unlock(&exe_allowlist_lock);
    } else {
        write_unlock(&exe_allowlist_lock);
        if (rc == 1)
            printk(KERN_INFO "[ELKEID] exe already added: %s\n", data);
        smith_kfree(node);
    }

    return rc;
}

static void del_execve_exe_allowlist(char *data)
{
    struct allowlist_node *node;

    write_lock(&exe_allowlist_lock);
    node = search_rb(&execve_exe_allowlist, data);
    if (node) {
        rb_erase(&node->node, &execve_exe_allowlist);
        execve_exe_allowlist_limit--;
    }
    write_unlock(&exe_allowlist_lock);

    if (node) {
        smith_kfree(node->data);
        smith_kfree(node);
    }
}

static int del_all_execve_exe_allowlist(void)
{
    write_lock(&exe_allowlist_lock);
    rbtree_clear(execve_exe_allowlist.rb_node);
    execve_exe_allowlist = RB_ROOT;
    execve_exe_allowlist_limit = 0;
    write_unlock(&exe_allowlist_lock);

    return 0;
}

static int print_execve_allowlist(const __user char *buf)
{
    struct rb_node *node;
    int len, sz = 0;

    read_lock(&exe_allowlist_lock);
    for (node = rb_first(&execve_exe_allowlist); node; node = rb_next(node)) {
        struct allowlist_node *data =
        container_of(node, struct allowlist_node, node);
        if (buf) {
            len = strlen(data->data) + 1;
            if (!smith_access_ok(buf + sz, len))
                break;
            if (copy_to_user((void *)(buf + sz), data->data, len))
                break;
            sz += len;
        } else {
            printk("[ELKEID DEBUG] execve_allowlist: %s\n", data->data);
        }
    }
    read_unlock(&exe_allowlist_lock);

    return sz;
}

static int execve_exe_check(char *data, int len, uint64_t value)
{
    int res;

    if (IS_ERR_OR_NULL(data) || len == 0 || value == 0)
        return 0;
    if (len == 2 && data[0] == '-' && (data[1] == '1' || data[1] == '2'))
        return 0;

    read_lock(&exe_allowlist_lock);
    res = exist_rb_value(&execve_exe_allowlist, value);
    read_unlock(&exe_allowlist_lock);

    return res;
}

/**
 * description of return value:
 * 0: success, the new record was just added to rbtree
 * 1: failed, the record was already in the rbtree
 * < 0: error code
 */
static int add_execve_argv_allowlist(char *data)
{
    struct allowlist_node *node;
    int rc = 0;

    if (!data)
        return -EINVAL;

    node = smith_kzalloc(sizeof(struct allowlist_node), GFP_KERNEL);
    if (!node)
        return -ENOMEM;
    node->data = data;
    node->len = strlen(data);
    node->value = hash_murmur_OAAT64(data, node->len);

    write_lock(&argv_allowlist_lock);
    rc = insert_rb(&execve_argv_allowlist, node);
    if (!rc) {
        execve_argv_allowlist_limit++;
        write_unlock(&argv_allowlist_lock);
    } else {
        write_unlock(&argv_allowlist_lock);
        if (rc == 1)
            printk(KERN_INFO"[ELKEID] cmd already added: %s\n", data);
        smith_kfree(node);
    }

    return rc;
}

static void del_execve_argv_allowlist(char *data)
{
    struct allowlist_node *node;

    write_lock(&argv_allowlist_lock);
    node = search_rb(&execve_argv_allowlist, data);
    if (node) {
        rb_erase(&node->node, &execve_argv_allowlist);
        execve_argv_allowlist_limit--;
    }
    write_unlock(&argv_allowlist_lock);

    if (node) {
        smith_kfree(node->data);
        smith_kfree(node);
    }
}

static int del_all_execve_argv_allowlist(void)
{
    write_lock(&argv_allowlist_lock);
    rbtree_clear(execve_argv_allowlist.rb_node);
    execve_argv_allowlist = RB_ROOT;
    execve_argv_allowlist_limit = 0;
    write_unlock(&argv_allowlist_lock);

    return 0;
}

static int print_argv_allowlist(const __user char *buf)
{
    struct rb_node *node;
    int len, sz = 0;
    read_lock(&argv_allowlist_lock);
    for (node = rb_first(&execve_argv_allowlist); node;
         node = rb_next(node)) {
        struct allowlist_node *data =
        container_of(node, struct allowlist_node, node);
        if (buf) {
            len = strlen(data->data) + 1;
            if (!smith_access_ok(buf + sz, len))
                break;
            if (copy_to_user((void *)(buf + sz), data->data, len))
                break;
            sz += len;
        } else {
            printk("[ELKEID DEBUG] argv_allowlist:%s \n", data->data);
        }
    }
    read_unlock(&argv_allowlist_lock);

    return sz;
}

static int execve_argv_check(char *data, int len)
{
    uint64_t value;
    int res;

    if (IS_ERR_OR_NULL(data) || len == 0)
        return 0;
    if (len == 2 && data[0] == '-' && (data[1] == '1' || data[1] == '2'))
        return 0;

    value = hash_murmur_OAAT64(data, len);
    read_lock(&exe_allowlist_lock);
    res = exist_rb_value(&execve_argv_allowlist, value);
    read_unlock(&exe_allowlist_lock);

    return res;
}

/*
 * rbtree of file md5 hash
 */

struct rb_root image_hash_list = RB_ROOT;
static DEFINE_RWLOCK(image_hash_lock);
struct image_hash_node {
    struct rb_node node;
    image_hash_t hash;
};

static void show_hash(image_hash_t *hash, char *msg)
{
    char md5[36] = {0};
    int i;
    for (i = 0; i < 16; i++)
        sprintf(&md5[i * 2], "%2.2x", hash->hash.v8[i]);
    printk("%s hash EL%6.6s %u %s %llu\n", msg, hash->id,
            hash->hlen, md5, hash->size);
}

static int hash_compare(image_hash_t *h1, image_hash_t *h2)
{
    uint16_t i;

    if (h1->size < h2->size)
        return -1;
    if (h1->size > h2->size)
        return 1;
    if (h1->hlen < h2->hlen)
        return -1;
    if (h1->hlen > h2->hlen)
        return 1;
    for (i = 0; i < h1->hlen; i++) {
        if (h1->hash.v8[i] < h2->hash.v8[i])
            return -1;
        if (h1->hash.v8[i] > h2->hash.v8[i])
            return 1;
    }
    return 0;
}

static int exist_rb_hash(struct rb_root *root, image_hash_t *hash)
{
    struct rb_node *node = root->rb_node;

    while (node) {
        struct image_hash_node *data;
        int rc;
        data = container_of(node, struct image_hash_node, node);
        rc = hash_compare(hash, &data->hash);
        if (rc < 0)
            node = node->rb_left;
        else if (rc > 0)
            node = node->rb_right;
        else {
            memcpy(hash->id, data->hash.id, sizeof(data->hash.id));
            return 1;
        }
    }
    return 0;
}

static struct image_hash_node *search_rb_hash(struct rb_root *root, image_hash_t *hash)
{
    struct rb_node *node = root->rb_node;

    while (node) {
        struct image_hash_node *data;
        int rc;
        data = container_of(node, struct image_hash_node, node);
        rc = hash_compare(hash, &data->hash);
        if (rc < 0)
            node = node->rb_left;
        else if (rc > 0)
            node = node->rb_right;
        else
            return data;
    }
    return NULL;
}

/*
 * return value description for insert_rb_hash():
 *  0: succeeded to insert node to rbtree
 *  1: same record was already inserted
 */
static int insert_rb_hash(struct rb_root *root, struct image_hash_node *hash)
{
    struct rb_node **nod = &(root->rb_node), *parent = NULL;

    while (*nod) {
        struct image_hash_node *data;
        int rc;
        parent = *nod;
        data = container_of(parent, struct image_hash_node, node);
        rc = hash_compare(&hash->hash, &data->hash);
        if (rc < 0)
            nod = &(parent->rb_left);
        else if (rc > 0)
            nod = &(parent->rb_right);
        else
            return 1;
    }

    rb_link_node(&hash->node, parent, nod);
    rb_insert_color(&hash->node, root);
    return 0;
}

static void clear_rb_hash(struct rb_node *node)
{
    struct image_hash_node *data;

    if(!node)
        return;

    clear_rb_hash(node->rb_left);
    clear_rb_hash(node->rb_right);

    data = rb_entry(node, struct image_hash_node, node);
    smith_kfree(data);
}

static int image_md5_add(image_hash_t *md5)
{
    struct image_hash_node *node;
    int rc = 0;

    if (!md5)
        return -EINVAL;

    node = smith_kzalloc(sizeof(struct image_hash_node), GFP_KERNEL);
    if (!node)
        return -ENOMEM;
    memcpy(&node->hash, md5, sizeof(image_hash_t));

    write_lock(&image_hash_lock);
    rc = insert_rb_hash(&image_hash_list, node);
    if (!rc) {
        write_unlock(&image_hash_lock);
    } else {
        write_unlock(&image_hash_lock);
        if (rc == 1) {
            show_hash(&node->hash, "DUPED:");
            printk(KERN_INFO"[ELKEID] hash already added.\n");
        }
        smith_kfree(node);
    }

    return rc;
}

static void image_md5_del(image_hash_t *md5)
{
    struct image_hash_node *node;

    write_lock(&image_hash_lock);
    node = search_rb_hash(&image_hash_list, md5);
    if (node)
        rb_erase(&node->node, &image_hash_list);
    write_unlock(&image_hash_lock);

    if (node)
        smith_kfree(node);
}

static int image_md5_clear(void)
{
    write_lock(&image_hash_lock);
    clear_rb_hash(image_hash_list.rb_node);
    image_hash_list = RB_ROOT;
    write_unlock(&image_hash_lock);

    return 0;
}

static int image_md5_check(image_hash_t *md5)
{
    int rc;

    read_lock(&image_hash_lock);
    if (md5)
        rc = exist_rb_hash(&image_hash_list, md5);
    else
        rc = (image_hash_list.rb_node != NULL);
    read_unlock(&image_hash_lock);

    return rc;
}

static void image_md5_enum(void)
{
    struct rb_node *nod;

    read_lock(&image_hash_lock);
    for (nod = rb_first(&image_hash_list); nod;
         nod = rb_next(nod)) {
        struct image_hash_node *hash = (void *)nod;
        show_hash(&hash->hash, "MD5:  ");
    }
    read_unlock(&image_hash_lock);
}

/*
 * exe_path / cmdline blocking rules
 */

static DEFINE_RWLOCK(exe_rule_lock);
HLIST_HEAD(exe_rule_list);

struct rule_item {
    int16_t            *next;
    char               *item;
    int16_t             size;
    int16_t             align;
} __attribute__((packed));

struct rule_node {
    struct hlist_node   link;
    char                id[8];
    struct rule_item    items[4];
    int16_t             nitems;
    int16_t             size;
    char                data[];
} __attribute__((packed));

static void rule_kmp_next(struct rule_item *ri)
{
    int16_t i = 0, j = -1;

    ri->next[0] = -1;
    do {
        if (j == -1 || ri->item[i] == ri->item[j]) {
            i++;
            j++;
            ri->next[i] = j;
        } else {
            j = ri->next[j];
        }
    } while (i < ri->size);
}

static int rule_kmp_match(struct rule_item *ri, struct exe_item *ei)
{
    int16_t i = 0, j = 0;

    if (!ri->size || !ri->item)
        return 1;
    if (ri->size > ei->size)
        return 0;

    while (i < ei->size) {
        if (j == -1 || ei->item[i] == ri->item[j]) {
            i++;
            j++;
            if (j == ri->size)
                return 1;
        } else {
            j = ri->next[j];
        }
    }
    return 0;
}

#if 0
static void smith_hexdump(void *ptr, int len)
{
    uint8_t *dat = ptr;
    char str[18] = {0}, hex[50] = {0};
    int i, j;

    for  (i = 0; i < len; i += 16) {
        memset(str, '.', 16);
        memset(hex, ' ', 48);
        for (j = 0; j < 16; j++) {
            if (i + j < len) {
                sprintf(&hex[3 * j], "%2.2X ", dat[i + j]);
                if (dat[i + j] >= 0x20 && dat[i + j] <= 0x7e)
                    str[j] = dat[i + j];
            } else {
                sprintf(&hex[3 * j], "   ");
            }
        }
        printk("%8.8x %s | %s\n", i, hex, str);
    }
}
#endif

static struct rule_node *rule_alloc(exe_rule_flex_t *rule)
{
    struct rule_node *nod;
    int next = 0, lnod, data, i;

    if (rule->nitems != 4)
        return NULL;

    for (i = 0; i < rule->nitems; i++) {
        if (!rule->items[i].len)
            continue ;
        if (sizeof(exe_rule_flex_t) + rule->items[i].off >=
            rule->size)
            return NULL;
        next += rule->items[i].len + 1;
    }
    if (!next)
        return NULL;

    lnod = sizeof(struct rule_node) + next * (sizeof(int16_t) + 1);
    nod = smith_kzalloc(lnod, GFP_KERNEL);
    if (!nod)
        return NULL;
    memcpy(nod->id, rule->id, sizeof(nod->id));
    nod->nitems = rule->nitems;

    data = next * sizeof(int16_t);
    next = 0;
    for (i = 0; i < rule->nitems; i++) {
        if (!rule->items[i].len)
            continue;
        nod->items[i].next = (int16_t *)&nod->data[next * sizeof(int16_t)];
        nod->items[i].item = (char *)&nod->data[data + next];
        nod->items[i].size = rule->items[i].len;
        memcpy(nod->items[i].item, &rule->data[rule->items[i].off],
               rule->items[i].len + 1);
        rule_kmp_next(&nod->items[i]);
        next += nod->items[i].size + 1;
    }
    // smith_hexdump(nod, lnod);
    return nod;
}

static struct rule_node *rule_add(struct hlist_head *list,
                    rwlock_t *lock, exe_rule_flex_t *rule)
{
    struct rule_node *nod;

    nod = rule_alloc(rule);
    if (!nod)
        return nod;

    write_lock(lock);
    hlist_add_head(&nod->link, list);
    write_unlock(lock);
    return nod;
}

static int rule_del(struct hlist_head *list,
            rwlock_t *lock, char *id)
{
    struct rule_node *nod = NULL;
    struct hlist_node *ent;

    write_lock(lock);
    hlist_for_each(ent, list) {
        nod = hlist_entry(ent, struct rule_node, link);
        if (!memcmp(nod->id, id, sizeof(nod->id)))
            break;
        else
            nod = NULL;
    }
    if (nod)
        hlist_del(&nod->link);
    write_unlock(lock);

    if (nod)
        smith_kfree(nod);

    return (nod != NULL);
}

static int rule_match(struct hlist_head *list,
            rwlock_t *lock, struct exe_item *ei,
            int nitems, char *id)
{
    struct rule_node *nod = NULL;
    struct hlist_node *ent;
    int rc;

    read_lock(lock);
    if (ei) {
        hlist_for_each(ent, list) {
            int i;
            nod = hlist_entry(ent, struct rule_node, link);
            if (nitems != nod->nitems)
                continue;
            for (i = 0; i < nod->nitems; i++) {
                if (!rule_kmp_match(&nod->items[i], &ei[i]))
                    break;
            }
            if (i >= nod->nitems)
                break;
            else
                nod = NULL;
        }
        if (nod)
            memcpy(id, nod->id, sizeof(nod->id));
        rc = (nod != NULL);
    } else {
        rc = !hlist_empty(list);
    }
    read_unlock(lock);

    return rc;
}

static int rule_clear(struct hlist_head *list, rwlock_t *lock)
{
    struct hlist_node *ent, *next;
    struct rule_node *nod;

    write_lock(lock);
    hlist_for_each_safe(ent, next, list) {
        nod = hlist_entry(ent, struct rule_node, link);
        hlist_del(&nod->link);
        smith_kfree(nod);
    }
    write_unlock(lock);
    return 0;
}
static void rule_enum(struct hlist_head *list, rwlock_t *lock)
{
    struct hlist_node *ent;
    struct rule_node *nod;
    int i = 0;

    read_lock(lock);
    printk("enuming exe/cmd rules: %px\n", list);
    hlist_for_each(ent, list) {
        nod = hlist_entry(ent, struct rule_node, link);
        printk("%4d: %8.8s %d %s|%s|%s|%s\n",
                i++, nod->id, nod->nitems,
                nod->items[0].item ? nod->items[0].item : "(null)",
                nod->items[1].item ? nod->items[1].item : "(null)",
                nod->items[2].item ? nod->items[2].item : "(null)",
                nod->items[3].item ? nod->items[3].item : "(null)");
    }
    read_unlock(lock);
}

static int rule_check(struct exe_item *items, int nitems, char *id)
{
    return rule_match(&exe_rule_list, &exe_rule_lock,
                      items, nitems, id);
}

/*
 * psad allowlist checking: ipv4
 */
static struct psad_ip4_list {
    struct rcu_head    rcu;
    struct ipaddr_v4 *ip4s;
    struct psad_ip_list list;
} *g_ip4_list;

static void psad_free_list_rcu(struct rcu_head *rcu)
{
    printk("ip allowlist %px to be freed.\n", rcu);
    smith_kfree(rcu);
}

static int psad_ip4_check(uint32_t ip)
{
    struct psad_ip4_list *psad;
    int rc = 0, first = 0, last, mid;

    rcu_read_lock();
    /* just skip if there's no allowlist */
    psad = rcu_dereference(g_ip4_list);
    if (!psad) {
        rcu_read_unlock();
        return 0;
    }

    /* using bi-search to check whether it's allowed */
    last = psad->list.nips - 1;
    while (first <= last) {
        mid = (first + last) / 2;
        rc = (psad->ip4s[mid].v4_addr32 == ip);
        if (rc)
            break;
        if (psad->ip4s[mid].v4_addr32 > ip)
            last = mid - 1;
        else
            first = mid + 1;
    }
    rcu_read_unlock();

    return rc;
}

static int psad_ip4_clear(void)
{
    struct psad_ip4_list *list = READ_ONCE(g_ip4_list);

    if (!list)
        return 0;

    do {
        if (cmpxchg(&g_ip4_list, list, NULL) == list)
            break;
        list = READ_ONCE(g_ip4_list);
    } while (list);

    if (list)
        call_rcu(&list->rcu, psad_free_list_rcu);

    return 1;
}

static int psad_ip4_set(struct psad_ip4_list *psad)
{
    struct psad_ip4_list *list = READ_ONCE(g_ip4_list);
    uint32_t *ip4s = (uint32_t *)psad->ip4s;
    int i, sorted, nips = psad->list.nips;

    do {
        sorted = 1;
        for (i = 1; i < nips; i++) {
            if (ip4s[i - 1] > ip4s[i]) {
                uint32_t ip = ip4s[i - 1];
                ip4s[i - 1] = ip4s[i];
                ip4s[i] = ip;
                sorted = 0;
            }
        }
    } while (!sorted);

    printk("allowed ipv4 addrs to bypass psad:");
    for (i = 0; i < nips; i++) {
        uint8_t *d = (uint8_t *)&ip4s[i];
        printk("%4d: %u.%u.%u.%u\n", i, d[0], d[1], d[2], d[3]);
    }

    do {
        if (cmpxchg(&g_ip4_list, list, psad) == list)
            break;
        list = READ_ONCE(g_ip4_list);
    } while (list);

    if (list)
        call_rcu(&list->rcu, psad_free_list_rcu);

    return offsetof(struct psad_ip_list, ips) +
           nips * sizeof(struct ipaddr_v4);
}

static struct psad_ip6_list {
    struct rcu_head    rcu;
    struct ipaddr_v6 *ip6s;
    struct psad_ip_list list;
} *g_ip6_list;

static int psad_ip6_compare(struct ipaddr_v6 *a1, struct ipaddr_v6 *a2)
{
    int i;

    for (i = 0; i < 4; i++) {
        if (a1->v6_addr32[i] > a2->v6_addr32[i])
            return 1;
        if (a1->v6_addr32[i] < a2->v6_addr32[i])
            return -1;
    }

    return 0;
}

static int psad_ip6_check(uint32_t *ip)
{
    struct psad_ip6_list *psad;
    struct ipaddr_v6 *a6 = (void *)ip;
    int rc = 0, first = 0, last, mid;

    rcu_read_lock();
    /* just skip if there's no allowlist */
    psad = rcu_dereference(g_ip6_list);
    if (!psad) {
        rcu_read_unlock();
        return 0;
    }

    /* using bi-search to check whether it's allowed */
    last = psad->list.nips - 1;
    while (first <= last) {
        mid = (first + last) / 2;
        rc = psad_ip6_compare(&psad->ip6s[mid], a6);
        if (rc == 0)
            break;
        if (rc > 0)
            last = mid - 1;
        else
            first = mid + 1;
    }
    rcu_read_unlock();

    return !rc;
}

static int psad_ip6_clear(void)
{
    struct psad_ip6_list *list = READ_ONCE(g_ip6_list);

    if (!list)
        return 0;

    do {
        if (cmpxchg(&g_ip6_list, list, NULL) == list)
            break;
        list = READ_ONCE(g_ip6_list);
    } while (list);

    if (list)
        call_rcu(&list->rcu, psad_free_list_rcu);

    return 1;
}

static int psad_ip6_set(struct psad_ip6_list *psad)
{
    struct psad_ip6_list *list = READ_ONCE(g_ip6_list);
    int i, sorted, nips = psad->list.nips;

    do {
        sorted = 1;
        for (i = 1; i < nips; i++) {
            int rc = psad_ip6_compare(&psad->ip6s[i - 1],
                                      &psad->ip6s[i]);
            if (rc > 0) {
                struct ipaddr_v6 a6 = psad->ip6s[i - 1];
                psad->ip6s[i - 1] = psad->ip6s[i];
                psad->ip6s[i] = a6;
                sorted = 0;
            }
        }
    } while (!sorted);

    printk("allowed ipv6 addrs to bypass psad:");
    for (i = 0; i < nips; i++) {
        uint16_t *d = (uint16_t *)&psad->ip6s[i];
        printk("%4d: %04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x\n",
                i, ntohs(d[0]), ntohs(d[1]), ntohs(d[2]), ntohs(d[3]),
                ntohs(d[4]), ntohs(d[5]), ntohs(d[6]), ntohs(d[7]));
    }

    do {
        if (cmpxchg(&g_ip6_list, list, psad) == list)
            break;
        list = READ_ONCE(g_ip6_list);
    } while (list);

    if (list)
        call_rcu(&list->rcu, psad_free_list_rcu);

    return offsetof(struct psad_ip_list, ips) +
           nips * sizeof(struct ipaddr_v6);
}

static int psad_set_ip_list(char *data, int len)
{
    struct psad_ip4_list *ip4s = (void *)data;
    struct psad_ip6_list *ip6s = (void *)data;

    if (ip4s->list.type == 4) {
        ip4s->ip4s = (struct ipaddr_v4 *)ip4s->list.ips;
        return psad_ip4_set(ip4s);
    } else if (ip6s->list.type == 10) {
        ip6s->ip6s = (struct ipaddr_v6 *)ip6s->list.ips;
        return psad_ip6_set(ip6s);
    }
    return 0;
}

static int filter_ioctl_internal(int cmd, char *data, int len)
{
    int rc = -EINVAL;

    switch (cmd) {

        case IMAGE_MD5_ADD:
            rc = image_md5_add((image_hash_t *)data);
            goto out;
        case IMAGE_MD5_DEL:
            image_md5_del((image_hash_t *)data);
            rc = 0;
            goto out;
        case IMAGE_MD5_CHK:
            goto out;
        case IMAGE_MD5_ENUM:
            image_md5_enum();
            rc = 0;
            goto out;

        case IMAGE_EXE_ADD:
            // smith_hexdump(data, len);
            if (rule_add(&exe_rule_list, &exe_rule_lock,
                         (exe_rule_flex_t *)data))
                rc = 0;
            goto out;
        case IMAGE_EXE_DEL:
            if (rule_del(&exe_rule_list, &exe_rule_lock, data))
                rc = 0;
            goto out;
        case IMAGE_EXE_CHK:
            goto out;
        case IMAGE_EXE_ENUM:
            rule_enum(&exe_rule_list, &exe_rule_lock);
            rc = 0;
            goto out;
        case PSAD_IP_LIST:
            rc = psad_set_ip_list(data, len);
            if (rc > 0)
                data = NULL;
            goto out;
    }

    /* remove spaces in prefix or suffix */
    smith_strim(data, len);
    len = strnlen(data, len);

    switch (cmd) {
        case ADD_EXECVE_EXE_ALLOWLIST:
            rc = add_execve_exe_allowlist(data);
            if (!rc)
                data = NULL;
            break;

        case DEL_EXECVE_EXE_ALLOWLIST:
            del_execve_exe_allowlist(data);
            rc = 0;
            break;

        case EXECVE_EXE_CHECK:
        {
            uint64_t hash = hash_murmur_OAAT64(data, len);
            rc = execve_exe_check(data, len, hash);
            printk("[ELKEID DEBUG] execve_exe_check: %d %s\n", rc, data);
            break;
        }

        case ADD_EXECVE_ARGV_ALLOWLIST:
            rc = add_execve_argv_allowlist(data);
            if (!rc)
                data = NULL;
            break;

        case DEL_EXECVE_ARGV_ALLOWLIST:
            del_execve_argv_allowlist(data);
            rc = 0;
            break;

        case EXECVE_ARGV_CHECK:
            rc = execve_argv_check(data, len);
            printk("[ELKEID DEBUG] execve_argv_check: %d %s\n", rc, data);
            break;

        default:
            break;
    }

out:
    smith_kfree(data);
    return rc;
}

static int filter_ioctl(int cmd, const __user char *buf)
{
    char *data = NULL;
    int rc = -EINVAL, len = 0, skip = 0;

    /* cmd should be TRACE_IOCTL_FILTER + command */
    cmd -= TRACE_IOCTL_FILTER;
    if (cmd <= 0)
        goto errorout;

    /* process short-cmds, avoiding memory allocation */
    if (cmd == DEL_ALL_EXECVE_EXE_ALLOWLIST)
        return del_all_execve_exe_allowlist();
    else if (cmd ==  DEL_ALL_EXECVE_ARGV_ALLOWLIST)
        return del_all_execve_argv_allowlist();
    else if (cmd == PRINT_EXE_ALLOWLIST)
        return print_execve_allowlist(buf);
    else if (cmd == PRINT_ARGV_ALLOWLIST)
        return print_argv_allowlist(buf);
    else if (cmd == IMAGE_MD5_CLR)
        return image_md5_clear();
    else if (cmd == IMAGE_EXE_CLR)
        return rule_clear(&exe_rule_list, &exe_rule_lock);
    else if (cmd == REGISTER_BINFMT)
        return smith_register_exec_load();
    else if (cmd == UNREGISTER_BINFMT)
        return smith_unregister_exec_load();
    else if (cmd == PSAD_IP_LIST && !buf) {
        psad_ip4_clear();
        psad_ip6_clear();
        return 0;
    }

    /* check whether length is valid */
    if (cmd == IMAGE_MD5_ADD || cmd == IMAGE_MD5_DEL) {
        len = sizeof(image_hash_t);
    } else if (cmd == IMAGE_MD5_CHK) {
        len = sizeof(image_hash_t);
    } else if (cmd == IMAGE_EXE_ADD) {
        if (smith_copy_from_user(&len, buf, 2))
            goto errorout;
        if (len <= sizeof(exe_rule_flex_t))
            goto errorout;
    } else if (cmd == IMAGE_EXE_DEL || cmd == IMAGE_EXE_CHK) {
        len = 8;
    } else if (cmd == PSAD_IP_LIST) {
        struct psad_ip_list list;
        if (smith_copy_from_user(&list, buf, sizeof(list)))
            goto errorout;
        if (list.type != 4 && list.type != 10)
            goto errorout;
        if (!list.nips) {
            if (list.type == 4)
                psad_ip4_clear();
            else
                psad_ip6_clear();
            goto errorout;
        }
        if (list.type == 4) {
            skip = offsetof(struct psad_ip4_list, list);
            len = (list.nips + 2) * sizeof(uint32_t) + skip;
        } else {
            skip = offsetof(struct psad_ip6_list, list);
            len = (list.nips * 4 + 2) * sizeof(uint32_t) + skip;
        }
    } else {
        len = strnlen_user(buf, ALLOWLIST_NODE_MAX);
        if (len < ALLOWLIST_NODE_MIN)
            goto errorout;
    }

    /* try to grab user's input parameters */
    if (!smith_access_ok(buf, len))
        goto errorout;
    data = smith_kzalloc(len + 1, GFP_KERNEL);
    if (!data)
        return -ENOMEM;
    if (smith_copy_from_user(data + skip, buf, len - skip)) {
        smith_kfree(data);
        goto errorout;
    }

    /* data_main to be handled internally */
    rc = filter_ioctl_internal(cmd, data, len);

errorout:
    return rc;
}

/* module prameters set callback */
static int filter_store(const char *buf, int len)
{
    char *data = NULL;
    int rc = -EINVAL, cmd, i;

    /* remove spaces in prefix or suffix */
    for (i = 0; i < len; i++) {
        if (!isspace(buf[i]))
            break;
    }
    if (i >= len)
        return rc;
    cmd = buf[i];
    if (cmd <= 0)
        goto errorout;
    buf = buf + i + 1;

    /* process short-cmds, avoiding memory allocation */
    if (cmd == DEL_ALL_EXECVE_EXE_ALLOWLIST) {
        del_all_execve_exe_allowlist();
        goto errorout;
    } else if (cmd ==  DEL_ALL_EXECVE_ARGV_ALLOWLIST) {
        del_all_execve_argv_allowlist();
        goto errorout;
    } else if (cmd == PRINT_EXE_ALLOWLIST) {
        print_execve_allowlist(NULL);
        goto errorout;
    } else if (cmd == PRINT_ARGV_ALLOWLIST) {
        print_argv_allowlist(NULL);
        goto errorout;
    } else if (cmd == IMAGE_MD5_CLR) {
        image_md5_clear();
        goto errorout;
    } else if (cmd == IMAGE_MD5_ENUM) {
        image_md5_enum();
        goto errorout;
    } else if (cmd == IMAGE_EXE_CLR) {
        rule_clear(&exe_rule_list, &exe_rule_lock);
        goto errorout;
    } else if (cmd == IMAGE_EXE_ENUM) {
        rule_enum(&exe_rule_list, &exe_rule_lock);
        goto errorout;
    } else if (cmd == REGISTER_BINFMT) {
        rc = smith_register_exec_load();
        goto errorout;
    } else if (cmd == UNREGISTER_BINFMT) {
        rc = smith_unregister_exec_load();
        goto errorout;
    }

    /* check whether length is valid */
    if (cmd == IMAGE_MD5_ADD || cmd == IMAGE_MD5_DEL) {
        goto errorout;
    } else if (cmd == IMAGE_EXE_ADD) {
        exe_rule_flex_t *rule = (void *)buf;
        if (rule->size > len - i)
            goto errorout;
        len = rule->size;
        if (len <= sizeof(exe_rule_flex_t))
            goto errorout;
    } else if (cmd == IMAGE_EXE_DEL || cmd == IMAGE_EXE_CHK) {
        len = 8;
    } else {
        len = strnlen(buf, len - i);
        if (len < ALLOWLIST_NODE_MIN || len > ALLOWLIST_NODE_MAX)
            goto errorout;
    }

    /* try to grab user's input parameters */
    data = smith_kzalloc(len + 1, GFP_KERNEL);
    if (!data)
        return -ENOMEM;
    memcpy(data, buf, len);

    /* data_main to be handled internally */
    rc = filter_ioctl_internal(cmd, data, len);

errorout:
    /* return len to reset offset */
    return len;
}

struct filter_ops g_flt_ops = {
    .exe_check = execve_exe_check,      /* exe_path checking: in allowlsit or not */
    .argv_check = execve_argv_check,    /* cmdline/argv checking */
    .hash_check = image_md5_check,      /* md5 hash blocklist checking */
    .rule_check = rule_check,           /* exe/cmd blocklist checking */
    .ipv4_check = psad_ip4_check,       /* ipv4 allowlist */
    .ipv6_check = psad_ip6_check,       /* ipv6 allowlist */
    .ioctl = filter_ioctl,              /* interfaces for user ioctl */
    .store = filter_store,              /* callback of module param settings */
};

static int __init filter_init(void)
{
    return 0;
}

static void filter_exit(void)
{
    del_all_execve_exe_allowlist();
    del_all_execve_argv_allowlist();
    image_md5_clear();
    rule_clear(&exe_rule_list, &exe_rule_lock);
    if (psad_ip4_clear() + psad_ip6_clear())
        rcu_barrier();
}

KPROBE_INITCALL(filter, filter_init, filter_exit);

// SPDX-License-Identifier: GPL-2.0
/*
 * filter.c
 *
 * Data allowlist for hook
 */

#include "../include/filter.h"
#include "../include/util.h"


#define ADD_EXECVE_EXE_ALLOWLIST 89         /* Y */
#define DEL_EXECVE_EXE_ALLOWLIST 70         /* F */
#define DEL_ALL_EXECVE_EXE_ALLOWLIST 119    /* w */
#define EXECVE_EXE_CHECK 121                /* y */
#define PRINT_ALL_ALLOWLIST 46              /* . */
#define ADD_EXECVE_ARGV_ALLOWLIST 109       /* m */
#define DEL_EXECVE_ARGV_ALLOWLIST 74        /* J */
#define DEL_ALL_EXECVE_ARGV_ALLOWLIST 117   /* u */
#define EXECVE_ARGV_CHECK 122               /* z */

#define ADD_WRITE_NOTIFI 87                 /* W */
#define DEL_WRITE_NOTIFI 120                /* v */
#define ADD_READ_NOTIFI 82                  /* R */
#define DEL_READ_NOTIFI 114                 /* r */
#define DEL_ALL_NOTIFI 65                   /* A */

#define ALLOWLIST_NODE_MIN 5
#define ALLOWLIST_NODE_MAX 4090
#define ALLOWLIST_LIMIT 128

static struct class *filter_class;
static int filter_major;
static char *sh_mem = NULL;

struct rb_root execve_exe_allowlist = RB_ROOT;

struct rb_root execve_argv_allowlist = RB_ROOT;

struct rb_root file_notify_checklist = RB_ROOT;

static int execve_exe_allowlist_limit = 0;

static int execve_argv_allowlist_limit = 0;

static int file_notify_checklist_limit = 512;

static DEFINE_RWLOCK(exe_allowlist_lock);
static DEFINE_RWLOCK(argv_allowlist_lock);
static DEFINE_RWLOCK(file_notify_checklist_lock);

static int device_mmap(struct file *filp, struct vm_area_struct *vma);

static ssize_t device_write(struct file *filp, const __user char *buff,
                            size_t len, loff_t * off);

static const struct file_operations mchar_fops = {
        .owner = THIS_MODULE,
        .mmap = device_mmap,
        .write = device_write,
};

struct allowlist_node {
    struct rb_node node;
    char *data;
};

struct file_notify_node {
    struct rb_node node;
    unsigned long  ino;
    uint32_t       size;
    uint32_t       used;
    char          *data;
};

/* entry of file path & mask */
struct mask_item {
    u8 *uuid;
    const char *name;
    unsigned long ino;
    int nlen;
    uint32_t mask;
};

/* result for entry lookup */
struct mask_info {
    char *tag;
    char *item;
    int ret;
    int nameonly;
};

/*
 *           1         2         3         4         5         6
 * 01234567890123456789012345678901234567890123456789012345678901234567890
 * |->0-sz-|->       uuid          <-|mask|->name, |mask|->name ....
 */

#define STTAG    "|->:"                             /* tag of volume policy string */
#define SOTAG    (4)                                /* sizeof tag */
#define SOSIZE   SOTAG                              /* start of size (of volume policy) */
#define SOUUID   (SOSIZE  + sizeof(uint32_t))       /* start of volume uuid */
#define SOMASK   (SOUUID + 16)                      /* start of mask of file path entry */
#define SONAME   (SOMASK + sizeof(uint32_t))        /* start of file path name */

#define TAG_SIZE(tag)  *((uint32_t *)((tag) + SOSIZE))

int _mask_assert(struct file_notify_node *node)
{
    return (memcmp(node->data, STTAG, SOTAG) || 0 == TAG_SIZE(node->data) ||
            TAG_SIZE(node->data) > node->used);
}

char *_mask_lookup(struct file_notify_node *node, struct mask_item *id, struct mask_info *mi)
{
    char *s = node->data, *t = NULL;
    uint32_t len = 0, i = SOMASK;
    int rc;

    if (!node->data || node->used <= SONAME) {
        if (mi)
            mi->ret = -1;
        return NULL;
    }

    if (_mask_assert(node)) {
        memset(node->data, 0, node->size);
        node->used = 0;
        if (mi)
            mi->ret = -1;
        return NULL;
    }

    do {
        char *tag = smith_strstr(s, (int)(node->used - (s - node->data)), STTAG);

        if (!tag)
            break;

        len = TAG_SIZE(tag);
        s += len;
        rc = memcmp(id->uuid, tag + SOUUID, 16);

        if (0 == rc) {
            t = tag;
            if (mi) {
                mi->ret = 0;
                mi->tag = tag;
            }
            break;
        }

        if (rc < 0) {
            if (mi) {
                mi->ret = -1;
                mi->tag = tag;
            }
        } else if (rc > 0) {
            if (mi) {
                mi->ret = 1;
                mi->tag = tag;
            }
        }
    } while (s - node->data < node->used);

    if (!t)
        return t;

    do {
        char *name = t + i + sizeof(uint32_t);

        if (!mi || !mi->nameonly) {
            if (!(*((uint32_t *)(t + i)) & id->mask)) {
                i += sizeof(uint32_t) + ALIGN(strlen(name) + 1, 4);
                continue;
            }
        }

        if (id->nlen == strlen(name) &&
            !memcmp(id->name, name, id->nlen)) {
            if (mi)
                mi->item = t + i;
            return t + i;
        }

        i += sizeof(uint32_t) + ALIGN(strlen(name) + 1, 4);
    } while (i < len);

    return NULL;
}

int _mask_realloc(struct file_notify_node *node)
{
    char *buf;
    uint32_t size;

    if (node->size)
        size = node->size * 2;
    else
        size = file_notify_checklist_limit;
    buf = smith_kzalloc(size, GFP_ATOMIC);
    if (!buf)
        return -ENOMEM;
    if (node->data) {
        if (node->used)
            memcpy(buf, node->data, node->used);
        smith_kfree(node->data);
    }
    node->data = buf;
    node->size = size;

    return 0;
}

int _mask_insert(struct file_notify_node *node, struct mask_item *id)
{
    struct mask_info mi;
    uint32_t len;
    char *e;
    int rc = 0;

retry:
    memset(&mi, 0, sizeof(mi));
    mi.nameonly = 1;
    if (_mask_lookup(node, id, &mi)) {
        /* same entry already in queue */
        *((uint32_t *)mi.item) |= id->mask;
        goto errorout;
    }

    if (mi.tag && memcmp(mi.tag, STTAG, SOTAG)) {
        BUG();
    }

    if (0 == mi.ret) {
        /* same uuid already in queue */
        len = ALIGN(sizeof(len) + id->nlen + 1, 4);
        if (node->used + len > node->size) {
            if (_mask_realloc(node)) {
                rc = -ENOMEM;
                goto errorout;
            }
            /* retry lookup: since node->data was changed so mi.tag was invalid */
            goto retry;
        }
        /* spare space from 1st names */
        TAG_SIZE(mi.tag) += len;
        e = mi.tag + SOMASK + len;
        memmove(e, mi.tag + SOMASK, node->used - (mi.tag - node->data));
        memcpy(mi.tag + SOMASK, &id->mask, sizeof(uint32_t));
        memcpy(mi.tag + SONAME, id->name, id->nlen);
        memset(mi.tag + SONAME + id->nlen, 0, len - id->nlen - sizeof(uint32_t));
        node->used += len;
    } else {
        len = SOMASK + ALIGN(sizeof(len) + id->nlen + 1, 4);
        if (node->used + len > node->size) {
            if (_mask_realloc(node)) {
                rc = -ENOMEM;
                goto errorout;
            }
            /* retry lookup: since node->data was changed so mi.tag was invalid */
            goto retry;
        }
        if (mi.tag && mi.ret > 0) {
            /* need handle inertion in the middle */
            memmove(mi.tag + len, mi.tag, node->used - (mi.tag - node->data));
        } else {
            /* just append to the tail */
            mi.tag = node->data + node->used;
        }
        memcpy(mi.tag, STTAG, SOTAG);
        memcpy(mi.tag + SOSIZE, &len, sizeof(len));
        memcpy(mi.tag + SOUUID, id->uuid, 16);
        memcpy(mi.tag + SOMASK, &id->mask, sizeof(uint32_t));
        memcpy(mi.tag + SONAME, id->name, id->nlen);
        memset(mi.tag + SONAME + id->nlen, 0, len - id->nlen - SONAME);
        node->used += len;
    }

errorout:
    return rc;
}

int _mask_remove(struct file_notify_node *node, struct mask_item *id)
{
    struct mask_info mi = {.nameonly = 1,};
    uint32_t len;
    int rc = 0;

    /* just return if entry not found in queue */
    if (!_mask_lookup(node, id, &mi)) {
        rc = -ENOENT;
        goto errorout;
    }

    if (mi.tag && memcmp(mi.tag, STTAG, SOTAG)) {
        BUG();
    }

    /* remove mask from queue */
    *((uint32_t *)mi.item) &= ~(id->mask);
    if (*((uint32_t *)mi.item))
        goto errorout;

    /* must remove the entry of the file path */
    len = ALIGN(sizeof(len) + id->nlen + 1, 4);
    TAG_SIZE(mi.tag) -= len;
    if (TAG_SIZE(mi.tag) == SOMASK) {
        /* no policy for this uuid / volume */
        len = len + SOMASK;
        if (node->used > len) {
            memmove(mi.tag, mi.tag + len, node->used -
                    len - (mi.tag - node->data));
            node->used -= len;
            memset(node->data + node->used, 0, len);
        } else {
            node->used = 0;
            memset(node->data, 0, node->size);
        }
    } else {
        /* only remove entry of this file path */
        memmove(mi.item, mi.item + len, node->used -
                len - (mi.item - node->data));
        node->used -= len;
        memset(node->data + node->used, 0, len);
    }

errorout:
    return rc;
}

char *mask_lookup(struct file_notify_node *node, u8 *uuid, const char *name, int nlen, uint32_t mask)
{
    struct mask_item item;

    item.uuid = uuid;
    item.name = name;
    item.nlen = nlen;
    item.mask = mask;
    item.ino = 0;
    return _mask_lookup(node, &item, NULL);
}

int mask_insert(struct file_notify_node *node, u8 *uuid, const char *name, int nlen, uint32_t mask)
{
    struct mask_item item;

    item.uuid = uuid;
    item.name = name;
    item.nlen = nlen;
    item.mask = mask;
    item.ino = 0;
    return _mask_insert(node, &item);
}

int mask_remove(struct file_notify_node *node, u8 *uuid, const char *name, int nlen, uint32_t mask)
{
    struct mask_item item;

    item.uuid = uuid;
    item.name = name;
    item.nlen = nlen;
    item.mask = mask;
    item.ino = 0;
    return _mask_remove(node, &item);
}

#if 0
/*
 * function test for mask & path support routines
 */
void mask_function_test(void)
{
    struct file_notify_node node = {0};
    u8 uuid[16] = {1, };

    if (mask_insert(&node, &uuid[0], "/etc/passwd", 11, 6))
        goto errorout;

    mask_lookup(&node, &uuid[0], "/etc/passwd", 11, 2);
    mask_remove(&node, &uuid[0], "/etc/passwd", 11, 4);
    uuid[0] = 3;
    mask_insert(&node, &uuid[0], "/etc/passwd", 11, 2);
    uuid[0] = 2;
    mask_insert(&node, &uuid[0], "/etc/passwd", 11, 4);
    mask_insert(&node, &uuid[0], "/etc/rlocal", 11, 2);
    mask_remove(&node, &uuid[0], "/etc/passwd", 11, 4);
    mask_remove(&node, &uuid[0], "/etc/rlocal", 11, 2);
    uuid[0] = 1;
    mask_remove(&node, &uuid[0], "/etc/passwd", 11, 2);
    uuid[0] = 2;
    mask_insert(&node, &uuid[0], "/etc/passwd", 11, 4);
    mask_insert(&node, &uuid[0], "/etc/rc.local", 13, 2);
    mask_remove(&node, &uuid[0], "/etc/rc.local", 13, 2);
    mask_remove(&node, &uuid[0], "/etc/passwd", 11, 4);

errorout:
    if (node.data)
        smith_kfree(node.data);
}

#endif

int file_notify_exist_rb(struct rb_root *root, unsigned long d)
{
    struct rb_node *node = root->rb_node;
    while (node) {
        struct file_notify_node *data = container_of(node,struct file_notify_node, node);
        if (d < data->ino) {
            node = node->rb_left;
        } else if (d > data->ino) {
            node = node->rb_right;
        } else {
            return 1;
        }
    }
    return 0;
}

struct file_notify_node *file_notify_search_rb(struct rb_root *root, unsigned long d)
{
    struct rb_node *node = root->rb_node;
    while (node) {
        struct file_notify_node *data = container_of(node, struct file_notify_node, node);
        if (d < data->ino) {
            node = node->rb_left;
        } else if (d > data->ino) {
            node = node->rb_right;
        } else {
            return data;
        }
    }
    return NULL;
}

int file_notify_insert_rb(struct rb_root *root, struct file_notify_node *data)
{
    struct rb_node **new = &(root->rb_node), *parent = NULL;

    while (*new) {
        struct file_notify_node *this = container_of(*new, struct file_notify_node, node);

        parent = *new;
        if (this->ino > data->ino) {
            new = &((*new)->rb_left);
        } else if (this->ino < data->ino) {
            new = &((*new)->rb_right);
        } else {
            return 0;
        }
    }

    rb_link_node(&data->node, parent, new);
    rb_insert_color(&data->node, root);
    return 1;
}

int del_rb_by_data_file_notify_checklist(unsigned long inode, u8 *uuid, const char *name, int nlen, int mask)
{
    struct file_notify_node *node = NULL;

    write_lock(&file_notify_checklist_lock);
    /* file_notify_search_rb should be under lock protection */
    node = file_notify_search_rb(&file_notify_checklist, inode);
    if (node) {
        if (mask_remove(node, uuid, name, nlen, mask) || node->used) {
            node = NULL;
        } else {
            rb_erase(&node->node, &file_notify_checklist);
        }
    }
    write_unlock(&file_notify_checklist_lock);

    if (node) {
        if (node->data)
            smith_kfree(node->data);
        smith_kfree(node);
    }

    return 1;
}

void add_file_notify_checklist(u8 *uuid, unsigned long inode, const char *name, int nlen, int mask)
{
    struct file_notify_node *node;

    write_lock(&file_notify_checklist_lock);
    node = file_notify_search_rb(&file_notify_checklist, inode);
    if(!node) {
        node = smith_kzalloc(sizeof(struct file_notify_node), GFP_KERNEL);
        if (!node)
            goto errorout;
        node->data = smith_kzalloc(file_notify_checklist_limit, GFP_KERNEL);
        if (!node->data) {
            smith_kfree(node);
            goto errorout;
        }
        node->size = file_notify_checklist_limit;
        node->ino = inode;
        file_notify_insert_rb(&file_notify_checklist, node);
    }
    mask_insert(node, uuid, name, nlen, mask);
errorout:
    write_unlock(&file_notify_checklist_lock);
}

int file_notify_check(u8 *uuid, unsigned long inode, const char *name, int nlen, int mask)
{
    struct file_notify_node *node;
    int rc = 0;

    /* should be protected by read_lock */
    read_lock(&file_notify_checklist_lock);
    node = file_notify_search_rb(&file_notify_checklist, inode);
    if(node)
        rc = !!mask_lookup(node, uuid, name, nlen, mask);
    read_unlock(&file_notify_checklist_lock);
    return rc;
}

static int del_file_notify_checklist(u8 *uuid, unsigned long data, const char *name, int nlen, int mask)
{
    return del_rb_by_data_file_notify_checklist(data, uuid, name, nlen, mask);
}

static void rbtree_clear_file_notify(struct rb_node *this_node)
{
    struct file_notify_node *node;

    if(!this_node)
        return;

    rbtree_clear_file_notify(this_node->rb_left);
    rbtree_clear_file_notify(this_node->rb_right);

    node = rb_entry(this_node, struct file_notify_node, node);
    if (node->data)
        smith_kfree(node->data);
    smith_kfree(node);
}

static void del_all_file_notify_checklist(void)
{
    if(!file_notify_checklist.rb_node)
        return;

    write_lock(&file_notify_checklist_lock);
    rbtree_clear_file_notify(file_notify_checklist.rb_node);
    file_notify_checklist = RB_ROOT;
    write_unlock(&file_notify_checklist_lock);
}

int exist_rb(struct rb_root *root, char *string)
{
    struct rb_node *node = root->rb_node;
    while (node) {
        struct allowlist_node *data = container_of(node,struct allowlist_node, node);

        int res;
        res = strcmp(string, data->data);

        if (res < 0) {
            node = node->rb_left;
        } else if (res > 0) {
            node = node->rb_right;
        } else {
            return 1;
        }
    }
    return 0;
}

struct allowlist_node *search_rb(struct rb_root *root, char *string)
{
    struct rb_node *node = root->rb_node;
    while (node) {
        struct allowlist_node *data = container_of(node, struct allowlist_node, node);

        int res = strcmp(string, data->data);
        if (res < 0) {
            node = node->rb_left;
        } else if (res > 0) {
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
int insert_rb(struct rb_root *root, struct allowlist_node *data)
{
    struct rb_node **new = &(root->rb_node), *parent = NULL;

    while (*new) {
        struct allowlist_node *this = container_of(*new, struct allowlist_node, node);

        int res = strcmp(data->data, this->data);
        parent = *new;
        if (res < 0) {
            new = &((*new)->rb_left);
        } else if (res > 0) {
            new = &((*new)->rb_right);
        } else {
            return 1;
        }
    }

    rb_link_node(&data->node, parent, new);
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

    write_lock(&exe_allowlist_lock);
    rc = insert_rb(&execve_exe_allowlist, node);
    if (!rc) {
        execve_exe_allowlist_limit++;
        write_unlock(&exe_allowlist_lock);
    } else {
        write_unlock(&exe_allowlist_lock);
        printk(KERN_INFO "[ELKEID] add_execve_exe_allowlist: already added.\n");
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

static void print_all_execve_allowlist(void)
{
    struct rb_node *node;

    read_lock(&exe_allowlist_lock);
    for (node = rb_first(&execve_exe_allowlist); node; node = rb_next(node)) {
        struct allowlist_node *data =
        container_of(node, struct allowlist_node, node);
        printk("[ELKEID DEBUG] execve_allowlist:%s \n", data->data);
    }
    read_unlock(&exe_allowlist_lock);
}

int execve_exe_check(char *data)
{
    int res;
    if (IS_ERR_OR_NULL(data) || strcmp(data, "-1") == 0
        || strcmp(data, "-2") == 0) {
        return 0;
    }

    read_lock(&exe_allowlist_lock);
    res = exist_rb(&execve_exe_allowlist, data);
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

    write_lock(&argv_allowlist_lock);
    rc = insert_rb(&execve_argv_allowlist, node);
    if (!rc) {
        execve_argv_allowlist_limit++;
        write_unlock(&argv_allowlist_lock);
    } else {
        write_unlock(&argv_allowlist_lock);
        printk(KERN_INFO"[ELKEID] add_execve_argv_allowlist: already added.\n");
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

static void del_all_execve_argv_allowlist(void)
{
    write_lock(&argv_allowlist_lock);
    rbtree_clear(execve_argv_allowlist.rb_node);
    execve_argv_allowlist = RB_ROOT;
    execve_argv_allowlist_limit = 0;
    write_unlock(&argv_allowlist_lock);
}

static void print_all_argv_allowlist(void)
{
    struct rb_node *node;
    read_lock(&argv_allowlist_lock);
    for (node = rb_first(&execve_argv_allowlist); node;
         node = rb_next(node)) {
        struct allowlist_node *data =
        container_of(node, struct allowlist_node, node);
        printk("[ELKEID DEBUG] argv_allowlist:%s \n", data->data);
    }
    read_unlock(&argv_allowlist_lock);
}

int execve_argv_check(char *data)
{
    int res;
    if (IS_ERR_OR_NULL(data) || strcmp(data, "-1") == 0
        || strcmp(data, "-2") == 0) {
        return 0;
    }

    read_lock(&exe_allowlist_lock);
    res = exist_rb(&execve_argv_allowlist, strim(data));
    read_unlock(&exe_allowlist_lock);

    return res;
}

static ssize_t device_write(struct file *filp, const __user char *buff,
                            size_t len, loff_t * off)
{
    int res;
    int err;
    char flag;
    char *data_main;

    struct path path;
    struct dentry *parent = NULL;

    if(smith_get_user(flag, buff))
        return len;

    /* check whether length is valid */
    if (len < ALLOWLIST_NODE_MIN || len > ALLOWLIST_NODE_MAX)
        return len;

    /* exceeds records limits ? */
    if (flag == ADD_EXECVE_EXE_ALLOWLIST &&
        execve_exe_allowlist_limit > ALLOWLIST_LIMIT) {
        return len;
    }
    if (flag == ADD_EXECVE_ARGV_ALLOWLIST &&
        execve_argv_allowlist_limit > ALLOWLIST_LIMIT) {
        return len;
    }

    /* try to grab user input */
    data_main = smith_kzalloc(len, GFP_KERNEL);
    if (!data_main)
        return len;

    if (smith_copy_from_user(data_main, buff + 1, len - 1)) {
        smith_kfree(data_main);
        return len;
    }

    switch (flag) {
        case ADD_EXECVE_EXE_ALLOWLIST:
            if (!add_execve_exe_allowlist(smith_strim(data_main)))
                data_main = NULL;
            break;

        case DEL_EXECVE_EXE_ALLOWLIST:
            del_execve_exe_allowlist(strim(data_main));
            break;

        case DEL_ALL_EXECVE_EXE_ALLOWLIST:
            del_all_execve_exe_allowlist();
            break;

        case EXECVE_EXE_CHECK:
            res = execve_exe_check(strim(data_main));
            printk("[ELKEID DEBUG] execve_exe_check:%s %d\n", strim(data_main), res);
            break;

        case PRINT_ALL_ALLOWLIST:
            print_all_execve_allowlist();
            print_all_argv_allowlist();
            break;

        case ADD_EXECVE_ARGV_ALLOWLIST:
            if (!add_execve_argv_allowlist(smith_strim(data_main)))
                data_main = NULL;
            break;

        case DEL_EXECVE_ARGV_ALLOWLIST:
            del_execve_argv_allowlist(strim(data_main));
            break;

        case DEL_ALL_EXECVE_ARGV_ALLOWLIST:
            del_all_execve_argv_allowlist();
            break;

        case EXECVE_ARGV_CHECK:
            res = execve_argv_check(strim(data_main));
            printk("[ELKEID DEBUG] execve_argv_check:%s %d\n", strim(data_main), res);
            break;

        case ADD_WRITE_NOTIFI:
            err = kern_path(strim(data_main), LOOKUP_FOLLOW, &path);
            if(!err) {
                if(S_ISDIR(path.dentry->d_inode->i_mode)) {
                    add_file_notify_checklist(smith_query_sb_uuid(path.dentry->d_sb), path.dentry->d_inode->i_ino, "*", 1, 2);
                } else {
                    parent = dget_parent(path.dentry);
                    if(parent)
                        add_file_notify_checklist(smith_query_sb_uuid(path.dentry->d_sb), parent->d_inode->i_ino,
                                              path.dentry->d_name.name, path.dentry->d_name.len, 2);
                }
            }
            break;

        case DEL_WRITE_NOTIFI:
            err = kern_path(strim(data_main), LOOKUP_FOLLOW, &path);
            if(!err) {
                if(S_ISDIR(path.dentry->d_inode->i_mode)) {
                    del_file_notify_checklist(smith_query_sb_uuid(path.dentry->d_sb), path.dentry->d_inode->i_ino, "*", 1, 2);
                } else {
                    parent = dget_parent(path.dentry);
                    if (parent)
                        del_file_notify_checklist(smith_query_sb_uuid(path.dentry->d_sb), parent->d_inode->i_ino,
                                                  path.dentry->d_name.name, path.dentry->d_name.len, 2);
                }
            }
            break;

        case ADD_READ_NOTIFI:
            err = kern_path(strim(data_main), LOOKUP_FOLLOW, &path);
            if(!err) {
                if(S_ISDIR(path.dentry->d_inode->i_mode)) {
                    add_file_notify_checklist(smith_query_sb_uuid(path.dentry->d_sb), path.dentry->d_inode->i_ino, "*", 1, 4);
                } else {
                    parent = dget_parent(path.dentry);
                    if (parent)
                        add_file_notify_checklist(smith_query_sb_uuid(path.dentry->d_sb), parent->d_inode->i_ino,
                                                  path.dentry->d_name.name, path.dentry->d_name.len, 4);
                }
            }
            break;

        case DEL_READ_NOTIFI:
            err = kern_path(strim(data_main), LOOKUP_FOLLOW, &path);
            if(!err) {
                if(S_ISDIR(path.dentry->d_inode->i_mode)) {
                    del_file_notify_checklist(smith_query_sb_uuid(path.dentry->d_sb), path.dentry->d_inode->i_ino, "*", 1, 4);
                } else {
                    parent = dget_parent(path.dentry);
                    if (parent)
                        del_file_notify_checklist(smith_query_sb_uuid(path.dentry->d_sb), parent->d_inode->i_ino,
                                                  path.dentry->d_name.name, path.dentry->d_name.len, 4);
                }
            }
            break;

        case DEL_ALL_NOTIFI:
            del_all_file_notify_checklist();
            break;
    }

    if(parent)
        dput(parent);

    if(data_main)
        smith_kfree(data_main);

    return len;
}

static int device_mmap(struct file *filp, struct vm_area_struct *vma)
{
    struct page *page;
    unsigned long size = (unsigned long)(vma->vm_end - vma->vm_start);

    if ((vma_pages(vma) + vma->vm_pgoff) > (SHMEM_MAX_SIZE >> PAGE_SHIFT)) {
        return -EINVAL;
    }

    page = virt_to_page((unsigned long)sh_mem + (vma->vm_pgoff << PAGE_SHIFT));

    return remap_pfn_range(vma, vma->vm_start, page_to_pfn(page), size,
                           vma->vm_page_prot);
}

int filter_init(void)
{
    int ret;
    struct device *dev;

    filter_major = register_chrdev(0, FILTER_DEVICE_NAME, &mchar_fops);

    if (filter_major < 0) {
        pr_err("[ELKEID FILTER] REGISTER_CHRDEV_ERROR\n");
        return filter_major;
    }

    filter_class = class_create(THIS_MODULE, FILTER_CLASS_NAME);
    if (IS_ERR(filter_class)) {
        pr_err("[ELKEID FILTER] CLASS_CREATE_ERROR");
        ret = PTR_ERR(filter_class);
        goto chrdev_unregister;
    }

    dev = device_create(filter_class, NULL, MKDEV(filter_major, 0),
                        NULL, FILTER_DEVICE_NAME);

    if (IS_ERR(dev)) {
        pr_err("[ELKEID FILTER] DEVICE_CREATE_ERROR");
        ret = PTR_ERR(dev);
        goto class_destroy;
    }

    sh_mem = smith_kzalloc(SHMEM_MAX_SIZE, GFP_KERNEL);

    if (sh_mem == NULL) {
        pr_err("[ELKEID FILTER] SHMEM_INIT_ERROR\n");
        ret = -ENOMEM;
        goto device_destroy;
    }
    return 0;

device_destroy:
    device_destroy(filter_class, MKDEV(filter_major, 0));
class_destroy:
    class_destroy(filter_class);
chrdev_unregister:
    unregister_chrdev(filter_major, FILTER_DEVICE_NAME);

    return ret;
}

void filter_cleanup(void)
{
    device_destroy(filter_class, MKDEV(filter_major, 0));
    class_destroy(filter_class);
    unregister_chrdev(filter_major, FILTER_DEVICE_NAME);
    del_all_execve_exe_allowlist();
    del_all_execve_argv_allowlist();
    del_all_file_notify_checklist();
    smith_kfree(sh_mem);
}

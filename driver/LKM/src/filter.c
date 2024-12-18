// SPDX-License-Identifier: GPL-2.0
/*
 * filter.c
 *
 * Data allowlist for hook
 */

#include <linux/mm.h>
#include <linux/fs.h>
#include <linux/device.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/uaccess.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/rbtree.h>
#include <linux/namei.h>
#include <linux/utsname.h>

#include "../include/util.h"
#include "../include/filter.h"


#define ADD_EXECVE_EXE_ALLOWLIST 89         /* Y */
#define DEL_EXECVE_EXE_ALLOWLIST 70         /* F */
#define DEL_ALL_EXECVE_EXE_ALLOWLIST 119    /* w */
#define EXECVE_EXE_CHECK 121                /* y */
#define PRINT_ALL_ALLOWLIST 46              /* . */
#define ADD_EXECVE_ARGV_ALLOWLIST 109       /* m */
#define DEL_EXECVE_ARGV_ALLOWLIST 74        /* J */
#define DEL_ALL_EXECVE_ARGV_ALLOWLIST 117   /* u */
#define EXECVE_ARGV_CHECK 122               /* z */
#define OPEN_INSTANCES_LIST_ALL 79          /* O */
#define OPEN_INSTANCES_LIST_TRACE 116       /* t */
#define OPEN_INSTANCES_LIST_FILTER 102      /* f */

#define ALLOWLIST_NODE_MIN 5
#define ALLOWLIST_NODE_MAX 4090
#define ALLOWLIST_LIMIT 128

static struct class *filter_class;
static int filter_major;

static struct rb_root execve_exe_allowlist = RB_ROOT;
static struct rb_root execve_argv_allowlist = RB_ROOT;

static int execve_exe_allowlist_limit = 0;

static int execve_argv_allowlist_limit = 0;

static DEFINE_RWLOCK(exe_allowlist_lock);
static DEFINE_RWLOCK(argv_allowlist_lock);

struct allowlist_node {
    struct rb_node node;
    char *data;
    uint64_t hash;
    int len;
};

static int exist_rb(struct rb_root *root, char *string)
{
    struct rb_node *node = root->rb_node;
    uint64_t hash;

    hash = hash_murmur_OAAT64(string, strlen(string));

    while (node) {
        struct allowlist_node *data = container_of(node, struct allowlist_node, node);
        if (hash < data->hash) {
            node = node->rb_left;
        } else if (hash > data->hash) {
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
    uint64_t hash;

    hash = hash_murmur_OAAT64(string, strlen(string));

    while (node) {
        struct allowlist_node *data = container_of(node, struct allowlist_node, node);
        if (hash < data->hash) {
            node = node->rb_left;
        } else if (hash > data->hash) {
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
        if (data->hash < node->hash) {
            nod = &((*nod)->rb_left);
        } else if (data->hash > node->hash) {
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
    unsigned long flags;
    int rc = 0;

    if (!data)
        return -EINVAL;

    node = smith_kzalloc(sizeof(struct allowlist_node), GFP_KERNEL);
    if (!node)
        return -ENOMEM;
    node->data = data;
    node->len = strlen(data);
    node->hash = hash_murmur_OAAT64(data, node->len);

    write_lock_irqsave(&exe_allowlist_lock, flags);
    rc = insert_rb(&execve_exe_allowlist, node);
    if (!rc) {
        execve_exe_allowlist_limit++;
        write_unlock_irqrestore(&exe_allowlist_lock, flags);
    } else {
        write_unlock_irqrestore(&exe_allowlist_lock, flags);
        smith_kfree(node);
    }

    return rc;
}

static void del_execve_exe_allowlist(char *data)
{
    struct allowlist_node *node;
    unsigned long flags;

    write_lock_irqsave(&exe_allowlist_lock, flags);
    node = search_rb(&execve_exe_allowlist, data);
    if (node) {
        rb_erase(&node->node, &execve_exe_allowlist);
        execve_exe_allowlist_limit--;
    }
    write_unlock_irqrestore(&exe_allowlist_lock, flags);

    if (node) {
        smith_kfree(node->data);
        smith_kfree(node);
    }
}

static int del_all_execve_exe_allowlist(void)
{
    unsigned long flags;

    write_lock_irqsave(&exe_allowlist_lock, flags);
    rbtree_clear(execve_exe_allowlist.rb_node);
    execve_exe_allowlist = RB_ROOT;
    execve_exe_allowlist_limit = 0;
    write_unlock_irqrestore(&exe_allowlist_lock, flags);

    return 0;
}

static void print_all_execve_allowlist(void)
{
    struct rb_node *node;
    unsigned long flags;

    read_lock_irqsave(&exe_allowlist_lock, flags);
    for (node = rb_first(&execve_exe_allowlist); node; node = rb_next(node)) {
        struct allowlist_node *data =
        container_of(node, struct allowlist_node, node);
        printk("[ELKEID DEBUG] execve_allowlist:%s \n", data->data);
    }
    read_unlock_irqrestore(&exe_allowlist_lock, flags);
}

int execve_exe_check(char *data, int len)
{
    unsigned long flags;
    int res;

    if (IS_ERR_OR_NULL(data) || len == 0)
        return 0;
    if (len == 2 && data[0] == '-' && (data[1] == '1' || data[1] == '2'))
        return 0;

    read_lock_irqsave(&exe_allowlist_lock, flags);
    res = exist_rb(&execve_exe_allowlist, data);
    read_unlock_irqrestore(&exe_allowlist_lock, flags);

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
    unsigned long flags;
    int rc = 0;

    if (!data)
        return -EINVAL;

    node = smith_kzalloc(sizeof(struct allowlist_node), GFP_KERNEL);
    if (!node)
        return -ENOMEM;
    node->data = data;
    node->len = strlen(data);
    node->hash = hash_murmur_OAAT64(data, node->len);

    write_lock_irqsave(&argv_allowlist_lock, flags);
    rc = insert_rb(&execve_argv_allowlist, node);
    if (!rc) {
        execve_argv_allowlist_limit++;
        write_unlock_irqrestore(&argv_allowlist_lock, flags);
    } else {
        write_unlock_irqrestore(&argv_allowlist_lock, flags);
        smith_kfree(node);
    }

    return rc;
}

static void del_execve_argv_allowlist(char *data)
{
    struct allowlist_node *node;
    unsigned long flags;

    write_lock_irqsave(&argv_allowlist_lock, flags);
    node = search_rb(&execve_argv_allowlist, data);
    if (node) {
        rb_erase(&node->node, &execve_argv_allowlist);
        execve_argv_allowlist_limit--;
    }
    write_unlock_irqrestore(&argv_allowlist_lock, flags);

    if (node) {
        smith_kfree(node->data);
        smith_kfree(node);
    }
}

static void del_all_execve_argv_allowlist(void)
{
    unsigned long flags;

    write_lock_irqsave(&argv_allowlist_lock, flags);
    rbtree_clear(execve_argv_allowlist.rb_node);
    execve_argv_allowlist = RB_ROOT;
    execve_argv_allowlist_limit = 0;
    write_unlock_irqrestore(&argv_allowlist_lock, flags);
}

static void print_all_argv_allowlist(void)
{
    struct rb_node *node;
    unsigned long flags;

    read_lock_irqsave(&argv_allowlist_lock, flags);
    for (node = rb_first(&execve_argv_allowlist); node;
         node = rb_next(node)) {
        struct allowlist_node *data =
        container_of(node, struct allowlist_node, node);
        printk("[ELKEID DEBUG] argv_allowlist:%s \n", data->data);
    }
    read_unlock_irqrestore(&argv_allowlist_lock, flags);
}

int execve_argv_check(char *data, int len)
{
    unsigned long flags;
    int res;

    if (IS_ERR_OR_NULL(data) || len == 0)
        return 0;
    if (len == 2 && data[0] == '-' && (data[1] == '1' || data[1] == '2'))
        return 0;

    read_lock_irqsave(&exe_allowlist_lock, flags);
    res = exist_rb(&execve_argv_allowlist, data);
    read_unlock_irqrestore(&exe_allowlist_lock, flags);

    return res;
}

size_t filter_process_allowlist(const __user char *buff, size_t len)
{
    char *data_main;
    int res;
    char flag = 0;

    if (smith_get_user(flag, buff))
        return len;

    /* diagnosis cases: enmerate opened instances */
    if (flag == OPEN_INSTANCES_LIST_ALL) {
        trace_show_instances();
        filter_show_instances();
        return len;
    } else if (flag == OPEN_INSTANCES_LIST_FILTER) {
        filter_show_instances();
        return len;
    } else if (flag == OPEN_INSTANCES_LIST_TRACE) {
        trace_show_instances();
        return len;
    }

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
        {
            char *exe_name = strim(data_main);
            res = execve_exe_check(exe_name, strlen(exe_name));
            printk("[ELKEID DEBUG] execve_exe_check:%s %d\n", exe_name, res);
            break;
        }

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
        {
            char *exe_argv = strim(data_main);
            res = execve_argv_check(exe_argv, strlen(exe_argv));
            printk("[ELKEID DEBUG] execve_argv_check:%s %d\n", exe_argv, res);
            break;
        }
    }

    if(data_main)
        smith_kfree(data_main);
    return len;
}

static ssize_t device_write(struct file *filp, const __user char *buff,
                            size_t len, loff_t * off)
{
    return filter_process_allowlist(buff, len);
}

struct filter_instance {
    struct list_head next;
    char comm[TASK_COMM_LEN];
    char node[__NEW_UTS_LEN];
    pid_t owner;
};

static LIST_HEAD(filter_list);
static struct mutex filter_lock;
static int filter_n_instances;

void filter_show_instances(void)
{
    struct filter_instance *iter;
    int niters = 0;

    mutex_lock(&filter_lock);
    printk("filter device opened %d times:\n", filter_n_instances);
    list_for_each_entry(iter, &filter_list, next) {
        niters++;
        printk("%6d: %u %16s %s\n", niters, iter->owner, iter->comm, iter->node);
    }
    if (niters != filter_n_instances)
        printk("inconsistent values: %d %d\n", niters, filter_n_instances);
    mutex_unlock(&filter_lock);
}

/* handling device open */
static int device_open(struct inode *inode, struct file *filp)
{
    struct filter_instance *iter;

    iter = kzalloc(sizeof(*iter), GFP_KERNEL);
    if (!iter)
        return -ENOMEM;

    /* tracing current task for this opened instance */
    iter->owner = current->pid;
    memcpy(iter->comm, current->comm, TASK_COMM_LEN);
    memcpy(iter->node, current->nsproxy->uts_ns->name.nodename, __NEW_UTS_LEN),

    mutex_lock(&filter_lock);
    filter_n_instances++;
    list_add_tail(&iter->next, &filter_list);
    mutex_unlock(&filter_lock);

    filp->private_data = iter;
    nonseekable_open(inode, filp);
    __module_get(THIS_MODULE);

    return 0;
}

/* handling deivce close */
static int device_release(struct inode *inode, struct file *filp)
{
    struct filter_instance *iter = filp->private_data;

    if (!iter)
        return 0;

    /* removing iter from trace_list */
    mutex_lock(&filter_lock);
    list_del(&iter->next);
    filter_n_instances--;
    mutex_unlock(&filter_lock);

    kfree(iter);
    module_put(THIS_MODULE);

    return 0;
}

static const struct file_operations mchar_fops = {
    .owner = THIS_MODULE,
    .write = device_write,
    .open = device_open,
    .release = device_release
};

int filter_init(void)
{
    int ret;
    struct device *dev;

    mutex_init(&filter_lock);
    filter_major = register_chrdev(0, FILTER_DEVICE_NAME, &mchar_fops);
    if (filter_major < 0) {
        pr_err("[ELKEID FILTER] REGISTER_CHRDEV_ERROR\n");
        return filter_major;
    }

#if defined(CLASS_CREATE_HAVE_OWNER)
    filter_class = class_create(THIS_MODULE, FILTER_CLASS_NAME);
#else
    filter_class = class_create(FILTER_CLASS_NAME);
#endif
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

    return 0;

class_destroy:
    class_destroy(filter_class);
chrdev_unregister:
    unregister_chrdev(filter_major, FILTER_DEVICE_NAME);
    mutex_destroy(&filter_lock);

    return ret;
}

void filter_cleanup(void)
{
    device_destroy(filter_class, MKDEV(filter_major, 0));
    class_destroy(filter_class);
    unregister_chrdev(filter_major, FILTER_DEVICE_NAME);

    if (filter_n_instances)
        filter_show_instances();
    mutex_destroy(&filter_lock);

    del_all_execve_exe_allowlist();
    del_all_execve_argv_allowlist();
}

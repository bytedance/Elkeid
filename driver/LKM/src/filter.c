// SPDX-License-Identifier: GPL-2.0
/*
 * filter.c
 *
 * Data allowlist for hook
 */

#include "../include/filter.h"
#include "../include/util.h"

#define ADD_EXECVE_EXE_SHITELIST 89         /* Y */
#define DEL_EXECVE_EXE_SHITELIST 70         /* F */
#define DEL_ALL_EXECVE_EXE_SHITELIST 119    /* w */
#define EXECVE_EXE_CHECK 121                /* y */
#define PRINT_ALL_ALLOWLIST 46              /* . */
#define ADD_EXECVE_ARGV_SHITELIST 109       /* m */
#define DEL_EXECVE_ARGV_SHITELIST 74        /* J */
#define DEL_ALL_EXECVE_ARGV_SHITELIST 117   /* u */
#define EXECVE_ARGV_CHECK 122               /* z */
#define PRINT_PPIN 95                       /* _ */

#define ALLOWLIST_NODE_MIN 5
#define ALLOWLIST_NODE_MAX 4090

static struct class *filter_class;
static int filter_major;
static char *sh_mem = NULL;

struct rb_root execve_exe_allowlist = RB_ROOT;

struct rb_root execve_argv_allowlist = RB_ROOT;

static int execve_exe_allowlist_limit = 0;

static int execve_argv_allowlist_limit = 0;

static atomic_t device_read_flag = ATOMIC_INIT(0);

static DEFINE_RWLOCK(exe_allowlist_lock);
static DEFINE_RWLOCK(argv_allowlist_lock);


static int device_mmap(struct file *filp, struct vm_area_struct *vma);

static ssize_t device_write(struct file *filp, const __user char *buff,
                            size_t len, loff_t * off);

static ssize_t device_read(struct file *filp, char __user * buf, size_t count,
        loff_t * offset);

static const struct file_operations mchar_fops = {
        .owner = THIS_MODULE,
        .mmap = device_mmap,
        .write = device_write,
        .read = device_read,
};

struct allowlist_node {
    struct rb_node node;
    char *data;
};

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
            return 0;
        }
    }

    rb_link_node(&data->node, parent, new);
    rb_insert_color(&data->node, root);
    return 1;
}

int del_rb_by_data_exe_list(char *str)
{
    struct allowlist_node *data = NULL;
    data = search_rb(&execve_exe_allowlist, str);
    if(!data)
        return 0;

    write_lock(&exe_allowlist_lock);
    /* make sure node is still in rb tree */
    data = search_rb(&execve_exe_allowlist, str);
    if (data) {
        rb_erase(&data->node, &execve_exe_allowlist);
        execve_exe_allowlist_limit--;
    }
    write_unlock(&exe_allowlist_lock);

    kfree(data->data);
    kfree(data);
    return 1;
}

int del_rb_by_data_argv_list(char *str)
{
    struct allowlist_node *data = NULL;
    data = search_rb(&execve_argv_allowlist, str);
    if(!data)
        return 0;

    write_lock(&argv_allowlist_lock);
    /* make sure node is still in rb tree */
    data = search_rb(&execve_argv_allowlist, str);
    if (data) {
        rb_erase(&data->node, &execve_argv_allowlist);
        execve_argv_allowlist_limit--;
    }
    write_unlock(&argv_allowlist_lock);

    kfree(data->data);
    kfree(data);
    return 1;
}

static void rbtree_clear(struct rb_node *this_node)
{
    struct allowlist_node *node;

    if(!this_node)
        return;

    rbtree_clear(this_node->rb_left);
    rbtree_clear(this_node->rb_right);

    node = rb_entry(this_node, struct allowlist_node, node);
    kfree(node->data);
    kfree(node);
}

static int add_execve_exe_allowlist(char *data)
{
    struct allowlist_node *node;
    int rc = 0;

    if (!data)
        return -EINVAL;

    node = kzalloc(sizeof(struct allowlist_node), GFP_ATOMIC);
    if (!node)
        return -ENOMEM;
    node->data = data;

    write_lock(&exe_allowlist_lock);
    rc = insert_rb(&execve_exe_allowlist, node);
    if (rc)
        execve_exe_allowlist_limit++;
    else
        printk(KERN_INFO "[ELKEID] add_execve_exe_allowlist error\n");
    write_unlock(&exe_allowlist_lock);

    return rc;
}

static int del_execve_exe_allowlist(char *data)
{
    return del_rb_by_data_exe_list(data);
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

static int add_execve_argv_allowlist(char *data)
{
    struct allowlist_node *node;
    int rc = 0;

    if (!data)
        return -EINVAL;

    node = kzalloc(sizeof(struct allowlist_node), GFP_ATOMIC);
    if (!node)
        return -ENOMEM;
    node->data = data;

    write_lock(&argv_allowlist_lock);
    rc = insert_rb(&execve_argv_allowlist, node);
    if (rc)
        execve_argv_allowlist_limit++;
    else
        printk(KERN_INFO "[ELKEID] add_execve_argv_allowlist error\n");
    write_unlock(&argv_allowlist_lock);

    return rc;
}

static int del_execve_argv_allowlist(char *data)
{
    return del_rb_by_data_argv_list(data);
}

static void del_all_execve_argv_allowlist(void)
{
    if(!execve_argv_allowlist.rb_node)
        return;

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
    char *data_main;
    int res;
    char flag;

    if (len < ALLOWLIST_NODE_MIN || len > ALLOWLIST_NODE_MAX)
        return len;

    if(smith_get_user(flag, buff))
        return len;

    data_main = kzalloc(len, GFP_KERNEL);
    if (!data_main)
        return len;

    if (smith_copy_from_user(data_main, buff + 1, len - 1)) {
        kfree(data_main);
        return len;
    }

    switch (flag) {
        case ADD_EXECVE_EXE_SHITELIST:
            if (execve_exe_allowlist_limit <= 96){
                /* assgin data_main to rb node */
                add_execve_exe_allowlist(smith_strim(data_main));
                data_main = NULL;
            }
            break;

        case DEL_EXECVE_EXE_SHITELIST:
            del_execve_exe_allowlist(strim(data_main));
            break;

        case DEL_ALL_EXECVE_EXE_SHITELIST:
            del_all_execve_exe_allowlist();
            break;

        case EXECVE_EXE_CHECK:
            res = execve_exe_check(data_main);
            printk("[ELKEID DEBUG] execve_exe_check:%s %d\n",
                   strim(data_main), res);
            break;

        case PRINT_ALL_ALLOWLIST:
            print_all_execve_allowlist();
            print_all_argv_allowlist();
            break;

        case ADD_EXECVE_ARGV_SHITELIST:
            if (execve_argv_allowlist_limit <= 96){
                /* assgin data_main to rb node */
                add_execve_argv_allowlist(smith_strim(data_main));
                data_main = NULL;
            }
            break;

        case DEL_EXECVE_ARGV_SHITELIST:
            del_execve_argv_allowlist(strim(data_main));
            break;

        case DEL_ALL_EXECVE_ARGV_SHITELIST:
            del_all_execve_argv_allowlist();
            break;

        case EXECVE_ARGV_CHECK:
            res = execve_argv_check(data_main);
            printk("[ELKEID DEBUG] execve_argv_check:%s %d\n",
                   strim(data_main), res);
            break;

        case PRINT_PPIN:
            atomic_set(&device_read_flag, 1);
            break;
    }

    if (data_main)
        kfree(data_main);
    return len;
}

static ssize_t device_read(struct file *filp, char __user * buf, size_t size,
        loff_t * offset)
{
    int len;
    u64 ppin;
    char ppin_str[64];

    if(atomic_cmpxchg(&device_read_flag, 1, 0) != 1)
        return 0;

    ppin = GET_PPIN();
    snprintf(ppin_str, 64, "%llu", ppin);
    len = strlen(ppin_str);
    if (len > size || copy_to_user(buf, ppin_str, len))
        return 0;

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

    sh_mem = kzalloc(SHMEM_MAX_SIZE, GFP_ATOMIC);

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
    kfree(sh_mem);
}

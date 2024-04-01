/* SPDX-License-Identifier: GPL-2.0 */

#ifndef FILTER_H
#define FILTER_H

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

struct image_hash;
struct exe_item;

struct filter_ops {
    int (*exe_check)(char *data, int len, uint64_t hash);
    int (*argv_check)(char *data, int len);
    int (*hash_check)(struct image_hash *md5);
    int (*rule_check)(struct exe_item *items, int nitems, char *id);
    int (*ipv4_check)(uint32_t ip);
    int (*ipv6_check)(uint32_t *ip);
    int (*ioctl)(int cmd, const __user char *buf);
    int (*store)(const char *buf, int len);
};
extern struct filter_ops g_flt_ops;

extern int smith_register_exec_load(void);
extern int smith_unregister_exec_load(void);

#endif /* FILTER_H */

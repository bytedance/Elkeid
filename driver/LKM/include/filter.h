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

#define FILTER_DEVICE_NAME "hids_driver_allowlist"
#define FILTER_CLASS_NAME "hids_driver_allowlist"

#define SHMEM_MAX_SIZE 8192

int filter_init(void);

void filter_cleanup(void);

int execve_exe_check(char *data, int len);

int file_notify_check(u8 *uuid, unsigned long inode, const char *name, int nlen, int mask);

int execve_argv_check(char *data, int len);

#endif /* FILTER_H */

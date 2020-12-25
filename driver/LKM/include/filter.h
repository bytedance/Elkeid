/* SPDX-License-Identifier: GPL-3.0 */

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

#define FILTER_DEVICE_NAME "hids_driver_allowlist"
#define FILTER_CLASS_NAME "hids_driver_allowlist"

#define SHMEM_MAX_SIZE 8192

int filter_init(void);

void filter_cleanup(void);

int execve_exe_check(char *data);

int execve_argv_check(char *data);

#endif /* FILTER_H */

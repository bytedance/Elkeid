/* SPDX-License-Identifier: GPL-2.0 */

#ifndef FILTER_H
#define FILTER_H

#define FILTER_DEVICE_NAME "hids_driver_allowlist"
#define FILTER_CLASS_NAME "hids_driver_allowlist"

#define SHMEM_MAX_SIZE 8192

int filter_init(void);

void filter_cleanup(void);

int execve_exe_check(char *data, int len);

int file_notify_check(u8 *uuid, unsigned long inode, const char *name, int nlen, int mask);

int execve_argv_check(char *data, int len);

size_t filter_process_allowlist(const __user char *buff, size_t len);

#endif /* FILTER_H */

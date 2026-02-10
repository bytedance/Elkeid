// SPDX-License-Identifier: GPL-2.0

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <fcntl.h>
#include <errno.h>
#include <ctype.h>

#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>

#include "../LKM/include/trace.h"


static struct tb_ring_operations *g_ring_ops;

extern struct tb_ring_operations  g_ring_v1_7;
extern struct tb_ring_operations  g_ring_v1_8;
extern struct tb_ring_operations  g_ring_v1_9;
extern struct tb_ring_operations  g_ring_ebpf;

/*
 * HIDS control routines for kmod/LKM
 */

/* control: "/sys/module/smith/parameters/control_trace" */
int tb_init_kmod(int dev, char *control)
{
    return tb_init(dev, control);
}

int tb_fini_kmod(int type)
{
    int rc;

    if (!g_ring_ops)
        return -1;
    if (RING_TYPE(type) != RING_KMOD)
        return -2;
    if (RING_TYPE(g_ring_ops->type) != RING_KMOD)
        return -3;
    rc = g_ring_ops->ring_fini(RING_KMOD);
    if (0 == rc)
        g_ring_ops = NULL;
    return rc;
}

int tb_read_kmod(char *msg, int len, int (*cb)(int *), int *ctx)
{
    if (!g_ring_ops)
        return -1;
    if (RING_TYPE(g_ring_ops->type) != RING_KMOD)
        return -2;
    return g_ring_ops->ring_read(msg, len, cb, ctx);
}

/* manually register or cleanup binfmt callbacks */
int tb_register_binfmt(void)
{
    if (!g_ring_ops)
        return -1;
    if (RING_TYPE(g_ring_ops->type) != RING_KMOD)
        return -2;
    return g_ring_ops->register_binfmt();
}

int tb_unregister_binfmt(void)
{
    if (!g_ring_ops)
        return -1;
    if (RING_TYPE(g_ring_ops->type) != RING_KMOD)
        return -2;
    return g_ring_ops->unregister_binfmt();
}

/* tell LKM driver that it's to be unloaded */
int tb_pre_unload(void)
{
    return tb_unregister_binfmt();
}

int tb_is_passed(struct timeval *tv, long cycle)
{
    if (!g_ring_ops || !g_ring_ops->ring_is_passed)
        return -1;
    return g_ring_ops->ring_is_passed(tv, cycle);
}

int tb_stat_kmod(struct ring_stat *stat)
{
    if (!g_ring_ops)
        return -1;
    if (RING_TYPE(g_ring_ops->type) != RING_KMOD)
        return -2;
    return g_ring_ops->ring_stat(stat);
}

void tb_show_kmod(struct ring_stat *s, struct ring_stat *l, struct ring_stat *n)
{
    if (!g_ring_ops)
        return;
    if (RING_TYPE(g_ring_ops->type) != RING_KMOD)
        return;
    g_ring_ops->ring_show(s, l, n);
}

/*
 * HIDS control routines for general
 */

int tb_init(int dev, char *control)
{
    int rc = -EINVAL;

    if (!g_ring_ops) {
        if (dev == RING_KMOD_V1_9)
            g_ring_ops = &g_ring_v1_9;
        else if (dev == RING_KMOD_V1_8)
            g_ring_ops = &g_ring_v1_8;
        else if (dev == RING_KMOD_V1_7)
            g_ring_ops = &g_ring_v1_7;
        else if (dev == RING_EBPF)
            g_ring_ops = &g_ring_ebpf;
    }

    if (g_ring_ops)
        rc = g_ring_ops->ring_init(RING_TYPE(dev), control);

   return rc;
}

void tb_fini(int dev)
{
    int rc;

    if (!g_ring_ops)
        return;
    if (RING_TYPE(g_ring_ops->type) != RING_TYPE(dev))
        return;
    rc = g_ring_ops->ring_fini(RING_TYPE(dev));
    if (0 == rc)
        g_ring_ops = NULL;
}

int tb_read(char *msg, int len, int (*cb)(int *), int *ctx)
{
    if (!g_ring_ops)
        return -1;

    return g_ring_ops->ring_read(msg, len, cb, ctx);
}

/*
 * Access control related routines for all
 */

int ac_init(int type, char *trace)
{
    int rc = -EINVAL;

    if (!g_ring_ops) {
        if (type == RING_KMOD_V1_9)
            g_ring_ops = &g_ring_v1_9;
        else if (type == RING_KMOD_V1_8)
            g_ring_ops = &g_ring_v1_8;
        else if (type == RING_KMOD_V1_7)
            g_ring_ops = &g_ring_v1_7;
        else if (type == RING_EBPF)
            g_ring_ops = &g_ring_ebpf;
    }

    if (g_ring_ops)
        rc = g_ring_ops->ac_init(RING_TYPE(type), trace);

   return rc;
}

void ac_fini(int type)
{
    int rc;

    if (!g_ring_ops)
        return;
    if (RING_TYPE(g_ring_ops->type) != RING_TYPE(type))
        return;
    rc = g_ring_ops->ac_fini(RING_TYPE(type));
    if (0 == rc)
        g_ring_ops = NULL;
}

int ac_setup(int ac, char *item, int len)
{
    if (!g_ring_ops)
        return -1;
    return g_ring_ops->ac_setup(ac, item, len);
}

int ac_clear(int ac)
{
    if (!g_ring_ops)
        return -1;
    return g_ring_ops->ac_clear(ac);
}

int ac_check(int ac, char *item, int len)
{
    if (!g_ring_ops)
        return -1;
    return g_ring_ops->ac_check(ac, item, len);
}

int ac_erase(int ac, char *item, int len)
{
    if (!g_ring_ops)
        return -1;
    return g_ring_ops->ac_erase(ac, item, len);
}

int ac_query(int ac, char *buf, int len)
{
    if (!g_ring_ops)
        return -1;
    return g_ring_ops->ac_query(ac, buf, len);
}

int ac_process(int type, char *control, char *ptr, int len, int quiet)
{
    if (!g_ring_ops || !g_ring_ops->ac_process || RING_TYPE(type) != RING_KMOD)
        return -1;
    return g_ring_ops->ac_process(control, ptr, len, quiet);
}

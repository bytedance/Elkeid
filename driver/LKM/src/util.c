// SPDX-License-Identifier: GPL-2.0
/*
 * util.c
 *
 */
#include "../include/util.h"
#include <linux/version.h>
#include <linux/kallsyms.h>
#include <linux/prefetch.h>


#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 7, 0) || LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 33)

#include <linux/kprobes.h>

static unsigned long (*kallsyms_lookup_name_sym)(const char *name);

static int _kallsyms_lookup_kprobe(struct kprobe *p, struct pt_regs *regs)
{
        return 0;
}

unsigned long get_kallsyms_func(void)
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
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 13, 0)
    /* uuid_t s_uuid; */
    return (u8 *)&sb->s_uuid;
#elif LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 39)
    /* s_uuid not defined, using fixed zone of this sb */
    return (u8 *)&sb->s_dev;
#else
    /* u8 s_uuid[16]; */
    return (u8 *)&sb->s_uuid[0];
#endif
}

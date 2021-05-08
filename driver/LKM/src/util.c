// SPDX-License-Identifier: GPL-2.0
/*
 * util.c
 *
 */
#include "../include/util.h"
#include <linux/version.h>
#include <linux/kallsyms.h>
#include <linux/kprobes.h>
/* kernel version after 5.8 should use api in linux/mmap_lock.h
   ref: https://lkml.org/lkml/2020/6/4/28
*/
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0)
#include <linux/mmap_lock.h>
#endif


#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 7, 0)

static unsigned long (*kallsyms_lookup_name_sym)(const char *name);
static int dummy_kprobe_handler(struct kprobe *p, struct pt_regs *regs)
{
        return 0;
}

unsigned long get_kallsyms_func(void)
{
        struct kprobe probe;
        int ret;
        unsigned long addr;

        memset(&probe, 0, sizeof(probe));
        probe.pre_handler = dummy_kprobe_handler;
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

#ifdef CONFIG_X86
#if LINUX_VERSION_CODE > KERNEL_VERSION(4, 7, 0)
u64 GET_PPIN(void)
{
	int err;
	u64 res;
	res = paravirt_read_msr_safe(0x4f, &err);
	return res;
}
#else
u64 GET_PPIN(void)
{
	return 0;
}
#endif
#else

u64 GET_PPIN(void)
{
    return 0;
}

#endif

int prepend(char **buffer, int *buflen, const char *str, int namelen)
{
    *buflen -= namelen;
    if (*buflen < 0)
        return -ENAMETOOLONG;
    *buffer -= namelen;
    memcpy(*buffer, str, namelen);
    return 0;
}

int prepend_name(char **buffer, int *buflen, struct qstr *name)
{
    return prepend(buffer, buflen, name->name, name->len);
}


//get file path from dentry struct
char *__dentry_path(struct dentry *dentry, char *buf, int buflen)
{
    char *end = buf + buflen;
    char *retval;

    prepend(&end, &buflen, "\0", 1);
    if (buflen < 1)
        goto Elong;
    retval = end - 1;
    *retval = '/';

    while (!IS_ROOT(dentry)) {
        struct dentry *parent = dentry->d_parent;
        int error;

        prefetch(parent);
        spin_lock(&dentry->d_lock);
        error = prepend_name(&end, &buflen, &dentry->d_name);
        spin_unlock(&dentry->d_lock);
        if (error != 0 || prepend(&end, &buflen, "/", 1) != 0)
            goto Elong;

        retval = end;
        dentry = parent;
    }
    return retval;
Elong:
    return ERR_PTR(-ENAMETOOLONG);
}

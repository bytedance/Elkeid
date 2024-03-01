// SPDX-License-Identifier: GPL-2.0
/*
 * kprobe.h
 *
 * Here's a sample kernel module showing the use of return probes.
 */
#ifndef __KPROBE_TEMPLATE_H
#define __KPROBE_TEMPLATE_H

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kprobes.h>

struct kprobe_initcall
{
    int (*init)(void);
    void (*exit)(void);
};

#define KPROBE_CALL(mod) smith_##mod##_init_body
#define KPROBE_INITCALL(mod, init_func, exit_func)    \
    const struct kprobe_initcall KPROBE_CALL(mod) = { \
        .init = init_func,                            \
        .exit = exit_func,                            \
    };

extern const struct kprobe_initcall KPROBE_CALL(trace);
extern const struct kprobe_initcall KPROBE_CALL(filter);
extern const struct kprobe_initcall KPROBE_CALL(anti_rootkit);
extern const struct kprobe_initcall KPROBE_CALL(kprobe_hook);

#define SMITH_VERSION "1.9.1.5"

#endif /* __KPROBE_TEMPLATE_H */

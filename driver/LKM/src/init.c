// SPDX-License-Identifier: GPL-3.0
/*
 * init.c
 *
 * Here's the register of kprobes, kretprobes and tracepoints.
 */
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include "../include/kprobe.h"

/* Defined in linker script */
extern struct kprobe *const __start_kprobe_template[];
extern struct kprobe *const __stop_kprobe_template[];

extern struct kretprobe *const __start_kretprobe_template[];
extern struct kretprobe *const __stop_kretprobe_template[];

extern struct tracepoint_entry *const __start_tracepoint_template[];
extern struct tracepoint_entry *const __stop_tracepoint_template[];

extern struct kprobe_initcall const *const __start_kprobe_initcall[];
extern struct kprobe_initcall const *const __stop_kprobe_initcall[];

static int __init do_kprobe_initcalls(void)
{
    int ret = 0;
    struct kprobe_initcall const *const *initcall_p;

    for (initcall_p = __start_kprobe_initcall;
         initcall_p < __stop_kprobe_initcall; initcall_p++) {
        struct kprobe_initcall const *initcall = *initcall_p;

        if (initcall->init) {
            ret = initcall->init();
            if (ret < 0)
                goto exit;
        }
    }

    return 0;
exit:
    while (--initcall_p >= __start_kprobe_initcall) {
        struct kprobe_initcall const *initcall = *initcall_p;

        if (initcall->exit)
            initcall->exit();
    }

    return ret;
}

static void do_kprobe_exitcalls(void)
{
    struct kprobe_initcall const *const *initcall_p =
            __stop_kprobe_initcall;

    while (--initcall_p >= __start_kprobe_initcall) {
        struct kprobe_initcall const *initcall = *initcall_p;

        if (initcall->exit)
            initcall->exit();
    }
}

static int __init kprobes_init(void)
{
    int ret;
    ret = do_kprobe_initcalls();
    if (ret < 0)
        return ret;

    return ret;
}

static void __exit kprobes_exit(void)
{
    do_kprobe_exitcalls();
}

module_init(kprobes_init);
module_exit(kprobes_exit);

MODULE_INFO(homepage, "https://github.com/smcdef/kprobe-template");
MODULE_VERSION("1.5.0.0");

//MODULE_LICENSE("GPLv3");
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Will Chen <chenyue.will@bytedance.com>;Muchun Song <songmuchun@bytedance.com>;Jia Ma <jia.ma@bytedance.com>; Gaba <panxiting@bytedance.com>");
MODULE_DESCRIPTION("Kprobe template for AgentSmith-HIDS");
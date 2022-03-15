// SPDX-License-Identifier: GPL-2.0
/*
 * init.c
 *
 * Here's the register of kprobes, kretprobes and tracepoints.
 */

#include "../include/kprobe.h"

/* Definions for global init/fini routines */
static const struct kprobe_initcall *__mod_entry[] =
{
    &KPROBE_CALL(trace),
    &KPROBE_CALL(anti_rootkit),
    &KPROBE_CALL(kprobe_hook),
};

static int __init kprobes_init(void)
{
    int i, rc = 0;

    for (i = 0; i < ARRAY_SIZE(__mod_entry); i++) {
        const struct kprobe_initcall *kic = __mod_entry[i];
        if (kic && kic->init) {
            rc = kic->init();
            if (rc < 0)
                goto exit;
        }
    }

    return 0;

exit:
    while (i-- > 0) {
        const struct kprobe_initcall *kic = __mod_entry[i];
        if (kic && kic->exit)
            kic->exit();
    }

    return rc;
}

static void __exit kprobes_exit(void)
{
    int i;

    for (i = ARRAY_SIZE(__mod_entry) - 1; i >= 0; i--) {
        const struct kprobe_initcall *kic = __mod_entry[i];
        if (kic && kic->exit)
            kic->exit();
    }

    return;
}

module_init(kprobes_init);
module_exit(kprobes_exit);

MODULE_INFO(homepage, "driver");
MODULE_VERSION("1.7.0.5");

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Will Chen <chenyue.will@bytedance.com>;Ping Shen <shenping.matt@bytedance.com>");
MODULE_DESCRIPTION("Elkied Driver is the core component of Elkeid HIDS project");

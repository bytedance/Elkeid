// SPDX-License-Identifier: GPL-2.0
/*
 * init.c
 *
 * Here's the register of kprobes, kretprobes and tracepoints.
 */

#include "../include/kprobe.h"

/* Definions for global init/fini routines */
extern const struct kprobe_initcall KPROBE_CALL(trace);
extern const struct kprobe_initcall KPROBE_CALL(anti_rootkit);
extern const struct kprobe_initcall KPROBE_CALL(kprobe_hook);

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

MODULE_VERSION("1.7.0.24");
MODULE_LICENSE("GPL");

MODULE_INFO(homepage, "https://github.com/bytedance/Elkeid/tree/main/driver");
MODULE_AUTHOR("Elkeid Team <elkeid@bytedance.com>");
MODULE_DESCRIPTION("Elkied Driver is the core component of Elkeid HIDS project");

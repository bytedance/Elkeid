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

struct kprobe_initcall {
	int (*init)(void);
	void (*exit)(void);
};

#define KPROBE_CALL(mod) smith_##mod##_init_body
#define KPROBE_INITCALL(mod, init_func, exit_func)	\
	const struct kprobe_initcall KPROBE_CALL(mod) = {		\
		.init	= init_func,	\
		.exit	= exit_func,	\
	};							\

#endif /* __KPROBE_TEMPLATE_H */
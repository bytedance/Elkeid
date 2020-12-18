// SPDX-License-Identifier: GPL-3.0
/*
 * kprobe.c
 *
 * Here's a sample kernel module showing the use of probes.
 */
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include "../include/kprobe.h"


#ifndef _HIDS_EBPF_VMLINUX_H_
#define _HIDS_EBPF_VMLINUX_H_

#ifndef KERNEL_VERSION
#define KERNEL_VERSION(a, b, c) (((a) << 16) + ((b) << 8) + ((c) > 255 ? 255 : (c)))
#endif

#define LINUX_VERSION_CODE  KERNEL_VERSION(KV_MAINVERSION, KV_PATCHLEVEL, KV_SUBLEVEL)

#ifdef __NATIVE_EBPF__

/* native version */
#define INCLUDE_FILE(x) #x
#define INLINE_INCLUDE(x) INCLUDE_FILE(x)
#define TARGET_INCLUDE(...) vmlinux-__VA_ARGS__.h
#define TARGET_VMLINUX(...) INLINE_INCLUDE(TARGET_INCLUDE(__VA_ARGS__))
#define INCLUDE_VMLINUX(...) TARGET_VMLINUX(__VA_ARGS__)
#include INCLUDE_VMLINUX(KV_VERSION)

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define clang_builtin_memset	__builtin_memset
#define clang_builtin_memcpy	__builtin_memcpy

#else

/* bpfd version */

#include <bpf/trace/vmlinux.h>
#include <bpf/trace/bpf_helpers.h>
#include <bpf/trace/bpf_tracing.h>
#include <bpf/trace/bpf_core_read.h>

#define clang_builtin_memset	memset
#define clang_builtin_memcpy	memcpy

#endif /* __NATIVE_EBPF__ */

extern unsigned int LINUX_KERNEL_VERSION __kconfig;

#endif /* _HIDS_EBPF_VMLINUX_H_ */

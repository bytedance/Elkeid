/* SPDX-License-Identifier: GPL-2.0 */

#ifndef __STRUCT_WRAP_H_
#define __STRUCT_WRAP_H_
#ifdef CONFIG_X86
static inline void smith_regs_set_return_value(struct pt_regs *regs, unsigned long rc)
{
	regs->ax = rc;
}

static inline unsigned long p_regs_get_arg1(struct pt_regs *p_regs) {
   return p_regs->di;
}

static inline unsigned long p_regs_get_arg2(struct pt_regs *p_regs) {
   return p_regs->si;
}

static inline unsigned long p_regs_get_arg3(struct pt_regs *p_regs) {
   return p_regs->dx;
}

static inline unsigned long p_regs_get_arg4(struct pt_regs *p_regs) {
   return p_regs->cx;
}

static inline unsigned long p_regs_get_arg5(struct pt_regs *p_regs) {
   return p_regs->r8;
}

static inline unsigned long p_regs_get_arg6(struct pt_regs *p_regs) {
   return p_regs->r9;
}
#elif defined(CONFIG_ARM64)
static inline void smith_regs_set_return_value(struct pt_regs *regs, unsigned long rc)
{
	regs->regs[0] = rc;
}

static inline unsigned long p_regs_get_arg1(struct pt_regs *p_regs) {
   return p_regs->regs[0];
}

static inline unsigned long p_regs_get_arg2(struct pt_regs *p_regs) {
   return p_regs->regs[1];
}

static inline unsigned long p_regs_get_arg3(struct pt_regs *p_regs) {
   return p_regs->regs[2];
}

static inline unsigned long p_regs_get_arg4(struct pt_regs *p_regs) {
   return p_regs->regs[3];
}

static inline unsigned long p_regs_get_arg5(struct pt_regs *p_regs) {
   return p_regs->regs[4];
}

static inline unsigned long p_regs_get_arg6(struct pt_regs *p_regs) {
   return p_regs->regs[5];
}
#endif

#ifdef CONFIG_X86
static inline unsigned long p_regs_get_arg1_syscall(struct pt_regs *p_regs) {
   return p_regs->di;
}

static inline unsigned long p_regs_get_arg2_syscall(struct pt_regs *p_regs) {
   return p_regs->si;
}

static inline unsigned long p_regs_get_arg3_syscall(struct pt_regs *p_regs) {
   return p_regs->dx;
}

static inline unsigned long p_regs_get_arg4_syscall(struct pt_regs *p_regs) {
   return p_regs->r10;
}

static inline unsigned long p_regs_get_arg5_syscall(struct pt_regs *p_regs) {
   return p_regs->r8;
}

static inline unsigned long p_regs_get_arg6_syscall(struct pt_regs *p_regs) {
   return p_regs->r9;
}
#elif defined(CONFIG_ARM64)
static inline unsigned long p_regs_get_arg1_syscall(struct pt_regs *p_regs) {
   return p_regs->regs[0];
}

static inline unsigned long p_regs_get_arg2_syscall(struct pt_regs *p_regs) {
   return p_regs->regs[1];
}

static inline unsigned long p_regs_get_arg3_syscall(struct pt_regs *p_regs) {
   return p_regs->regs[2];
}

static inline unsigned long p_regs_get_arg4_syscall(struct pt_regs *p_regs) {
   return p_regs->regs[3];
}

static inline unsigned long p_regs_get_arg5_syscall(struct pt_regs *p_regs) {
   return p_regs->regs[4];
}

static inline unsigned long p_regs_get_arg6_syscall(struct pt_regs *p_regs) {
   return p_regs->regs[5];
}
#endif

// Only Get Syscall Functions Parameter Can Use p_get_arg()
static inline unsigned long p_get_arg1_syscall(struct pt_regs *p_regs) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 17, 0) && defined(CONFIG_ARCH_HAS_SYSCALL_WRAPPER)
    return p_regs_get_arg1_syscall((struct pt_regs *)p_regs_get_arg1_syscall(p_regs));
#else
    return p_regs_get_arg1_syscall(p_regs);
#endif
}

static inline unsigned long p_get_arg2_syscall(struct pt_regs *p_regs) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 17, 0) && defined(CONFIG_ARCH_HAS_SYSCALL_WRAPPER)
    return p_regs_get_arg2_syscall((struct pt_regs *)p_regs_get_arg1_syscall(p_regs));
#else
    return p_regs_get_arg2_syscall(p_regs);
#endif
}

static inline unsigned long p_get_arg3_syscall(struct pt_regs *p_regs) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 17, 0) && defined(CONFIG_ARCH_HAS_SYSCALL_WRAPPER)
    return p_regs_get_arg3_syscall((struct pt_regs *)p_regs_get_arg1_syscall(p_regs));
#else
    return p_regs_get_arg3_syscall(p_regs);
#endif
}

static inline unsigned long p_get_arg4_syscall(struct pt_regs *p_regs) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 17, 0) && defined(CONFIG_ARCH_HAS_SYSCALL_WRAPPER)
    return p_regs_get_arg4_syscall((struct pt_regs *)p_regs_get_arg1_syscall(p_regs));
#else
    return p_regs_get_arg4_syscall(p_regs);
#endif
}

static inline unsigned long p_get_arg5_syscall(struct pt_regs *p_regs) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 17, 0) && defined(CONFIG_ARCH_HAS_SYSCALL_WRAPPER)
    return p_regs_get_arg5_syscall((struct pt_regs *)p_regs_get_arg1_syscall(p_regs));
#else
    return p_regs_get_arg5_syscall(p_regs);
#endif
}

static inline unsigned long p_get_arg6_syscall(struct pt_regs *p_regs) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 17, 0) && defined(CONFIG_ARCH_HAS_SYSCALL_WRAPPER)
    return p_regs_get_arg6_syscall((struct pt_regs *)p_regs_get_arg1_syscall(p_regs));
#else
    return p_regs_get_arg6_syscall(p_regs);
#endif
}
#endif
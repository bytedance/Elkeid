/* SPDX-License-Identifier: GPL-3.0 */

#ifndef __STRUCT_WRAP_H_
#define __STRUCT_WRAP_H_
#ifdef CONFIG_X86
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
   return p_regs->r10;
}

static inline unsigned long p_regs_get_arg5(struct pt_regs *p_regs) {
   return p_regs->r8;
}

static inline unsigned long p_regs_get_arg6(struct pt_regs *p_regs) {
   return p_regs->r9;
}
#elif defined(CONFIG_ARM64)
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

static inline unsigned long p_get_arg1(struct pt_regs *p_regs) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 17, 0) && defined(CONFIG_ARCH_HAS_SYSCALL_WRAPPER)
    return p_regs_get_arg1((struct pt_regs *)p_regs_get_arg1(p_regs));
#else
    return p_regs_get_arg1(p_regs);
#endif
}

static inline unsigned long p_get_arg2(struct pt_regs *p_regs) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 17, 0) && defined(CONFIG_ARCH_HAS_SYSCALL_WRAPPER)
    return p_regs_get_arg2((struct pt_regs *)p_regs_get_arg1(p_regs));
#else
    return p_regs_get_arg2(p_regs);
#endif
}

static inline unsigned long p_get_arg3(struct pt_regs *p_regs) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 17, 0) && defined(CONFIG_ARCH_HAS_SYSCALL_WRAPPER)
    return p_regs_get_arg3((struct pt_regs *)p_regs_get_arg1(p_regs));
#else
    return p_regs_get_arg3(p_regs);
#endif
}

static inline unsigned long p_get_arg4(struct pt_regs *p_regs) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 17, 0) && defined(CONFIG_ARCH_HAS_SYSCALL_WRAPPER)
    return p_regs_get_arg4((struct pt_regs *)p_regs_get_arg1(p_regs));
#else
    return p_regs_get_arg4(p_regs);
#endif
}

static inline unsigned long p_get_arg5(struct pt_regs *p_regs) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 17, 0) && defined(CONFIG_ARCH_HAS_SYSCALL_WRAPPER)
    return p_regs_get_arg5((struct pt_regs *)p_regs_get_arg1(p_regs));
#else
    return p_regs_get_arg5(p_regs);
#endif
}

static inline unsigned long p_get_arg6(struct pt_regs *p_regs) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 17, 0) && defined(CONFIG_ARCH_HAS_SYSCALL_WRAPPER)
    return p_regs_get_arg6((struct pt_regs *)p_regs_get_arg1(p_regs));
#else
    return p_regs_get_arg6(p_regs);
#endif
}

static inline int get_current_uid(void) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 5, 0)
    return current->real_cred->uid.val;
#else
    return current->real_cred->uid;
#endif
}

static inline int get_current_euid(void) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 5, 0)
    return current->real_cred->euid.val;
#else
    return current->real_cred->euid;
#endif
}

static void *getDNSQuery(unsigned char *data, int index, char *res) {
    int i;
    int flag = -1;
    int len;
    len = strlen(data + index);

    for (i = 0; i < len; i++) {
        if (flag == -1) {
            flag = (data + index)[i];
        } else if (flag == 0) {
            flag = (data + index)[i];
            res[i - 1] = 46;
        } else {
            res[i - 1] = (data + index)[i];
            flag = flag - 1;
        }
    }
    return 0;
}

static inline unsigned int __get_sessionid(void) {
    unsigned int sessionid = 0;
#ifdef CONFIG_AUDITSYSCALL
    sessionid = current->sessionid;
#endif
    return sessionid;
}

static inline int __get_pgid(void) {
    struct task_struct *task;
    task = pid_task(task_pgrp(current), PIDTYPE_PID);
    if(task != NULL)
        return task->pid;
    else
        return -1;
}

static inline int __get_sid(void) {
    struct task_struct *task;
    task = pid_task(task_session(current), PIDTYPE_PID);
    if(task != NULL)
        return task->pid;
    else
        return -1;
}
#endif
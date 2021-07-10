#ifndef __SYSCALL_H__
#define __SYSCALL_H__

#ifdef __cplusplus
extern "C" {
#endif

long int do_syscall(long int sys_no, ...);

#ifdef __cplusplus
}
#endif

__asm__ (
".section .text\n"
".type do_syscall, @function\n"
"do_syscall:\n"
"    mov %rdi, %rax\n"
"    mov %rsi, %rdi\n"
"    mov %rdx, %rsi\n"
"    mov %rcx, %rdx\n"
"    mov %r8, %r10\n"
"    mov %r9, %r8\n"
"    mov 8(%rsp), %r9\n"
"    syscall\n"
"    ret"
);

#endif
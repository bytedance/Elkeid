#include "futex.h"
#include <syscall.h>
#include <linux/futex.h>
#include <syscall/do_syscall.h>

int futex_wait(int *u_addr, int val, const timespec *timeout) {
    return (int)do_syscall(SYS_futex, u_addr, FUTEX_WAIT, val, timeout, nullptr, 0);
}

int futex_wake(int *u_addr, int val) {
    return (int)do_syscall(SYS_futex, u_addr, FUTEX_WAKE, val, nullptr, nullptr, 0);
}

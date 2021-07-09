#ifndef GO_PROBE_FUTEX_H
#define GO_PROBE_FUTEX_H

#include <ctime>

int futex_wait(int *u_addr, int val, const timespec *timeout = nullptr);
int futex_wake(int *u_addr, int val);

#endif //GO_PROBE_FUTEX_H

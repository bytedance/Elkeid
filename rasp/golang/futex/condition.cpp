#include "condition.h"
#include "futex.h"
#include <cerrno>
#include <climits>

void CCondition::wait(const timespec *timeout) {
    while (true) {
        if (__sync_bool_compare_and_swap(&mFutex, 1, 0))
            break;

        int err = futex_wait(&mFutex, 0, timeout);

        if (err < 0 && -err == ETIMEDOUT) {
            break;
        }
    }
}

void CCondition::wait(CMutex &mutex, const timespec *timeout) {
    while (true) {
        if (__sync_bool_compare_and_swap(&mFutex, 1, 0))
            break;

        mutex.unlock();

        int err = futex_wait(&mFutex, 0, timeout);

        if (err < 0 && -err == ETIMEDOUT) {
            mutex.lock();
            break;
        }

        mutex.lock();
    }
}

void CCondition::notify() {
    if (__sync_bool_compare_and_swap(&mFutex, 0, 1)) {
        if (futex_wake(&mFutex, 1) < 0) {

        }
    }
}

void CCondition::broadcast() {
    if (__sync_bool_compare_and_swap(&mFutex, 0, 1)) {
        if (futex_wake(&mFutex, INT_MAX) < 0) {

        }
    }
}

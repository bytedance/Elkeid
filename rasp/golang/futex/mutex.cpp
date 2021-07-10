#include "mutex.h"
#include "futex.h"
#include <cerrno>

void CMutex::lock() {
    while (true) {
        if (__sync_bool_compare_and_swap(&mFutex, 1, 0))
            break;

        int err = futex_wait(&mFutex, 0);

        if (err < 0 && -err != EAGAIN) {

        }
    }
}

void CMutex::unlock() {
    if (__sync_bool_compare_and_swap(&mFutex, 0, 1)) {
        if (futex_wake(&mFutex, 1) < 0) {
            // error
        }
    }
}

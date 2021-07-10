#ifndef GO_PROBE_CONDITION_H
#define GO_PROBE_CONDITION_H

#include "mutex.h"

class CCondition {
public:
    void wait(const timespec *timeout = nullptr);
    void wait(CMutex &mutex, const timespec *timeout = nullptr);

public:
    void notify();
    void broadcast();

private:
    int mFutex{0};
};


#endif //GO_PROBE_CONDITION_H

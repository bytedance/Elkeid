#ifndef GO_PROBE_MUTEX_H
#define GO_PROBE_MUTEX_H

#include <ctime>

class CMutex {
public:
    void lock();
    void unlock();

private:
    int mFutex{1};
};


#endif //GO_PROBE_MUTEX_H

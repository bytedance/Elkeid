#ifndef GO_PROBE_SMITH_PROBE_H
#define GO_PROBE_SMITH_PROBE_H

#include "smith_client.h"
#include <futex/condition.h>
#include <common/utils/circular_buffer.h>

constexpr auto TRACE_MAX_SIZE = 100;

class CSmithProbe: public ISmithNotify {
#define gSmithProbe SINGLETON_(CSmithProbe)
public:
    void start();
    void stop();

public:
    void trace(const CSmithTrace& smithTrace);

public:
    void traceThread();

public:
    void onMessage(const CSmithMessage &message) override;

private:
    bool mExit{false};

private:
    CCondition mCondition;

private:
    CSmithClient mClient{this};

private:
    CThread_<CSmithProbe> mThread;
    CCircularBuffer<CSmithTrace, TRACE_MAX_SIZE> mTraces;
};


#endif //GO_PROBE_SMITH_PROBE_H

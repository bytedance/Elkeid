#ifndef GO_PROBE_SMITH_PROBE_H
#define GO_PROBE_SMITH_PROBE_H

#include "smith_client.h"
#include <z_sync.h>
#include <common/utils/circular_buffer.h>

constexpr auto TRACE_BUFFER_SIZE = 100;

class CSmithProbe: public ISmithNotify {
#define gSmithProbe SINGLETON(CSmithProbe)
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
    bool filter(const CSmithTrace& smithTrace);

private:
    bool mExit{false};

private:
    std::mutex mMutex;
    std::map<std::tuple<int, int>, CFilter> mFilters;

private:
    z_cond_t mCond{};
    CSmithClient mClient{this};

private:
    CThread<CSmithProbe> mThread;
    CCircularBuffer<CSmithTrace, TRACE_BUFFER_SIZE> mTraces;
};


#endif //GO_PROBE_SMITH_PROBE_H

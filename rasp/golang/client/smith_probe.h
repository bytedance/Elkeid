#ifndef GO_PROBE_SMITH_PROBE_H
#define GO_PROBE_SMITH_PROBE_H

#include "smith_client.h"
#include <z_sync.h>
#include <zero/atomic/circular_buffer.h>

constexpr auto TRACE_BUFFER_SIZE = 100;

class CSmithProbe: public ISmithNotify {
#define gSmithProbe zero::Singleton<CSmithProbe>::getInstance()
public:
    void start();
    void stop();

public:
    void trace(const CSmithTrace& smithTrace);

public:
    void traceThread();

public:
    void resetQuotas();

public:
    void onMessage(const CSmithMessage &message) override;

private:
    bool filter(const CSmithTrace& smithTrace);

private:
    bool mExit{false};

private:
    std::mutex mLimitMutex;
    std::mutex mFilterMutex;
    std::map<std::tuple<int, int>, int> mLimits;
    std::map<std::tuple<int, int>, CFilter> mFilters;

private:
    z_cond_t mCond{};
    CSmithClient mClient{this};

private:
    zero::Thread<CSmithProbe> mTimer{this};
    zero::Thread<CSmithProbe> mThread{this};
    zero::atomic::CircularBuffer<CSmithTrace, TRACE_BUFFER_SIZE> mTraces;
};


#endif //GO_PROBE_SMITH_PROBE_H

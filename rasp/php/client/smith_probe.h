#ifndef PHP_PROBE_SMITH_PROBE_H
#define PHP_PROBE_SMITH_PROBE_H

#include "smith_client.h"
#include <zero/singleton.h>

class SmithProbe: public ISmithNotify {
#define gSmithProbe zero::Singleton<SmithProbe>::getInstance()
public:
    SmithProbe();
    ~SmithProbe() override;

public:
    void start();
    void stop();

public:
    void consume();

public:
    void onTimer();
    void onMessage(const SmithMessage &message) override;

private:
    bool filter(const SmithTrace& smithTrace);

private:
    bool mExit{false};

private:
    std::mutex mLimitMutex;
    std::mutex mFilterMutex;
    std::map<std::tuple<int, int>, int> mLimits;
    std::map<std::tuple<int, int>, Filter> mFilters;

private:
    event *mTimer;
    event_base *mEventBase;
    SmithClient mClient{mEventBase, this};
    zero::Thread<SmithProbe> mConsumer{this};
};


#endif //PHP_PROBE_SMITH_PROBE_H

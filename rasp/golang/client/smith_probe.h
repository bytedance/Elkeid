#ifndef GO_PROBE_SMITH_PROBE_H
#define GO_PROBE_SMITH_PROBE_H

#include "smith_client.h"
#include <zero/thread.h>
#include <zero/singleton.h>
#include <zero/atomic/event.h>
#include <zero/atomic/circular_buffer.h>

constexpr auto TRACE_BUFFER_SIZE = 100;

class SmithProbe: public IMessageHandler {
#define gSmithProbe zero::Singleton<SmithProbe>::getInstance()
public:
    SmithProbe();
    ~SmithProbe() override;

public:
    void start();
    void stop();

public:
    void loop();

public:
    void enqueue(const Trace& trace);
    void consume();

public:
    void onTimer();
    void onMessage(const SmithMessage &message) override;

private:
    bool filter(const Trace& trace);

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
    Heartbeat mHeartbeat;
    zero::atomic::Event mEvent;
    SmithClient mClient{mEventBase, this};
    zero::Thread<SmithProbe> mConsumer{this};
    zero::Thread<SmithProbe> mEventLoop{this};
    zero::atomic::CircularBuffer<Trace, TRACE_BUFFER_SIZE> mBuffer;
};

#endif //GO_PROBE_SMITH_PROBE_H

#ifndef GO_PROBE_SMITH_CLIENT_H
#define GO_PROBE_SMITH_CLIENT_H

#include "smith_message.h"
#include <mutex>
#include <event.h>
#include <zero/interface.h>
#include <zero/thread.h>

class ISmithNotify: public zero::Interface {
public:
    virtual void onMessage(const CSmithMessage &message) = 0;
};

class CSmithClient {
public:
    explicit CSmithClient(ISmithNotify *notify);
    ~CSmithClient();

public:
    bool start();
    bool stop();

private:
    void setTimer();
    void cancelTimer();

public:
    void loopThread();

public:
    void onTimer();

private:
    bool connect();
    void disconnect();

public:
    void onBufferRead(bufferevent *bev);
    void onBufferWrite(bufferevent *bev);
    void onBufferEvent(bufferevent *bev, short what);

public:
    bool write(const CSmithMessage &message);
    bool writeBuffer(const std::string& message);

private:
    std::mutex mMutex;
    ISmithNotify *mNotify{};

private:
    event *mTimer{};
    bufferevent *mBev{};
    event_base *mEventBase;
    zero::Thread<CSmithClient> mThread{this};
};


#endif //GO_PROBE_SMITH_CLIENT_H

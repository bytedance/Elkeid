#ifndef GO_PROBE_SMITH_CLIENT_H
#define GO_PROBE_SMITH_CLIENT_H

#include "smith_message.h"
#include <event.h>
#include <common/interface.h>
#include <common/mutex.h>
#include <common/singleton.h>
#include <common/thread.h>

class ISmithNotify: public Interface {
public:
    virtual void onMessage(const CSmithMessage &message) = 0;
};

class CSmithClient {
#define gSmithClient SINGLETON_(CSmithClient)
public:
    CSmithClient();
    ~CSmithClient();

public:
    bool start();
    bool stop();

public:
    void setNotify(ISmithNotify *notify);

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
    Mutex mBevMutex;
    ISmithNotify *mNotify{};

private:
    event *mTimer{};
    bufferevent *mBev{};
    event_base *mEventBase;
    CThread_<CSmithClient> mThread;
};


#endif //GO_PROBE_SMITH_CLIENT_H

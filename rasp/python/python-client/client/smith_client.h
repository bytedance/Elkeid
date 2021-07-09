#ifndef PYTHON_CLIENT_SMITH_CLIENT_H
#define PYTHON_CLIENT_SMITH_CLIENT_H

#include <event.h>
#include <string>
#include <common/mutex.h>
#include <common/singleton.h>
#include <common/thread.h>
#include <list>

class CSmithClient {
#define gSmithClient SINGLETON_(CSmithClient)
public:
    CSmithClient();
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
    bool writeBuffer(const std::string& message);

public:
    bool fetch(std::string& message);

public:
    std::string mVersion;

private:
    pid_t mPID;

private:
    Mutex mBevMutex;
    Mutex mInboxMutex;

private:
    event *mTimer{};
    bufferevent *mBev{};
    event_base *mEventBase;
    CThread_<CSmithClient> mThread;

private:
    std::list<std::string> mInbox;
};


#endif //PYTHON_CLIENT_SMITH_CLIENT_H

#ifndef PHP_PROBE_SMITH_CLIENT_H
#define PHP_PROBE_SMITH_CLIENT_H

#include "smith_message.h"
#include <mutex>
#include <event.h>
#include <zero/interface.h>
#include <zero/thread.h>

class ISmithNotify: public zero::Interface {
public:
    virtual void onMessage(const SmithMessage &message) = 0;
};

class SmithClient {
public:
    explicit SmithClient(event_base *base, ISmithNotify *notify);
    ~SmithClient();

public:
    bool connect();
    void disconnect();

public:
    void onBufferRead(bufferevent *bev);
    void onBufferWrite(bufferevent *bev);
    void onBufferEvent(bufferevent *bev, short what);

public:
    bool write(const SmithMessage &message);
    bool writeBuffer(const std::string& message);

private:
    std::mutex mMutex;
    ISmithNotify *mNotify{};

private:
    event *mTimer{};
    bufferevent *mBev{};
    event_base *mEventBase{};
};


#endif //PHP_PROBE_SMITH_CLIENT_H

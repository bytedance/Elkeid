#ifndef GO_PROBE_SMITH_CLIENT_H
#define GO_PROBE_SMITH_CLIENT_H

#include "smith_message.h"
#include <mutex>
#include <event.h>
#include <zero/interface.h>

class IMessageHandler: public zero::Interface {
public:
    virtual void onMessage(const SmithMessage &message) = 0;
};

class SmithClient {
public:
    explicit SmithClient(event_base *base, IMessageHandler *handler);
    ~SmithClient();

public:
    bool connect();
    void disconnect();

public:
    void readMessage();

public:
    void onBufferRead(bufferevent *bev);
    void onBufferWrite(bufferevent *bev);
    void onBufferEvent(bufferevent *bev, short what);

public:
    bool write(const SmithMessage &message);
    bool writeBuffer(const std::string& message);

private:
    std::mutex mMutex;
    IMessageHandler *mHandler{};

private:
    event *mTimer{};
    bufferevent *mBev{};
    event_base *mEventBase{};
};

#endif //GO_PROBE_SMITH_CLIENT_H

#include "smith_client.h"
#include <event2/thread.h>
#include <sys/un.h>
#include <common/log.h>

constexpr auto CLIENT_TIMER = 60;

constexpr auto PROTOCOL_HEADER_SIZE = 4;
constexpr auto PROTOCOL_MAX_SIZE = 10240;
constexpr auto EVENT_BUFFER_MAX_SIZE = 1024 * 1024;

constexpr auto SOCKET_PATH = "/var/run/smith_agent.sock";

CSmithClient::CSmithClient(ISmithNotify *notify) {
    evthread_use_pthreads();

    mNotify = notify;
    mEventBase = event_base_new();
}

CSmithClient::~CSmithClient() {
    if (mEventBase) {
        event_base_free(mEventBase);
        mEventBase = nullptr;
    }
}

bool CSmithClient::start() {
    LOG_INFO("client start");

    if (!mEventBase) {
        LOG_ERROR("event base null");
        return false;
    }

    connect();
    setTimer();

    mThread.start(this, &CSmithClient::loopThread);

    return true;
}

bool CSmithClient::stop() {
    cancelTimer();
    disconnect();

    event_base_loopbreak(mEventBase);
    mThread.stop();

    return true;
}

void CSmithClient::onBufferRead(bufferevent *bev) {
    evbuffer *input = bufferevent_get_input(bev);

    int length = 0;
    evbuffer_copyout(input, &length, PROTOCOL_HEADER_SIZE);

    length = ntohl(length);

    if (length > PROTOCOL_MAX_SIZE) {
        LOG_ERROR("message max size limit: %d", length);
        disconnect();
        return;
    }

    if (evbuffer_get_length(input) < length + PROTOCOL_HEADER_SIZE)
        return;

    char *buffer = new char[length + 1]();

    evbuffer_drain(input, PROTOCOL_HEADER_SIZE);
    evbuffer_remove(input, buffer, length);

    if (mNotify)
        mNotify->onMessage(nlohmann::json::parse(buffer).get<CSmithMessage>());

    delete []buffer;
}

void CSmithClient::onBufferWrite(bufferevent *bev) {

}

void CSmithClient::onBufferEvent(bufferevent *bev, short what) {
    if (what & BEV_EVENT_EOF || what & BEV_EVENT_ERROR) {
        LOG_INFO("buffer event: %hd", what);
        disconnect();
    }
}

bool CSmithClient::writeBuffer(const std::string &message) {
    AutoMutex _0_(mBevMutex);

    if (!mBev)
        return false;

    evbuffer *output = bufferevent_get_output(mBev);

    if (evbuffer_get_length(output) > EVENT_BUFFER_MAX_SIZE) {
        LOG_WARNING("buffer max size limit");
        return false;
    }

    int length = htonl(message.length());

    bufferevent_write(mBev, &length, sizeof(length));
    bufferevent_write(mBev, message.data(), message.size());

    return true;
}

bool CSmithClient::connect() {
    AutoMutex _0_(mBevMutex);

    sockaddr_un un = {};

    un.sun_family = AF_UNIX;
    strcpy(un.sun_path, SOCKET_PATH);

    mBev = bufferevent_socket_new(mEventBase, -1, BEV_OPT_CLOSE_ON_FREE | BEV_OPT_THREADSAFE);

    if (!mBev) {
        LOG_ERROR("buffer event null");
        return false;
    }

    if (bufferevent_socket_connect(mBev, (sockaddr *)&un, sizeof(un)) < 0) {
        LOG_ERROR("connect error: %s", evutil_socket_error_to_string(EVUTIL_SOCKET_ERROR()));

        bufferevent_free(mBev);
        mBev = nullptr;

        return false;
    }

    struct stub {
        static void onRead(bufferevent *bev, void *ctx) {
            static_cast<CSmithClient *>(ctx)->onBufferRead(bev);
        }

        static void onWrite(bufferevent *bev, void *ctx) {
            static_cast<CSmithClient *>(ctx)->onBufferWrite(bev);
        }

        static void onEvent(bufferevent *bev, short what, void *ctx) {
            static_cast<CSmithClient *>(ctx)->onBufferEvent(bev, what);
        }
    };

    bufferevent_setcb(mBev, stub::onRead, stub::onWrite, stub::onEvent, this);
    bufferevent_enable(mBev, EV_READ | EV_WRITE);
    bufferevent_setwatermark(mBev, EV_READ, PROTOCOL_HEADER_SIZE, EVENT_BUFFER_MAX_SIZE);

    return true;
}

void CSmithClient::disconnect() {
    AutoMutex _0_(mBevMutex);

    LOG_INFO("disconnect");

    if (mBev) {
        bufferevent_free(mBev);
        mBev = nullptr;
    }
}

void CSmithClient::setTimer() {
    struct stub {
        static void onEvent(evutil_socket_t fd ,short Event, void* arg) {
            static_cast<CSmithClient *>(arg)->onTimer();
        }
    };

    mTimer = event_new(mEventBase, -1, EV_PERSIST, stub::onEvent, this);

    timeval timeOutVal = {CLIENT_TIMER, 0};
    evtimer_add(mTimer, &timeOutVal);
}

void CSmithClient::cancelTimer() {
    if (mTimer) {
        evtimer_del(mTimer);
        event_free(mTimer);

        mTimer = nullptr;
    }
}

void CSmithClient::onTimer() {
    if (mBev) {
        LOG_INFO("heartbeat");
        write({emHeartBeat, nlohmann::json::object()});
    } else {
        LOG_INFO("reconnect");
        connect();
    }
}

void CSmithClient::loopThread() {
    LOG_INFO("client loop thread start");
    event_base_dispatch(mEventBase);
}

bool CSmithClient::write(const CSmithMessage &message) {
    return writeBuffer(nlohmann::json(message).dump());
}

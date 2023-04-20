#include "smith_client.h"
#include <sys/un.h>
#include <zero/log.h>
#include <unistd.h>

constexpr auto RECONNECT_DELAY = timeval {60, 0};

constexpr auto PROTOCOL_HEADER_SIZE = 4;
constexpr auto PROTOCOL_MAX_SIZE = 10240;
constexpr auto EVENT_BUFFER_MAX_SIZE = 1024 * 1024;

constexpr auto SOCKET_PATH = "/var/run/smith_agent.sock";
constexpr auto MESSAGE_DIRECTORY = "/var/run/elkeid_rasp";

SmithClient::SmithClient(event_base *base, IMessageHandler *handler) {
    mHandler = handler;
    mEventBase = base;

    struct stub {
        static void onEvent(evutil_socket_t fd, short what, void *arg) {
            static_cast<SmithClient *>(arg)->readMessage();
            static_cast<SmithClient *>(arg)->connect();
        }
    };

    mTimer = evtimer_new(mEventBase, stub::onEvent, this);
}

SmithClient::~SmithClient() {
    if (mTimer) {
        event_free(mTimer);
        mTimer = nullptr;
    }
}

void SmithClient::onBufferRead(bufferevent *bev) {
    evbuffer *input = bufferevent_get_input(bev);

    while (true) {
        unsigned int length = 0;

        if (evbuffer_copyout(input, &length, PROTOCOL_HEADER_SIZE) != PROTOCOL_HEADER_SIZE)
            break;

        length = ntohl(length);

        if (length > PROTOCOL_MAX_SIZE) {
            LOG_ERROR("message max size limit: %u", length);
            disconnect();
            evtimer_add(mTimer, &RECONNECT_DELAY);
            break;
        }

        if (evbuffer_get_length(input) < length + PROTOCOL_HEADER_SIZE)
            break;

        std::unique_ptr<char[]> buffer = std::make_unique<char[]>(length + 1);

        if (evbuffer_drain(input, PROTOCOL_HEADER_SIZE) != 0 || evbuffer_remove(input, buffer.get(), length) != length) {
            LOG_ERROR("read buffer failed: %s", evutil_socket_error_to_string(EVUTIL_SOCKET_ERROR()));
            disconnect();
            evtimer_add(mTimer, &RECONNECT_DELAY);
            break;
        }

        try {
            mHandler->onMessage(nlohmann::json::parse(buffer.get()).get<SmithMessage>());
        } catch (const nlohmann::json::exception &e) {
            LOG_ERROR("exception: %s", e.what());
            disconnect();
            evtimer_add(mTimer, &RECONNECT_DELAY);
            break;
        }
    }
}

void SmithClient::onBufferWrite(bufferevent *bev) {

}

void SmithClient::onBufferEvent(bufferevent *bev, short what) {
    if (what & BEV_EVENT_EOF) {
        LOG_INFO("buffer event EOF");
        disconnect();
        evtimer_add(mTimer, &RECONNECT_DELAY);
    } else if (what & BEV_EVENT_ERROR) {
        LOG_ERROR("buffer event error: %s", evutil_socket_error_to_string(EVUTIL_SOCKET_ERROR()));
        disconnect();
        evtimer_add(mTimer, &RECONNECT_DELAY);
    }
}

bool SmithClient::writeBuffer(const std::string &message) {
    std::lock_guard<std::mutex> _0_(mMutex);

    if (!mBev)
        return false;

    evbuffer *output = bufferevent_get_output(mBev);

    if (evbuffer_get_length(output) > EVENT_BUFFER_MAX_SIZE) {
        LOG_WARNING("buffer max size limit");
        return false;
    }

    unsigned int length = htonl(message.length());

    evbuffer_add(output, &length, sizeof(length));
    evbuffer_add(output, message.data(), message.size());

    return true;
}

bool SmithClient::connect() {
    LOG_INFO("connect to %s", SOCKET_PATH);

    std::lock_guard<std::mutex> _0_(mMutex);

    sockaddr_un un = {};

    un.sun_family = AF_UNIX;
    strcpy(un.sun_path, SOCKET_PATH);

    mBev = bufferevent_socket_new(
            mEventBase,
            -1,
            BEV_OPT_CLOSE_ON_FREE | BEV_OPT_THREADSAFE | BEV_OPT_DEFER_CALLBACKS | BEV_OPT_UNLOCK_CALLBACKS
    );

    if (!mBev) {
        LOG_ERROR("new buffer event failed");
        evtimer_add(mTimer, &RECONNECT_DELAY);
        return false;
    }

    struct stub {
        static void onRead(bufferevent *bev, void *ctx) {
            static_cast<SmithClient *>(ctx)->onBufferRead(bev);
        }

        static void onWrite(bufferevent *bev, void *ctx) {
            static_cast<SmithClient *>(ctx)->onBufferWrite(bev);
        }

        static void onEvent(bufferevent *bev, short what, void *ctx) {
            static_cast<SmithClient *>(ctx)->onBufferEvent(bev, what);
        }
    };

    bufferevent_setcb(mBev, stub::onRead, stub::onWrite, stub::onEvent, this);
    bufferevent_enable(mBev, EV_READ | EV_WRITE);
    bufferevent_setwatermark(mBev, EV_READ, PROTOCOL_HEADER_SIZE, EVENT_BUFFER_MAX_SIZE);

    if (bufferevent_socket_connect(mBev, (sockaddr *)&un, sizeof(un)) < 0) {
        LOG_ERROR("connect failed: %s", evutil_socket_error_to_string(EVUTIL_SOCKET_ERROR()));

        bufferevent_free(mBev);
        mBev = nullptr;

        evtimer_add(mTimer, &RECONNECT_DELAY);

        return false;
    }

    return true;
}

void SmithClient::disconnect() {
    std::lock_guard<std::mutex> _0_(mMutex);

    LOG_INFO("disconnect");

    if (mBev) {
        bufferevent_free(mBev);
        mBev = nullptr;
    }
}

void SmithClient::readMessage() {
    std::filesystem::path path = std::filesystem::path(MESSAGE_DIRECTORY) / zero::strings::format("%d.json", getppid());
    std::ifstream stream(path);

    if (!stream.is_open())
        return;

    LOG_INFO("read message from %s", path.string().c_str());

    try {
        for (const auto &message: nlohmann::json::parse(stream).get<std::list<SmithMessage>>())
            mHandler->onMessage(message);
    } catch (const nlohmann::json::exception &e) {
        LOG_ERROR("exception: %s", e.what());
    }

    stream.close();

    std::error_code ec;

    if (!std::filesystem::remove(path, ec)) {
        LOG_WARNING("remove failed: %s", ec.message().c_str());
    }
}

bool SmithClient::write(const SmithMessage &message) {
    return writeBuffer(nlohmann::json(message).dump(-1, ' ', false, nlohmann::json::error_handler_t::replace));
}

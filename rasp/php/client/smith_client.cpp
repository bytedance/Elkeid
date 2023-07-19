#include "smith_client.h"
#include <aio/ev/timer.h>
#include <aio/net/stream.h>
#include <zero/log.h>
#include <unistd.h>

using namespace std::chrono_literals;

constexpr auto SOCKET_PATH = "/var/run/smith_agent.sock";
constexpr auto MESSAGE_DIRECTORY = "/var/run/elkeid_rasp";

std::shared_ptr<zero::async::promise::Promise<void>>
transfer(
        const std::shared_ptr<aio::Context> &context,
        const zero::ptr::RefPtr<aio::ISender<SmithMessage>> &sender,
        const zero::ptr::RefPtr<aio::IReceiver<SmithMessage>> &receiver
) {
    return aio::net::stream::connect(
            context,
            SOCKET_PATH
    )->then([=](const zero::ptr::RefPtr<aio::ev::IBuffer> &buffer) {
        return zero::async::promise::all(
                zero::async::promise::doWhile([=]() {
                    return buffer->readExactly(4)->then([=](const std::vector<std::byte> &header) {
                        return buffer->readExactly(ntohl(*(uint32_t *) header.data()));
                    })->then([=](const std::vector<std::byte> &msg) {
                        LOG_INFO("message: %.*s", msg.size(), msg.data());

                        try {
                            sender->trySend(nlohmann::json::parse(msg).get<SmithMessage>());
                        } catch (const nlohmann::json::exception &e) {
                            LOG_ERROR("exception: %s", e.what());
                        }
                    });
                }),
                zero::async::promise::doWhile([=]() {
                    return receiver->receive()->then([=](const SmithMessage &message) {
                        std::string msg = nlohmann::json(message).dump(
                                -1,
                                ' ',
                                false,
                                nlohmann::json::error_handler_t::replace
                        );

                        uint32_t length = htonl(msg.length());

                        buffer->submit({(const std::byte *) &length, sizeof(uint32_t)});
                        buffer->submit({(const std::byte *) msg.data(), msg.size()});

                        if (buffer->pending() > 1024 * 1024)
                            return buffer->drain();

                        return zero::async::promise::resolve<void>();
                    });
                })
        );
    });
}

std::pair<zero::ptr::RefPtr<aio::IReceiver<SmithMessage>>, zero::ptr::RefPtr<aio::ISender<SmithMessage>>>
startClient(const std::shared_ptr<aio::Context> &context) {
    zero::ptr::RefPtr<aio::IChannel<SmithMessage>> channels[2] = {
            zero::ptr::makeRef<aio::Channel<SmithMessage, 100>>(context),
            zero::ptr::makeRef<aio::Channel<SmithMessage, 100>>(context)
    };

    zero::async::promise::doWhile([=]() {
        return transfer(context, channels[0], channels[1])->fail([=](const zero::async::promise::Reason &reason) {
            LOG_WARNING(
                    "transfer finished[code[%d] msg[%s]]",
                    reason.code,
                    reason.message.c_str()
            );

            return zero::ptr::makeRef<aio::ev::Timer>(context)->setTimeout(1min);
        });
    });

    zero::ptr::makeRef<aio::ev::Timer>(context)->setInterval(
            5min,
            [
                    channel = channels[0],
                    path = std::filesystem::path(MESSAGE_DIRECTORY) / zero::strings::format("%d.json", getppid())
            ]() {
                std::ifstream stream(path);

                if (!stream.is_open())
                    return true;

                LOG_INFO("read message from %s", path.string().c_str());

                try {
                    for (const auto &message: nlohmann::json::parse(stream).get<std::list<SmithMessage>>())
                        channel->trySend(message);
                } catch (const nlohmann::json::exception &e) {
                    LOG_ERROR("exception: %s", e.what());
                }

                stream.close();

                std::error_code ec;

                if (!std::filesystem::remove(path, ec)) {
                    LOG_WARNING("remove failed: %s", ec.message().c_str());
                }

                return true;
            }
    );

    return {channels[0], channels[1]};
}

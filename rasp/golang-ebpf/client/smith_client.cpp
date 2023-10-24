#include "smith_client.h"
#include <aio/ev/timer.h>
#include <aio/net/stream.h>
#include <zero/log.h>

using namespace std::chrono_literals;

constexpr auto SOCKET_PATH = "/var/run/smith_agent.sock";

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

                        auto result = buffer->submit({(const std::byte *) &length, sizeof(uint32_t)});

                        if (!result) {
                            LOG_WARNING("submit data failed");
                            return zero::async::promise::reject<void>({-1, "submit data failed"});
                        }
                        result =  buffer->submit({(const std::byte *) msg.data(), msg.size()});
                        if (!result) {
                            LOG_WARNING("submit data failed");
                            return zero::async::promise::reject<void>({-1, "submit data failed"});
                        }

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

    return {channels[0], channels[1]};
}

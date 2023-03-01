#include "smith_client.h"
#include <aio/ev/timer.h>
#include <aio/net/stream.h>
#include <zero/log.h>

constexpr auto SOCKET_PATH = "/var/run/smith_agent.sock";

std::shared_ptr<zero::async::promise::Promise<void>>
transfer(
        const std::shared_ptr<aio::Context> &context,
        const std::array<std::shared_ptr<aio::IChannel<SmithMessage>>, 2> &channels
) {
    return aio::net::connect(context, SOCKET_PATH)->then([=](const std::shared_ptr<aio::ev::IBuffer> &buffer) {
        return zero::async::promise::all(
                zero::async::promise::loop<void>([=](const auto &loop) {
                    buffer->read(4)->then([=](const std::vector<std::byte> &header) {
                        return buffer->read(ntohl(*(uint32_t *) header.data()));
                    })->then([=](const std::vector<std::byte> &msg) {
                        LOG_INFO("message: %.*s", msg.size(), msg.data());

                        try {
                            channels[0]->sendNoWait(nlohmann::json::parse(msg).get<SmithMessage>());
                        } catch (const nlohmann::json::exception &e) {
                            LOG_ERROR("exception: %s", e.what());
                        }

                        P_CONTINUE(loop);
                    }, [=](const zero::async::promise::Reason &reason) {
                        P_BREAK_E(loop, reason);
                    });
                }),
                zero::async::promise::loop<void>([=](const auto &loop) {
                    channels[1]->receive()->then([=](const SmithMessage &message) {
                        std::string msg = nlohmann::json(message).dump(
                                -1,
                                ' ',
                                false,
                                nlohmann::json::error_handler_t::replace
                        );

                        uint32_t length = htonl(msg.length());

                        buffer->write(&length, sizeof(uint32_t));

                        if (buffer->write(msg) > 1024 * 1024)
                            return buffer->drain();

                        return zero::async::promise::resolve<void>();
                    })->then([=]() {
                        P_CONTINUE(loop);
                    }, [=](const zero::async::promise::Reason &reason) {
                        P_BREAK_E(loop, reason);
                    });
                })
        );
    })->fail([](const zero::async::promise::Reason &reason) {
        LOG_WARNING("transfer finished: %s", reason.message.c_str());
    });
}

std::array<std::shared_ptr<aio::IChannel<SmithMessage>>, 2> startClient(const std::shared_ptr<aio::Context> &context) {
    std::array<std::shared_ptr<aio::IChannel<SmithMessage>>, 2> channels = {
            std::make_shared<aio::Channel<SmithMessage, 100>>(context),
            std::make_shared<aio::Channel<SmithMessage, 100>>(context)
    };

    zero::async::promise::loop<void>([=](const auto &loop) {
        transfer(context, channels)->finally([=]() {
            LOG_INFO("disconnect");

            std::make_shared<aio::ev::Timer>(context)->setTimeout(std::chrono::minutes{1})->then([=] {
                LOG_INFO("reconnect");
                P_CONTINUE(loop);
            });
        });
    });

    return channels;
}

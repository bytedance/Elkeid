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
        const std::shared_ptr<aio::ISender<SmithMessage>> &sender,
        const std::shared_ptr<aio::IReceiver<SmithMessage>> &receiver
) {
    return aio::net::connect(context, SOCKET_PATH)->then([=](const std::shared_ptr<aio::ev::IBuffer> &buffer) {
        return zero::async::promise::all(
                zero::async::promise::loop<void>([=](const auto &loop) {
                    buffer->read(4)->then([=](const std::vector<std::byte> &header) {
                        return buffer->read(ntohl(*(uint32_t *) header.data()));
                    })->then([=](const std::vector<std::byte> &msg) {
                        LOG_INFO("message: %.*s", msg.size(), msg.data());

                        try {
                            sender->sendNoWait(nlohmann::json::parse(msg).get<SmithMessage>());
                        } catch (const nlohmann::json::exception &e) {
                            LOG_ERROR("exception: %s", e.what());
                        }

                        P_CONTINUE(loop);
                    }, [=](const zero::async::promise::Reason &reason) {
                        P_BREAK_E(loop, reason);
                    });
                }),
                zero::async::promise::loop<void>([=](const auto &loop) {
                    receiver->receive()->then([=](const SmithMessage &message) {
                        std::string msg = nlohmann::json(message).dump(
                                -1,
                                ' ',
                                false,
                                nlohmann::json::error_handler_t::replace
                        );

                        uint32_t length = htonl(msg.length());

                        buffer->write({(const std::byte *) &length, sizeof(uint32_t)});

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

std::pair<std::shared_ptr<aio::IReceiver<SmithMessage>>, std::shared_ptr<aio::ISender<SmithMessage>>>
startClient(const std::shared_ptr<aio::Context> &context) {
    std::shared_ptr<aio::IChannel<SmithMessage>> channels[2] = {
            std::make_shared<aio::Channel<SmithMessage, 100>>(context),
            std::make_shared<aio::Channel<SmithMessage, 100>>(context)
    };

    zero::async::promise::loop<void>([=](const auto &loop) {
        transfer(context, channels[0], channels[1])->finally([=]() {
            LOG_INFO("disconnect");

            std::make_shared<aio::ev::Timer>(context)->setTimeout(1min)->then([=] {
                LOG_INFO("reconnect");
                P_CONTINUE(loop);
            });
        });
    });

    std::make_shared<aio::ev::Timer>(context)->setInterval(
            5min,
            [
                    channel = channels[0],
                    path = std::filesystem::path(MESSAGE_DIRECTORY) / zero::strings::format("%d.json", getpid())
            ]() {
                std::ifstream stream(path);

                if (!stream.is_open())
                    return true;

                LOG_INFO("read message from %s", path.string().c_str());

                try {
                    for (const auto &message: nlohmann::json::parse(stream).get<std::list<SmithMessage>>())
                        channel->sendNoWait(message);
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

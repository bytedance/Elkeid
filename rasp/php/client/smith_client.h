#ifndef PHP_PROBE_SMITH_CLIENT_H
#define PHP_PROBE_SMITH_CLIENT_H

#include "smith_message.h"
#include <aio/channel.h>

std::array<std::shared_ptr<aio::IChannel<SmithMessage>>, 2> startClient(const std::shared_ptr<aio::Context> &context);

#endif //PHP_PROBE_SMITH_CLIENT_H

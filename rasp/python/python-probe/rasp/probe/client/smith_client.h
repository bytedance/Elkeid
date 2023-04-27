#ifndef PYTHON_CLIENT_SMITH_CLIENT_H
#define PYTHON_CLIENT_SMITH_CLIENT_H

#include "smith_message.h"
#include <aio/channel.h>

std::pair<std::shared_ptr<aio::IReceiver<SmithMessage>>, std::shared_ptr<aio::ISender<SmithMessage>>>
startClient(const std::shared_ptr<aio::Context> &context);

#endif //PYTHON_CLIENT_SMITH_CLIENT_H

#ifndef GO_PROBE_EBPF_SMITH_CLIENT_H
#define GO_PROBE_EBPF_SMITH_CLIENT_H

#include "smith_message.h"
#include <aio/sync/channel.h>

std::array<std::shared_ptr<aio::sync::IChannel<SmithMessage>>, 2> startClient(const aio::Context &context);

#endif //GO_PROBE_EBPF_SMITH_CLIENT_H

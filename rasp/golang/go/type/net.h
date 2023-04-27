#ifndef GO_PROBE_NET_H
#define GO_PROBE_NET_H

#include "basic.h"

namespace go {
    namespace net {
        struct TCPAddress {
            go::Slice<go::Uint8> ip;
            go::Int port;
            go::String zone;
        };

        typedef TCPAddress UDPAddress;

        struct IPAddress {
            go::Slice<go::Uint8> ip;
            go::String zone;
        };

        struct UnixAddress {
            go::String name;
            go::String net;
        };
    }

    METADATA(net::TCPAddress, go::Slice<go::Uint8>, go::Int, go::String)
    METADATA(net::IPAddress, go::Slice<go::Uint8>, go::String)
    METADATA(net::UnixAddress, go::String, go::String)
}

#endif //GO_PROBE_NET_H

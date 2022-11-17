#ifndef GO_PROBE_NET_H
#define GO_PROBE_NET_H

#include "basic.h"

namespace go {
    struct net_address {
        go::string network;
        go::string address;
    };

    METADATA(net_address, go::string, go::string)

    struct tcp_address {
        go::slice<go::Uint8> ip;
        go::Int port;
        go::string zone;
    };

    METADATA(tcp_address, go::slice<go::Uint8>, go::Int, go::string)

    typedef tcp_address udp_address;

    struct ip_address {
        go::slice<go::Uint8> ip;
        go::string zone;
    };

    METADATA(ip_address, go::slice<go::Uint8>, go::string)

    struct unix_address {
        go::string name;
        go::string net;
    };

    METADATA(unix_address, go::string, go::string)
}

#endif //GO_PROBE_NET_H

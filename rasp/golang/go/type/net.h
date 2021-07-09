#ifndef GO_PROBE_NET_H
#define GO_PROBE_NET_H

#include "basic.h"

struct net_address {
    go::string network;
    go::string address;
};

struct tcp_addr {
    go::slice<go::Uint8> ip;
    go::Int port;
    go::string zone;
};

typedef tcp_addr udp_addr;

struct ip_addr {
    go::slice<go::Uint8> ip;
    go::string zone;
};

struct unix_addr {
    go::string name;
    go::string net;
};

#endif //GO_PROBE_NET_H

#ifndef GO_PROBE_API_H
#define GO_PROBE_API_H

#include "hook.h"

struct CAPIRegister {
    const char *name;
    CAPIMetadata metadata;
    bool ignoreCase;
};

constexpr std::initializer_list<CAPIRegister> APIRegistry = {
        {
                "os/exec.Command",
                CAPIEntry<0, 0, go::string, go::slice<go::string>>::metadata(),
                false
        },
        {
                "os/exec.(*Cmd).Start",
                CAPIEntry<0, 1, go::exec_cmd *>::metadata(),
                false
        },
        {
                "os.OpenFile",
                CAPIEntry<1, 0, go::string, go::Int, go::Uint32>::metadata(),
                false
        },
        {
                "os.Remove",
                CAPIEntry<1, 1, go::string>::metadata(),
                false
        },
        {
                "os.RemoveAll",
                CAPIEntry<1, 2, go::string>::metadata(),
                false
        },
        {
                "os.Rename",
                CAPIEntry<1, 3, go::string, go::string>::metadata(),
                true
        },
        {
                "io/ioutil.ReadDir",
                CAPIEntry<1, 4, go::string>::metadata(),
                false
        },
        {
                "net.Dial",
                CAPIEntry<2, 0, go::string, go::string>::metadata(),
                false
        },
        {
                "net.DialTCP",
                CAPIEntry<2, 1, go::string, go::tcp_address *, go::tcp_address *>::metadata(),
                false
        },
        {
                "net.DialIP",
                CAPIEntry<2, 2, go::string, go::ip_address *, go::ip_address *>::metadata(),
                false
        },
        {
                "net.DialUDP",
                CAPIEntry<2, 3, go::string, go::udp_address *, go::udp_address *>::metadata(),
                false
        },
        {
                "net.DialUnix",
                CAPIEntry<2, 4, go::string, go::unix_address *, go::unix_address *>::metadata(),
                false
        },
        {
                "net.(*Dialer).DialContext",
                CAPIEntry<2, 5, go::Uintptr, go::interface, go::string, go::string>::metadata(),
                false
        },
        {
                "net.ResolveTCPAddr",
                CAPIEntry<3, 0, go::string, go::string>::metadata(),
                false
        },
        {
                "net.ResolveIPAddr",
                CAPIEntry<3, 1, go::string, go::string>::metadata(),
                false
        },
        {
                "net.ResolveUDPAddr",
                CAPIEntry<3, 2, go::string, go::string>::metadata(),
                false
        },
        {
                "net.ResolveUnixAddr",
                CAPIEntry<3, 3, go::string, go::string>::metadata(),
                false
        },
        {
                "net.LookupAddr",
                CAPIEntry<4, 0, go::string>::metadata(),
                false
        },
        {
                "net.LookupCNAME",
                CAPIEntry<4, 1, go::string>::metadata(),
                false
        },
        {
                "net.LookupHost",
                CAPIEntry<4, 2, go::string>::metadata(),
                false
        },
        {
                "net.LookupPort",
                CAPIEntry<4, 3, go::string, go::string>::metadata(),
                false
        },
        {
                "net.LookupTXT",
                CAPIEntry<4, 4, go::string>::metadata(),
                false
        },
        {
                "net.LookupIP",
                CAPIEntry<4, 5, go::string>::metadata(),
                false
        },
        {
                "net.LookupMX",
                CAPIEntry<4, 6, go::string>::metadata(),
                false
        },
        {
                "net.LookupNS",
                CAPIEntry<4, 7, go::string>::metadata(),
                false
        },
        {
                "net.(*Resolver).LookupAddr",
                CAPIEntry<4, 8, go::Uintptr, go::interface, go::string>::metadata(),
                true
        },
        {
                "net.(*Resolver).LookupCNAME",
                CAPIEntry<4, 9, go::Uintptr, go::interface, go::string>::metadata(),
                true
        },
        {
                "net.(*Resolver).LookupHost",
                CAPIEntry<4, 10, go::Uintptr, go::interface, go::string>::metadata(),
                false
        },
        {
                "net.(*Resolver).LookupPort",
                CAPIEntry<4, 11, go::Uintptr, go::interface, go::string, go::string>::metadata(),
                false
        },
        {
                "net.(*Resolver).LookupTXT",
                CAPIEntry<4, 12, go::Uintptr, go::interface, go::string>::metadata(),
                true
        },
        {
                "net.(*Resolver).LookupIPAddr",
                CAPIEntry<4, 13, go::Uintptr, go::interface, go::string>::metadata(),
                false
        },
        {
                "net.(*Resolver).LookupMX",
                CAPIEntry<4, 14, go::Uintptr, go::interface, go::string>::metadata(),
                true
        },
        {
                "net.(*Resolver).LookupNS",
                CAPIEntry<4, 15, go::Uintptr, go::interface, go::string>::metadata(),
                true
        },
        {
                "net.Listen",
                CAPIEntry<5, 0, go::string, go::string>::metadata(),
                false
        },
        {
                "net.ListenTCP",
                CAPIEntry<5, 1, go::string, go::tcp_address *>::metadata(),
                false
        },
        {
                "net.ListenIP",
                CAPIEntry<5, 2, go::string, go::ip_address *>::metadata(),
                false
        },
        {
                "net.ListenUDP",
                CAPIEntry<5, 3, go::string, go::udp_address *>::metadata(),
                false
        },
        {
                "net.ListenUnix",
                CAPIEntry<5, 4, go::string, go::unix_address *>::metadata(),
                false
        },
        {
                "net/http.NewRequest",
                CAPIEntry<6, 0, go::string, go::string>::metadata(),
                false
        },
        {
                "net/http.NewRequestWithContext",
                CAPIEntry<6, 1, go::interface, go::string, go::string>::metadata(),
                false
        },
        {
                "plugin.Open",
                CAPIEntry<7, 0, go::string>::metadata(),
                false
        }
};

#endif //GO_PROBE_API_H

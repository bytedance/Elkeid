#include "api_registry.h"
#include <go/api/api.h>
#include <common/log.h>
#include <common/utils/string_helper.h>

#define INSERT(name, api) insert(name, (void *)ENTRY_NAME(api), ORIGIN_PTR(api))
#define INSERT_BLACKLIST(name) mBlacklist.emplace_back(name)

CAPIRegistry::CAPIRegistry() {
    INSERT("os/exec.Command", exec_command);
    INSERT("os/exec.(*Cmd).Start", exec_cmd_start);

    INSERT("os.OpenFile", os_openfile);
    INSERT("os.Remove", os_remove);
    INSERT("os.RemoveAll", os_remove_all);
    INSERT("os.Rename", os_rename);
    INSERT("io/ioutil.ReadDir", os_readdir);

    INSERT("net.Dial", net_dial);
    INSERT("net.DialTCP", net_dial_tcp);
    INSERT("net.DialIP", net_dial_ip);
    INSERT("net.DialUDP", net_dial_udp);
    INSERT("net.DialUnix", net_dial_unix);

    INSERT("net.(*Dialer).DialContext", net_dialer_dial_context);

    INSERT("net.ResolveTCPAddr", net_resolve_tcp_addr);
    INSERT("net.ResolveIPAddr", net_resolve_ip_addr);
    INSERT("net.ResolveUDPAddr", net_resolve_udp_addr);
    INSERT("net.ResolveUnixAddr", net_resolve_unix_addr);

    INSERT("net.LookupAddr", net_lookup_addr);
    INSERT("net.LookupCNAME", net_lookup_cname);
    INSERT("net.LookupHost", net_lookup_host);
    INSERT("net.LookupPort", net_lookup_port);
    INSERT("net.LookupTXT", net_lookup_txt);
    INSERT("net.LookupIP", net_lookup_ip);
    INSERT("net.LookupMX", net_lookup_mx);
    INSERT("net.LookupNS", net_lookup_ns);

    INSERT("net.(*Resolver).LookupAddr", net_resolver_lookup_addr);
    INSERT("net.(*Resolver).LookupCNAME", net_resolver_lookup_cname);
    INSERT("net.(*Resolver).LookupHost", net_resolver_lookup_host);
    INSERT("net.(*Resolver).LookupPort", net_resolver_lookup_port);
    INSERT("net.(*Resolver).LookupTXT", net_resolver_lookup_txt);
    INSERT("net.(*Resolver).LookupMX", net_resolver_lookup_mx);
    INSERT("net.(*Resolver).LookupNS", net_resolver_lookup_ns);

    INSERT("net.Listen", net_listen);
    INSERT("net.ListenTCP", net_listen_tcp);
    INSERT("net.ListenIP", net_listen_ip);
    INSERT("net.ListenUDP", net_listen_udp);
    INSERT("net.ListenUnix", net_listen_unix);

    INSERT("net/http.NewRequest", net_http_new_request);
    INSERT("net/http.NewRequestWithContext", net_http_new_request_with_context);

    INSERT("plugin.Open", plugin_open);

    INSERT_BLACKLIST("net.dial");
    INSERT_BLACKLIST("net.dialIP");
    INSERT_BLACKLIST("net.dialTCP");
    INSERT_BLACKLIST("net.dialUDP");
    INSERT_BLACKLIST("net.dialUnix");
}

bool CAPIRegistry::find(const std::string &name, CAPIRegister& apiRegister) {
    if (std::find(mBlacklist.begin(), mBlacklist.end(), name) != mBlacklist.end()) {
        LOG_INFO("blacklist: %s", name.c_str());
        return false;
    }

    auto it = mRegistry.find(CStringHelper::tolower(name));

    if (it == mRegistry.end())
        return false;

    apiRegister = it->second;
    mRegistry.erase(it);

    return true;
}

void CAPIRegistry::insert(const std::string &name, void *entry, void **origin) {
    mRegistry.insert(std::make_pair(CStringHelper::tolower(name), CAPIRegister{entry, origin}));
}

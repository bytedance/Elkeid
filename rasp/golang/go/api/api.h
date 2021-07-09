#ifndef GO_PROBE_API_H
#define GO_PROBE_API_H

#include "hook.h"

GO_HOOK_ENTRY_DEFINE(exec_command, 0, 0)
GO_HOOK_ENTRY_DEFINE(exec_cmd_start, 0, 1)

GO_HOOK_ENTRY_DEFINE(os_openfile, 1, 0)
GO_HOOK_ENTRY_DEFINE(os_remove, 1, 1)
GO_HOOK_ENTRY_DEFINE(os_remove_all, 1, 2)
GO_HOOK_ENTRY_DEFINE(os_rename, 1, 3)
GO_HOOK_ENTRY_DEFINE(os_readdir, 1, 4)

GO_HOOK_ENTRY_DEFINE(net_dial, 2, 0)
GO_HOOK_ENTRY_DEFINE(net_dial_tcp, 2, 1)
GO_HOOK_ENTRY_DEFINE(net_dial_ip, 2, 2)
GO_HOOK_ENTRY_DEFINE(net_dial_udp, 2, 3)
GO_HOOK_ENTRY_DEFINE(net_dial_unix, 2, 4)

GO_HOOK_ENTRY_DEFINE(net_dialer_dial_context, 2, 5)

GO_HOOK_ENTRY_DEFINE(net_resolve_tcp_addr, 3, 0)
GO_HOOK_ENTRY_DEFINE(net_resolve_ip_addr, 3, 1)
GO_HOOK_ENTRY_DEFINE(net_resolve_udp_addr, 3, 2)
GO_HOOK_ENTRY_DEFINE(net_resolve_unix_addr, 3, 3)

GO_HOOK_ENTRY_DEFINE(net_lookup_addr, 4, 0)
GO_HOOK_ENTRY_DEFINE(net_lookup_cname, 4, 1)
GO_HOOK_ENTRY_DEFINE(net_lookup_host, 4, 2)
GO_HOOK_ENTRY_DEFINE(net_lookup_port, 4, 3)
GO_HOOK_ENTRY_DEFINE(net_lookup_txt, 4, 4)
GO_HOOK_ENTRY_DEFINE(net_lookup_ip, 4, 5)
GO_HOOK_ENTRY_DEFINE(net_lookup_mx, 4, 6)
GO_HOOK_ENTRY_DEFINE(net_lookup_ns, 4, 7)

GO_HOOK_ENTRY_DEFINE(net_resolver_lookup_addr, 4, 8)
GO_HOOK_ENTRY_DEFINE(net_resolver_lookup_cname, 4, 9)
GO_HOOK_ENTRY_DEFINE(net_resolver_lookup_host, 4, 10)
GO_HOOK_ENTRY_DEFINE(net_resolver_lookup_port, 4, 11)
GO_HOOK_ENTRY_DEFINE(net_resolver_lookup_txt, 4, 12)
GO_HOOK_ENTRY_DEFINE(net_resolver_lookup_ip_addr, 4, 13)
GO_HOOK_ENTRY_DEFINE(net_resolver_lookup_mx, 4, 14)
GO_HOOK_ENTRY_DEFINE(net_resolver_lookup_ns, 4, 15)

GO_HOOK_ENTRY_DEFINE(net_listen, 5, 0)
GO_HOOK_ENTRY_DEFINE(net_listen_tcp, 5, 1)
GO_HOOK_ENTRY_DEFINE(net_listen_ip, 5, 2)
GO_HOOK_ENTRY_DEFINE(net_listen_udp, 5, 3)
GO_HOOK_ENTRY_DEFINE(net_listen_unix, 5, 4)

GO_HOOK_ENTRY_DEFINE(net_http_new_request, 6, 0)
GO_HOOK_ENTRY_DEFINE(net_http_new_request_with_context, 6, 1)

GO_HOOK_ENTRY_DEFINE(plugin_open, 7, 0)

#endif //GO_PROBE_API_H

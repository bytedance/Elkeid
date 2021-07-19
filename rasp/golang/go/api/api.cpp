#include "api.h"

GO_HOOK_ENTRY(exec_command, go::string, go::slice<go::string>)
GO_HOOK_ENTRY(exec_cmd_start, go::exec_cmd *)

GO_HOOK_ENTRY(os_openfile, go::string, go::Int, go::Uint32)
GO_HOOK_ENTRY(os_remove, go::string)
GO_HOOK_ENTRY(os_remove_all, go::string)
GO_HOOK_ENTRY(os_rename, go::string, go::string)
GO_HOOK_ENTRY(os_readdir, go::string)

GO_HOOK_ENTRY(net_dial, go::string, go::string)
GO_HOOK_ENTRY(net_dial_tcp, go::string, go::tcp_address *, go::tcp_address *)
GO_HOOK_ENTRY(net_dial_ip, go::string, go::ip_address *, go::ip_address *)
GO_HOOK_ENTRY(net_dial_udp, go::string, go::udp_address *, go::udp_address *)
GO_HOOK_ENTRY(net_dial_unix, go::string, go::unix_address *, go::unix_address *)

GO_HOOK_ENTRY(net_dialer_dial_context, go::Uintptr, go::interface, go::string, go::string)

GO_HOOK_ENTRY(net_resolve_tcp_addr, go::string, go::string)
GO_HOOK_ENTRY(net_resolve_ip_addr, go::string, go::string)
GO_HOOK_ENTRY(net_resolve_udp_addr, go::string, go::string)
GO_HOOK_ENTRY(net_resolve_unix_addr, go::string, go::string)

GO_HOOK_ENTRY(net_lookup_addr, go::string)
GO_HOOK_ENTRY(net_lookup_cname, go::string)
GO_HOOK_ENTRY(net_lookup_host, go::string)
GO_HOOK_ENTRY(net_lookup_port, go::string, go::string)
GO_HOOK_ENTRY(net_lookup_txt, go::string)
GO_HOOK_ENTRY(net_lookup_ip, go::string)
GO_HOOK_ENTRY(net_lookup_mx, go::string)
GO_HOOK_ENTRY(net_lookup_ns, go::string)

GO_HOOK_ENTRY(net_resolver_lookup_addr, go::Uintptr, go::interface, go::string)
GO_HOOK_ENTRY(net_resolver_lookup_cname, go::Uintptr, go::interface, go::string)
GO_HOOK_ENTRY(net_resolver_lookup_host, go::Uintptr, go::interface, go::string)
GO_HOOK_ENTRY(net_resolver_lookup_port, go::Uintptr, go::interface, go::string, go::string)
GO_HOOK_ENTRY(net_resolver_lookup_txt, go::Uintptr, go::interface, go::string)
GO_HOOK_ENTRY(net_resolver_lookup_ip_addr, go::Uintptr, go::interface, go::string)
GO_HOOK_ENTRY(net_resolver_lookup_mx, go::Uintptr, go::interface, go::string)
GO_HOOK_ENTRY(net_resolver_lookup_ns, go::Uintptr, go::interface, go::string)

GO_HOOK_ENTRY(net_listen, go::string, go::string)
GO_HOOK_ENTRY(net_listen_tcp, go::string, go::tcp_address *)
GO_HOOK_ENTRY(net_listen_ip, go::string, go::ip_address *)
GO_HOOK_ENTRY(net_listen_udp, go::string, go::udp_address *)
GO_HOOK_ENTRY(net_listen_unix, go::string, go::unix_address *)

GO_HOOK_ENTRY(net_http_new_request, go::string, go::string)
GO_HOOK_ENTRY(net_http_new_request_with_context, go::interface, go::string, go::string)

GO_HOOK_ENTRY(plugin_open, go::string)

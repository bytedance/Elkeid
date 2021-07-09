#include "api.h"

constexpr auto DIALER_OFFSET = sizeof(go::Uintptr) + sizeof(go::interface);
constexpr auto RESOLVER_OFFSET = sizeof(go::Uintptr) + sizeof(go::interface);

GO_HOOK_ENTRY(exec_command, 0, go::string, go::slice<go::string>)
GO_HOOK_ENTRY(exec_cmd_start, 0, exec_cmd *)

GO_HOOK_ENTRY(os_openfile, 0, go::string, go::Int, go::Uint32)
GO_HOOK_ENTRY(os_remove, 0, go::string)
GO_HOOK_ENTRY(os_remove_all, 0, go::string)
GO_HOOK_ENTRY(os_rename, 0, go::string, go::string)
GO_HOOK_ENTRY(os_readdir, 0, go::string)

GO_HOOK_ENTRY(net_dial, 0, go::string, go::string)
GO_HOOK_ENTRY(net_dial_tcp, 0, go::string, tcp_addr *, tcp_addr *)
GO_HOOK_ENTRY(net_dial_ip, 0, go::string, ip_addr *, ip_addr *)
GO_HOOK_ENTRY(net_dial_udp, 0, go::string, udp_addr *, udp_addr *)
GO_HOOK_ENTRY(net_dial_unix, 0, go::string, unix_addr *, unix_addr *)

GO_HOOK_ENTRY(net_dialer_dial_context, DIALER_OFFSET, go::string, go::string)

GO_HOOK_ENTRY(net_resolve_tcp_addr, 0, go::string, go::string)
GO_HOOK_ENTRY(net_resolve_ip_addr, 0, go::string, go::string)
GO_HOOK_ENTRY(net_resolve_udp_addr, 0, go::string, go::string)
GO_HOOK_ENTRY(net_resolve_unix_addr, 0, go::string, go::string)

GO_HOOK_ENTRY(net_lookup_addr, 0, go::string)
GO_HOOK_ENTRY(net_lookup_cname, 0, go::string)
GO_HOOK_ENTRY(net_lookup_host, 0, go::string)
GO_HOOK_ENTRY(net_lookup_port, 0, go::string, go::string)
GO_HOOK_ENTRY(net_lookup_txt, 0, go::string)
GO_HOOK_ENTRY(net_lookup_ip, 0, go::string)
GO_HOOK_ENTRY(net_lookup_mx, 0, go::string)
GO_HOOK_ENTRY(net_lookup_ns, 0, go::string)

GO_HOOK_ENTRY(net_resolver_lookup_addr, RESOLVER_OFFSET, go::string)
GO_HOOK_ENTRY(net_resolver_lookup_cname, RESOLVER_OFFSET, go::string)
GO_HOOK_ENTRY(net_resolver_lookup_host, RESOLVER_OFFSET, go::string)
GO_HOOK_ENTRY(net_resolver_lookup_port, RESOLVER_OFFSET, go::string, go::string)
GO_HOOK_ENTRY(net_resolver_lookup_txt, RESOLVER_OFFSET, go::string)
GO_HOOK_ENTRY(net_resolver_lookup_ip_addr, RESOLVER_OFFSET, go::string)
GO_HOOK_ENTRY(net_resolver_lookup_mx, RESOLVER_OFFSET, go::string)
GO_HOOK_ENTRY(net_resolver_lookup_ns, RESOLVER_OFFSET, go::string)

GO_HOOK_ENTRY(net_listen, 0, go::string, go::string)
GO_HOOK_ENTRY(net_listen_tcp, 0, go::string, tcp_addr *)
GO_HOOK_ENTRY(net_listen_ip, 0, go::string, ip_addr *)
GO_HOOK_ENTRY(net_listen_udp, 0, go::string, udp_addr *)
GO_HOOK_ENTRY(net_listen_unix, 0, go::string, unix_addr *)

GO_HOOK_ENTRY(net_http_new_request, 0, go::string, go::string)
GO_HOOK_ENTRY(net_http_new_request_with_context, sizeof(go::interface), go::string, go::string)

GO_HOOK_ENTRY(plugin_open, 0, go::string)

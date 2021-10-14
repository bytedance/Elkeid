/* SPDX-License-Identifier: GPL-2.0 */
#if !defined(_KPROBE_PRINT_H) || defined(TRACE_HEADER_MULTI_READ)
#define _KPROBE_PRINT_H

#include "trace.h"
#include "struct_wrap.h"

#define RS "\x1e"

PRINT_EVENT_DEFINE(call_usermodehelper_exec,

                   PE_PROTO(const char * exe, char * argv, int wait),

                   PE_ARGS(exe, argv, wait),

                   PE_printk("607" RS "%s" RS "%s" RS "%d",
                           __get_str(exe, exe), __get_str(argv, argv), __get_ent(wait, wait))
);

PRINT_EVENT_DEFINE(security_inode4_create,

                   PE_PROTO(char * exe_path, char * pathstr, __be32 dip,
                                   int dport, __be32 sip, int sport, pid_t socket_pid, char * s_id),

                   PE_ARGS(exe_path, pathstr, dip, dport, sip, sport, socket_pid, s_id),

                   PE_printk("602" RS "%d" RS "%s" RS "%d" RS "%d" RS "%d" RS "%d" RS "%d" RS "%s" RS "%s" RS "%u" RS "%u" RS "%u" RS "%s" RS "%d.%d.%d.%d" RS "%d" RS "%d.%d.%d.%d" RS "%d" RS "2" RS "%d" RS "%s",
                           __get_ent(uid, __get_current_uid()),
                           __get_str(exe_path, exe_path),
                           __get_ent(pid, current->pid),
                           __get_ent(ppid, current->real_parent->tgid),
                           __get_ent(pgid, __get_pgid()),
                           __get_ent(tgid, current->tgid),
                           __get_ent(sid, __get_sid()),
                           __get_stl(comm, current->comm, TASK_COMM_LEN),
                           __get_str(nodename, current->nsproxy->uts_ns->name.nodename),
                           __get_ent(sessionid, __get_sessionid()),
                           __get_ent(pid_inum, __get_pid_ns_inum()),
                           __get_ent(root_pid_inum, ROOT_PID_NS_INUM),
                           __get_str(pathstr, pathstr),
                           NIPQUAD(__get_ent(dip, dip)),
                           __get_ent(dport, dport),
                           NIPQUAD(__get_ent(sip, sip)),
                           __get_ent(sport, sport),
                           __get_ent(socket_pid, socket_pid),
                           __get_str(s_id, s_id)
                   )
);

PRINT_EVENT_DEFINE(security_inode_create_nosocket,

                   PE_PROTO(char * exe_path, char * pathstr, char * s_id),

                   PE_ARGS(exe_path, pathstr, s_id),

                   PE_printk("602" RS "%d" RS "%s" RS "%d" RS "%d" RS "%d" RS "%d" RS "%d" RS "%s" RS "%s" RS "%u" RS "%u" RS "%u" RS "%s" RS "-1" RS "-1" RS "-1" RS "-1" RS "-1" RS "-1" RS "-1" RS "%s",
                           __get_ent(uid, __get_current_uid()),
                           __get_str(exe_path, exe_path),
                           __get_ent(pid, current->pid),
                           __get_ent(ppid, current->real_parent->tgid),
                           __get_ent(pgid, __get_pgid()),
                           __get_ent(tgid, current->tgid),
                           __get_ent(sid, __get_sid()),
                           __get_stl(comm, current->comm, TASK_COMM_LEN),
                           __get_str(nodename, current->nsproxy->uts_ns->name.nodename),
                           __get_ent(sessionid, __get_sessionid()),
                           __get_ent(pid_inum, __get_pid_ns_inum()),
                           __get_ent(root_pid_inum, ROOT_PID_NS_INUM),
                           __get_str(pathstr, pathstr),
                           __get_str(s_id, s_id)
                   )
);


#if IS_ENABLED(CONFIG_IPV6)
PRINT_EVENT_DEFINE(security_inode6_create,


                   PE_PROTO(char * exe_path, char * pathstr, struct in6_addr *dip, int dport, struct in6_addr *sip,
                           int sport, pid_t socket_pid, char * s_id),

                   PE_ARGS(exe_path, pathstr, dip, dport, sip, sport, socket_pid, s_id),

                   PE_printk("602" RS "%d" RS "%s" RS "%d" RS "%d" RS "%d" RS "%d" RS "%d" RS "%s" RS "%s" RS "%u" RS "%u" RS "%u" RS "%s" RS "%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x" RS "%d" RS "%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x" RS "%d" RS "10" RS "%d" RS "%s",
                           __get_ent(uid, __get_current_uid()),
                           __get_str(exe_path, exe_path),
                           __get_ent(pid, current->pid),
                           __get_ent(ppid, current->real_parent->tgid),
                           __get_ent(pgid, __get_pgid()),
                           __get_ent(tgid, current->tgid),
                           __get_ent(sid, __get_sid()),
                           __get_stl(comm, current->comm, TASK_COMM_LEN),
                           __get_str(nodename, current->nsproxy->uts_ns->name.nodename),
                           __get_ent(sessionid, __get_sessionid()),
                           __get_ent(pid_inum, __get_pid_ns_inum()),
                           __get_ent(root_pid_inum, ROOT_PID_NS_INUM),
                           __get_str(pathstr, pathstr),
                           NIP6(__get_ent(*dip, *dip)), 
                           __get_ent(dport, dport),
                           NIP6(__get_ent(*sip, *sip)),
                           __get_ent(sport, sport),
                           __get_ent(socket_pid, socket_pid),
                           __get_str(s_id, s_id)
                   )
);
#endif

PRINT_EVENT_DEFINE(dns,

                   PE_PROTO(int dport,
                           __be32 dip, char * exe_path,
                           __be32 sip, int sport, int opcode, int rcode,
                           char * query),

                   PE_ARGS(dport, dip, exe_path,
                           sip, sport, opcode, rcode,
                           query),

                   PE_printk("601" RS "%d" RS "%s" RS "%d" RS "%d" RS "%d" RS "%d" RS "%d" RS "%s" RS "%s" RS "%u" RS "%u" RS "%u" RS "%s" RS "2" RS "%d.%d.%d.%d" RS "%d" RS "%d.%d.%d.%d" RS "%d" RS "%d" RS "%d",
                           __get_ent(uid, __get_current_uid()),
                           __get_str(exe_path, exe_path),
                           __get_ent(pid, current->pid),
                           __get_ent(ppid, current->real_parent->tgid),
                           __get_ent(pgid, __get_pgid()),
                           __get_ent(tgid, current->tgid),
                           __get_ent(sid, __get_sid()),
                           __get_stl(comm, current->comm, TASK_COMM_LEN),
                           __get_str(nodename, current->nsproxy->uts_ns->name.nodename),
                           __get_ent(sessionid, __get_sessionid()),
                           __get_ent(pid_inum, __get_pid_ns_inum()),
                           __get_ent(root_pid_inum, ROOT_PID_NS_INUM),
                           __get_str(query, query),
                           NIPQUAD(__get_ent(dip, dip)),
                           __get_ent(dport, dport),
                           NIPQUAD(__get_ent(sip, sip)),
                           __get_ent(sport, sport),
                           __get_ent(opcode, opcode),
                           __get_ent(rcode, rcode)
                   )
);

#if IS_ENABLED(CONFIG_IPV6)
PRINT_EVENT_DEFINE(dns6,

                   PE_PROTO(int dport,
                           struct in6_addr *dip, char * exe_path,
                           struct in6_addr *sip, int sport, int opcode, int rcode,
                           char * query),

                   PE_ARGS(dport, dip, exe_path,
                           sip, sport, opcode, rcode,
                           query),

                   PE_printk("601" RS "%d" RS "%s" RS "%d" RS "%d" RS "%d" RS "%d" RS "%d" RS "%s" RS "%s" RS "%u" RS "%u" RS "%u" RS "%s" RS "10" RS "%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x" RS "%d" RS "%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x" RS "%d" RS "%d" RS "%d",
                           __get_ent(uid, __get_current_uid()),
                           __get_str(exe_path, exe_path),
                           __get_ent(pid, current->pid),
                           __get_ent(ppid, current->real_parent->tgid),
                           __get_ent(pgid, __get_pgid()),
                           __get_ent(tgid, current->tgid),
                           __get_ent(sid, __get_sid()),
                           __get_stl(comm, current->comm, TASK_COMM_LEN),
                           __get_str(nodename, current->nsproxy->uts_ns->name.nodename),
                           __get_ent(sessionid, __get_sessionid()),
                           __get_ent(pid_inum, __get_pid_ns_inum()),
                           __get_ent(root_pid_inum, ROOT_PID_NS_INUM),
                           __get_str(query, query),
                           NIP6(__get_ent(*dip, *dip)),
                           __get_ent(dport, dport),
                           NIP6(__get_ent(*sip, *sip)),
                           __get_ent(sport, sport),
                           __get_ent(opcode, opcode),
                           __get_ent(rcode, rcode)
                   )
);
#endif

PRINT_EVENT_DEFINE(execve,

                   PE_PROTO(char * pname, char * exe_path, char * argv,
                            char * tmp_stdin, char * tmp_stdout,
                            __be32 dip, int dport, __be32 sip, int sport,
                           char * pid_tree, char * tty_name, pid_t socket_pid,
                           char * ssh_connection, char * ld_preload, int retval),

                   PE_ARGS(pname, exe_path, argv,
                           tmp_stdin, tmp_stdout,
                           dip, dport, sip, sport,
                           pid_tree, tty_name, socket_pid,
                           ssh_connection, ld_preload, retval),

                   PE_printk("59" RS "%d" RS "%s" RS "%d" RS "%d" RS "%d" RS "%d" RS "%d" RS "%s" RS "%s" RS "%u" RS "%u" RS "%u" RS "%s" RS "%s" RS "%s" RS "%s" RS "%d.%d.%d.%d" RS "%d" RS "%d.%d.%d.%d" RS "%d" RS "2" RS "%s" RS "%s" RS "%d" RS "%s" RS "%s" RS "%d",
                           __get_ent(uid, __get_current_uid()),
                           __get_str(exe_path, exe_path),
                           __get_ent(pid, current->pid),
                           __get_ent(ppid, current->real_parent->tgid),
                           __get_ent(pgid, __get_pgid()),
                           __get_ent(tgid, current->tgid),
                           __get_ent(sid, __get_sid()),
                           __get_stl(comm, current->comm, TASK_COMM_LEN),
                           __get_str(nodename, current->nsproxy->uts_ns->name.nodename),
                           __get_ent(sessionid, __get_sessionid()),
                           __get_ent(pid_inum, __get_pid_ns_inum()),
                           __get_ent(root_pid_inum, ROOT_PID_NS_INUM),

                           __get_str(argv, argv),
                           __get_str(pname, pname),
                           __get_str(tmp_stdin, tmp_stdin),
                           __get_str(tmp_stdout, tmp_stdout),
                           NIPQUAD(__get_ent(dip, dip)),
                           __get_ent(dport, dport),
                           NIPQUAD(__get_ent(sip, sip)),
                           __get_ent(sport, sport),
                           __get_str(pid_tree, pid_tree),
                           __get_str(tty_name, tty_name),
                           __get_ent(socket_pid, socket_pid),
                           __get_str(ssh_connection, ssh_connection),
                           __get_str(ld_preload, ld_preload),
                           __get_ent(retval, retval)
                   )
);

PRINT_EVENT_DEFINE(execve_nosocket,

                   PE_PROTO(char * pname, char * exe_path, char * argv,
                            char * tmp_stdin, char * tmp_stdout, char * pid_tree,
                            char * tty_name, char * ssh_connection, char * ld_preload, int retval),

                   PE_ARGS(pname, exe_path, argv,
                           tmp_stdin, tmp_stdout,
                           pid_tree, tty_name,
                           ssh_connection, ld_preload,
                           retval),

                   PE_printk("59" RS "%d" RS "%s" RS "%d" RS "%d" RS "%d" RS "%d" RS "%d"  RS "%s" RS "%s" RS "%u" RS "%u" RS "%u" RS "%s" RS "%s" RS "%s" RS "%s" RS "-1" RS "-1" RS "-1" RS "-1" RS "-1" RS "%s" RS "%s" RS "-1" RS "%s" RS "%s" RS "%d",
                           __get_ent(uid, __get_current_uid()),
                           __get_str(exe_path, exe_path),
                           __get_ent(pid, current->pid),
                           __get_ent(ppid, current->real_parent->tgid),
                           __get_ent(pgid, __get_pgid()),
                           __get_ent(tgid, current->tgid),
                           __get_ent(sid, __get_sid()),
                           __get_stl(comm, current->comm, TASK_COMM_LEN),
                           __get_str(nodename, current->nsproxy->uts_ns->name.nodename),
                           __get_ent(sessionid, __get_sessionid()),
                           __get_ent(pid_inum, __get_pid_ns_inum()),
                           __get_ent(root_pid_inum, ROOT_PID_NS_INUM),

                           __get_str(argv, argv),
                           __get_str(pname, pname),
                           __get_str(tmp_stdin, tmp_stdin),
                           __get_str(tmp_stdout, tmp_stdout),
                           __get_str(pid_tree, pid_tree),
                           __get_str(tty_name, tty_name),
                           __get_str(ssh_connection, ssh_connection),
                           __get_str(ld_preload, ld_preload),
                           __get_ent(retval, retval)
                   )
);

#if IS_ENABLED(CONFIG_IPV6)
PRINT_EVENT_DEFINE(execve6,

                   PE_PROTO(char * pname, char * exe_path, char * argv,
                            char * tmp_stdin, char * tmp_stdout,
                            struct in6_addr *dip, int dport, struct in6_addr *sip, int sport,
                           char * pid_tree, char * tty_name, pid_t socket_pid,
                           char * ssh_connection, char * ld_preload, int retval),

                   PE_ARGS(pname, exe_path, argv,
                           tmp_stdin, tmp_stdout,
                           dip, dport, sip, sport,
                           pid_tree, tty_name, socket_pid,
                           ssh_connection, ld_preload, retval),

                   PE_printk("59" RS "%d" RS "%s" RS "%d" RS "%d" RS "%d" RS "%d" RS "%d" RS "%s" RS "%s" RS "%u" RS "%u" RS "%u" RS "%s" RS "%s" RS "%s" RS "%s" RS "%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x" RS "%d" RS "%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x" RS "%d" RS "10" RS "%s" RS "%s" RS "%d" RS "%s" RS "%s" RS "%d",
                           __get_ent(uid, __get_current_uid()),
                           __get_str(exe_path, exe_path),
                           __get_ent(pid, current->pid),
                           __get_ent(ppid, current->real_parent->tgid),
                           __get_ent(pgid, __get_pgid()),
                           __get_ent(tgid, current->tgid),
                           __get_ent(sid, __get_sid()),
                           __get_stl(comm, current->comm, TASK_COMM_LEN),
                           __get_str(nodename, current->nsproxy->uts_ns->name.nodename),
                           __get_ent(sessionid, __get_sessionid()),
                           __get_ent(pid_inum, __get_pid_ns_inum()),
                           __get_ent(root_pid_inum, ROOT_PID_NS_INUM),

                           __get_str(argv, argv),
                           __get_str(pname, pname),
                           __get_str(tmp_stdin, tmp_stdin),
                           __get_str(tmp_stdout, tmp_stdout),
                           NIP6(__get_ent(*dip, *dip)),
                           __get_ent(dport, dport),
                           NIP6(__get_ent(*sip, *sip)),
                           __get_ent(sport, sport),
                           __get_str(pid_tree, pid_tree),
                           __get_str(tty_name, tty_name),
                           __get_ent(socket_pid, socket_pid),
                           __get_str(ssh_connection, ssh_connection),
                           __get_str(ld_preload, ld_preload),
                           __get_ent(retval, retval)
                   )
);
#endif

PRINT_EVENT_DEFINE(accept,

                   PE_PROTO(int dport, __be32 dip, char * exe_path,
                                  __be32 sip, int sport, int retval),

                   PE_ARGS(dport, dip, exe_path,
                                 sip, sport, retval),

                   PE_printk("43" RS "%d" RS "%s" RS "%d" RS "%d" RS "%d" RS "%d" RS "%d" RS "%s" RS "%s" RS "%u" RS "%u" RS "%u" RS "2" RS "%d.%d.%d.%d" RS "%d" RS "%d.%d.%d.%d" RS "%d" RS "%d",
                           __get_ent(uid, __get_current_uid()),
                           __get_str(exe_path, exe_path),
                           __get_ent(pid, current->pid),
                           __get_ent(ppid, current->real_parent->tgid),
                           __get_ent(pgid, __get_pgid()),
                           __get_ent(tgid, current->tgid),
                           __get_ent(sid, __get_sid()),
                           __get_stl(comm, current->comm, TASK_COMM_LEN),
                           __get_str(nodename, current->nsproxy->uts_ns->name.nodename),
                           __get_ent(sessionid, __get_sessionid()),
                           __get_ent(pid_inum, __get_pid_ns_inum()),
                           __get_ent(root_pid_inum, ROOT_PID_NS_INUM),

                           NIPQUAD(__get_ent(dip, dip)),
                           __get_ent(dport, dport),
                           NIPQUAD(__get_ent(sip, sip)),
                           __get_ent(sport, sport),
                           __get_ent(retval, retval)
                   )
);

#if IS_ENABLED(CONFIG_IPV6)
PRINT_EVENT_DEFINE(accept6,

                   PE_PROTO(int dport, struct in6_addr *dip, char * exe_path,
                           struct in6_addr *sip, int sport, int retval),

                   PE_ARGS(dport, dip, exe_path,
                           sip, sport, retval),

                   PE_printk("43" RS "%d" RS "%s" RS "%d" RS "%d" RS "%d" RS "%d" RS "%d" RS "%s" RS "%s" RS "%u" RS "%u" RS "%u" RS "10" RS "%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x" RS "%d" RS "%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x" RS "%d" RS "%d",
                           __get_ent(uid, __get_current_uid()),
                           __get_str(exe_path, exe_path),
                           __get_ent(pid, current->pid),
                           __get_ent(ppid, current->real_parent->tgid),
                           __get_ent(pgid, __get_pgid()),
                           __get_ent(tgid, current->tgid),
                           __get_ent(sid, __get_sid()),
                           __get_stl(comm, current->comm, TASK_COMM_LEN),
                           __get_str(nodename, current->nsproxy->uts_ns->name.nodename),
                           __get_ent(sessionid, __get_sessionid()),
                           __get_ent(pid_inum, __get_pid_ns_inum()),
                           __get_ent(root_pid_inum, ROOT_PID_NS_INUM),

                           NIP6(__get_ent(*dip, *dip)),
                           __get_ent(dport, dport),
                           NIP6(__get_ent(*sip, *sip)),
                           __get_ent(sport, sport),
                           __get_ent(retval, retval) )
);
#endif

PRINT_EVENT_DEFINE(connect4,

                   PE_PROTO(
                           int dport, __be32 dip, char * exe_path,
                           __be32 sip, int sport, int retval),

                   PE_ARGS(
                           dport, dip, exe_path,
                           sip, sport, retval),

                   PE_printk("42" RS "%d" RS "%s" RS "%d" RS "%d" RS "%d" RS "%d" RS "%d" RS "%s" RS "%s" RS "%u" RS "%u" RS "%u" RS "2" RS "%d.%d.%d.%d" RS "%d" RS "%d.%d.%d.%d" RS "%d" RS "%d",
                           __get_ent(uid, __get_current_uid()),
                           __get_str(exe_path, exe_path),
                           __get_ent(pid, current->pid),
                           __get_ent(ppid, current->real_parent->tgid),
                           __get_ent(pgid, __get_pgid()),
                           __get_ent(tgid, current->tgid),
                           __get_ent(sid, __get_sid()),
                           __get_stl(comm, current->comm, TASK_COMM_LEN),
                           __get_str(nodename, current->nsproxy->uts_ns->name.nodename),
                           __get_ent(sessionid, __get_sessionid()),
                           __get_ent(pid_inum, __get_pid_ns_inum()),
                           __get_ent(root_pid_inum, ROOT_PID_NS_INUM),

                           NIPQUAD(__get_ent(dip, dip)),
                           __get_ent(dport, dport),
                           NIPQUAD(__get_ent(sip, sip)),
                           __get_ent(sport, sport),
                           __get_ent(retval, retval)
                   )
);

#if IS_ENABLED(CONFIG_IPV6)
PRINT_EVENT_DEFINE(connect6,

                   PE_PROTO(
                           int dport, struct in6_addr *dip, char * exe_path,
                           struct in6_addr *sip, int sport, int retval),

                   PE_ARGS(
                           dport, dip, exe_path,
                           sip, sport, retval),

                   PE_printk("42" RS "%d" RS "%s" RS "%d" RS "%d" RS "%d" RS "%d" RS "%d" RS "%s" RS "%s" RS "%u" RS "%u" RS "%u" RS "10" RS "%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x" RS "%d" RS "%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x" RS "%d" RS "%d",
                                                      __get_ent(uid, __get_current_uid()),
                           __get_str(exe_path, exe_path),
                           __get_ent(pid, current->pid),
                           __get_ent(ppid, current->real_parent->tgid),
                           __get_ent(pgid, __get_pgid()),
                           __get_ent(tgid, current->tgid),
                           __get_ent(sid, __get_sid()),
                           __get_stl(comm, current->comm, TASK_COMM_LEN),
                           __get_str(nodename, current->nsproxy->uts_ns->name.nodename),
                           __get_ent(sessionid, __get_sessionid()),
                           __get_ent(pid_inum, __get_pid_ns_inum()),
                           __get_ent(root_pid_inum, ROOT_PID_NS_INUM),

                           NIP6(__get_ent(*dip, *dip)),
                           __get_ent(dport, dport),
                           NIP6(__get_ent(*sip, *sip)),
                           __get_ent(sport, sport),
                           __get_ent(retval, retval)
                   )
);
#endif

PRINT_EVENT_DEFINE(ptrace,

                   PE_PROTO(long request, long owner_pid, void *addr, char *data_res, char *exe_path, char *pid_tree),

                   PE_ARGS(request, owner_pid, addr, data_res, exe_path, pid_tree),

                   PE_printk("101" RS "%d" RS "%s" RS "%d" RS "%d" RS "%d" RS "%d" RS "%d" RS "%s" RS "%s" RS "%u" RS "%u" RS "%u" RS "%ld" RS "%ld" RS "%ld" RS "%s" RS "%s",
                           __get_ent(uid, __get_current_uid()),
                           __get_str(exe_path, exe_path),
                           __get_ent(pid, current->pid),
                           __get_ent(ppid, current->real_parent->tgid),
                           __get_ent(pgid, __get_pgid()),
                           __get_ent(tgid, current->tgid),
                           __get_ent(sid, __get_sid()),
                           __get_stl(comm, current->comm, TASK_COMM_LEN),
                           __get_str(nodename, current->nsproxy->uts_ns->name.nodename),
                           __get_ent(sessionid, __get_sessionid()),
                           __get_ent(pid_inum, __get_pid_ns_inum()),
                           __get_ent(root_pid_inum, ROOT_PID_NS_INUM),
                           __get_ent(request, request),
                           __get_ent(owner_pid, owner_pid),
                           __get_ent((long)addr, (long)addr),
                           __get_str(data_res, data_res),
                           __get_str(pid_tree, pid_tree)
                   )
);

PRINT_EVENT_DEFINE(bind,

                   PE_PROTO(char * exe_path,
                           struct in_addr *in_addr, int sport, int retval),

                   PE_ARGS(exe_path, in_addr, sport, retval),

                   PE_printk("49" RS "%d" RS "%s" RS "%d" RS "%d" RS "%d" RS "%d" RS "%d" RS "%s" RS "%s" RS "%u" RS "%u" RS "%u" RS "2" RS "%d.%d.%d.%d" RS "%d" RS "%d",
                           __get_ent(uid, __get_current_uid()),
                           __get_str(exe_path, exe_path),
                           __get_ent(pid, current->pid),
                           __get_ent(ppid, current->real_parent->tgid),
                           __get_ent(pgid, __get_pgid()),
                           __get_ent(tgid, current->tgid),
                           __get_ent(sid, __get_sid()),
                           __get_stl(comm, current->comm, TASK_COMM_LEN),
                           __get_str(nodename, current->nsproxy->uts_ns->name.nodename),
                           __get_ent(sessionid, __get_sessionid()),
                           __get_ent(pid_inum, __get_pid_ns_inum()),
                           __get_ent(root_pid_inum, ROOT_PID_NS_INUM),

                           NIPQUAD(__get_ent(in_addr, in_addr)),
                           __get_ent(sport, sport),
                           __get_ent(retval, retval)
                   )

);

#if IS_ENABLED(CONFIG_IPV6)
PRINT_EVENT_DEFINE(bind6,
                   PE_PROTO(char * exe_path,
                           struct in6_addr *in6_addr, int sport, int retval),

                   PE_ARGS(exe_path, in6_addr, sport, retval),

                   PE_printk("49" RS "%d" RS "%s" RS "%d" RS "%d" RS "%d" RS "%d" RS "%d" RS "%s" RS "%s" RS "%u" RS "%u" RS "%u" RS "2" RS "%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x" RS "%d" RS "%d",
                           __get_ent(uid, __get_current_uid()),
                           __get_str(exe_path, exe_path),
                           __get_ent(pid, current->pid),
                           __get_ent(ppid, current->real_parent->tgid),
                           __get_ent(pgid, __get_pgid()),
                           __get_ent(tgid, current->tgid),
                           __get_ent(sid, __get_sid()),
                           __get_stl(comm, current->comm, TASK_COMM_LEN),
                           __get_str(nodename, current->nsproxy->uts_ns->name.nodename),
                           __get_ent(sessionid, __get_sessionid()),
                           __get_ent(pid_inum, __get_pid_ns_inum()),
                           __get_ent(root_pid_inum, ROOT_PID_NS_INUM),

                           NIP6(__get_ent(*in6_addr, *in6_addr)),
                           __get_ent(sport, sport),
                           __get_ent(retval, retval)
                   )

);
#endif

PRINT_EVENT_DEFINE(update_cred,

                   PE_PROTO(char * exe_path, char *pid_tree, int old_uid, int retval),

                   PE_ARGS(exe_path, pid_tree, old_uid, retval),

                   PE_printk("604" RS "%d" RS "%s" RS "%d" RS "%d" RS "%d" RS "%d" RS "%d" RS "%s" RS "%s" RS "%u" RS "%u" RS "%u" RS "%s" RS "%d" RS "%d",
                           __get_ent(uid, __get_current_uid()),
                           __get_str(exe_path, exe_path),
                           __get_ent(pid, current->pid),
                           __get_ent(ppid, current->real_parent->tgid),
                           __get_ent(pgid, __get_pgid()),
                           __get_ent(tgid, current->tgid),
                           __get_ent(sid, __get_sid()),
                           __get_stl(comm, current->comm, TASK_COMM_LEN),
                           __get_str(nodename, current->nsproxy->uts_ns->name.nodename),
                           __get_ent(sessionid, __get_sessionid()),
                           __get_ent(pid_inum, __get_pid_ns_inum()),
                           __get_ent(root_pid_inum, ROOT_PID_NS_INUM),

                           __get_str(pid_tree, pid_tree),
                           __get_ent(old_uid, old_uid),
                           __get_ent(retval, retval)
                   )
);


PRINT_EVENT_DEFINE(do_init_module,

                   PE_PROTO(char * exe_path, char * mod_name, char * pid_tree, char * pwd),

                   PE_ARGS(exe_path, mod_name, pid_tree, pwd),

                   PE_printk("603" RS "%d" RS "%s" RS "%d" RS "%d" RS "%d" RS "%d" RS "%d" RS "%s" RS "%s" RS "%u" RS "%u" RS "%u" RS "%s" RS "%s" RS "%s",
                           __get_ent(uid, __get_current_uid()),
                           __get_str(exe_path, exe_path),
                           __get_ent(pid, current->pid),
                           __get_ent(ppid, current->real_parent->tgid),
                           __get_ent(pgid, __get_pgid()),
                           __get_ent(tgid, current->tgid),
                           __get_ent(sid, __get_sid()),
                           __get_stl(comm, current->comm, TASK_COMM_LEN),
                           __get_str(nodename, current->nsproxy->uts_ns->name.nodename),
                           __get_ent(sessionid, __get_sessionid()),
                           __get_ent(pid_inum, __get_pid_ns_inum()),
                           __get_ent(root_pid_inum, ROOT_PID_NS_INUM),

                           __get_str(mod_name, mod_name),
                           __get_str(pid_tree, pid_tree),
                           __get_str(pwd, pwd)
                   )
);

PRINT_EVENT_DEFINE(rename,

                   PE_PROTO(char * exe_path,char * oldname, char * newname, char * s_id),

                   PE_ARGS(exe_path, oldname, newname, s_id),

                   PE_printk("82" RS "%d" RS "%s" RS "%d" RS "%d" RS "%d" RS "%d" RS "%d" RS "%s" RS "%s" RS "%u" RS "%u" RS "%u" RS "%s" RS "%s" RS "%s",
                           __get_ent(uid, __get_current_uid()),
                           __get_str(exe_path, exe_path),
                           __get_ent(pid, current->pid),
                           __get_ent(ppid, current->real_parent->tgid),
                           __get_ent(pgid, __get_pgid()),
                           __get_ent(tgid, current->tgid),
                           __get_ent(sid, __get_sid()),
                           __get_stl(comm, current->comm, TASK_COMM_LEN),
                           __get_str(nodename, current->nsproxy->uts_ns->name.nodename),
                           __get_ent(sessionid, __get_sessionid()),
                           __get_ent(pid_inum, __get_pid_ns_inum()),
                           __get_ent(root_pid_inum, ROOT_PID_NS_INUM),

                           __get_str(oldname, oldname),
                           __get_str(newname, newname),
                           __get_str(s_id, s_id)
                        )
);

PRINT_EVENT_DEFINE(link,

                   PE_PROTO(char * exe_path, char * oldname, char * newname, char * s_id),

                   PE_ARGS(exe_path, oldname, newname, s_id),

                   PE_printk("86" RS "%d" RS "%s" RS "%d" RS "%d" RS "%d" RS "%d" RS "%d" RS "%s" RS "%s" RS "%u" RS "%u" RS "%u" RS "%s" RS "%s" RS "%s",
                           __get_ent(uid, __get_current_uid()),
                           __get_str(exe_path, exe_path),
                           __get_ent(pid, current->pid),
                           __get_ent(ppid, current->real_parent->tgid),
                           __get_ent(pgid, __get_pgid()),
                           __get_ent(tgid, current->tgid),
                           __get_ent(sid, __get_sid()),
                           __get_stl(comm, current->comm, TASK_COMM_LEN),
                           __get_str(nodename, current->nsproxy->uts_ns->name.nodename),
                           __get_ent(sessionid, __get_sessionid()),
                           __get_ent(pid_inum, __get_pid_ns_inum()),
                           __get_ent(root_pid_inum, ROOT_PID_NS_INUM),

                           __get_str(oldname, oldname),
                           __get_str(newname, newname),
                           __get_str(s_id, s_id)
                   )
);


PRINT_EVENT_DEFINE(mprotect,

                   PE_PROTO(char *exe_path, unsigned long prot, char *owner_file, int owner_pid, char *vm_file, char *pid_tree),

                   PE_ARGS(exe_path, prot, owner_file, owner_pid, vm_file, pid_tree),

                   PE_printk("10" RS "%d" RS "%s" RS "%d" RS "%d" RS "%d" RS "%d" RS "%d" RS "%s" RS "%s" RS "%u" RS "%u" RS "%u" RS "%lu" RS "%d" RS "%s" RS "%s" RS "%s",
                           __get_ent(uid, __get_current_uid()),
                           __get_str(exe_path, exe_path),
                           __get_ent(pid, current->pid),
                           __get_ent(ppid, current->real_parent->tgid),
                           __get_ent(pgid, __get_pgid()),
                           __get_ent(tgid, current->tgid),
                           __get_ent(sid, __get_sid()),
                           __get_stl(comm, current->comm, TASK_COMM_LEN),
                           __get_str(nodename, current->nsproxy->uts_ns->name.nodename),
                           __get_ent(sessionid, __get_sessionid()),
                           __get_ent(pid_inum, __get_pid_ns_inum()),
                           __get_ent(root_pid_inum, ROOT_PID_NS_INUM),
                           __get_ent(prot, prot),
                           __get_ent(owner_pid, owner_pid),
                           __get_str(owner_file, owner_file),
                           __get_str(vm_file, vm_file),
                           __get_str(pid_tree, pid_tree)
                   )
);


PRINT_EVENT_DEFINE(setsid,

                   PE_PROTO(char *exe_path),

                   PE_ARGS(exe_path),

                   PE_printk("112" RS "%d" RS "%s" RS "%d" RS "%d" RS "%d" RS "%d" RS "%d" RS "%s" RS "%s" RS "%u" RS "%u" RS "%u",
                           __get_ent(uid, __get_current_uid()),
                           __get_str(exe_path, exe_path),
                           __get_ent(pid, current->pid),
                           __get_ent(ppid, current->real_parent->tgid),
                           __get_ent(pgid, __get_pgid()),
                           __get_ent(tgid, current->tgid),
                           __get_ent(sid, __get_sid()),
                           __get_stl(comm, current->comm, TASK_COMM_LEN),
                           __get_str(nodename, current->nsproxy->uts_ns->name.nodename),
                           __get_ent(sessionid, __get_sessionid()),
                           __get_ent(pid_inum, __get_pid_ns_inum()),
                           __get_ent(root_pid_inum, ROOT_PID_NS_INUM)
                   )

);

PRINT_EVENT_DEFINE(prctl,

                   PE_PROTO(char *exe_path, int option, char *newname),

                   PE_ARGS(exe_path, option, newname),

                   PE_printk("157" RS "%d" RS "%s" RS "%d" RS "%d" RS "%d" RS "%d" RS "%d" RS "%s" RS "%s" RS "%u" RS "%u" RS "%u" RS "%d" RS "%s",
                           __get_ent(uid, __get_current_uid()),
                           __get_str(exe_path, exe_path),
                           __get_ent(pid, current->pid),
                           __get_ent(ppid, current->real_parent->tgid),
                           __get_ent(pgid, __get_pgid()),
                           __get_ent(tgid, current->tgid),
                           __get_ent(sid, __get_sid()),
                           __get_stl(comm, current->comm, TASK_COMM_LEN),
                           __get_str(nodename, current->nsproxy->uts_ns->name.nodename),
                           __get_ent(sessionid, __get_sessionid()),
                           __get_ent(pid_inum, __get_pid_ns_inum()),
                           __get_ent(root_pid_inum, ROOT_PID_NS_INUM),
                           __get_ent(option, option),
                           __get_str(newname, newname)
                   )
);

PRINT_EVENT_DEFINE(open,

                   PE_PROTO(char *exe_path, char *filename, int flags, umode_t mode),

                   PE_ARGS(exe_path, filename, flags, mode),

                   PE_printk("2" RS "%d" RS "%s" RS "%d" RS "%d" RS "%d" RS "%d" RS "%d" RS "%s" RS "%s" RS "%u" RS "%u" RS "%u" RS "%d" RS "%d" RS "%s",
                           __get_ent(uid, __get_current_uid()),
                           __get_str(exe_path, exe_path),
                           __get_ent(pid, current->pid),
                           __get_ent(ppid, current->real_parent->tgid),
                           __get_ent(pgid, __get_pgid()),
                           __get_ent(tgid, current->tgid),
                           __get_ent(sid, __get_sid()),
                           __get_stl(comm, current->comm, TASK_COMM_LEN),
                           __get_str(nodename, current->nsproxy->uts_ns->name.nodename),
                           __get_ent(sessionid, __get_sessionid()),
                           __get_ent(pid_inum, __get_pid_ns_inum()),
                           __get_ent(root_pid_inum, ROOT_PID_NS_INUM),

                           __get_ent(flags, flags),
                           __get_ent(mode, mode),
                           __get_str(filename, filename)
                   )
);

PRINT_EVENT_DEFINE(nanosleep,

                   PE_PROTO(char *exe_path, long long sec, long nsec),

                   PE_ARGS(exe_path, sec, nsec),

                   PE_printk("35" RS "%d" RS "%s" RS "%d" RS "%d" RS "%d" RS "%d" RS "%d" RS "%s" RS "%s" RS "%u" RS "%u" RS "%u" RS "%lld" RS "%ld",
                           __get_ent(uid, __get_current_uid()),
                           __get_str(exe_path, exe_path),
                           __get_ent(pid, current->pid),
                           __get_ent(ppid, current->real_parent->tgid),
                           __get_ent(pgid, __get_pgid()),
                           __get_ent(tgid, current->tgid),
                           __get_ent(sid, __get_sid()),
                           __get_stl(comm, current->comm, TASK_COMM_LEN),
                           __get_str(nodename, current->nsproxy->uts_ns->name.nodename),
                           __get_ent(sessionid, __get_sessionid()),
                           __get_ent(pid_inum, __get_pid_ns_inum()),
                           __get_ent(root_pid_inum, ROOT_PID_NS_INUM),

                           __get_ent(sec, sec),
                           __get_ent(nsec, nsec)
                   )
);

PRINT_EVENT_DEFINE(kill,

                   PE_PROTO(char *exe_path, pid_t target_pid, int sig),

                   PE_ARGS(exe_path, target_pid, sig),

                   PE_printk("62" RS "%d" RS "%s" RS "%d" RS "%d" RS "%d" RS "%d" RS "%d" RS "%s" RS "%s" RS "%u" RS "%u" RS "%u" RS "%d" RS "%d",
                           __get_ent(uid, __get_current_uid()),
                           __get_str(exe_path, exe_path),
                           __get_ent(pid, current->pid),
                           __get_ent(ppid, current->real_parent->tgid),
                           __get_ent(pgid, __get_pgid()),
                           __get_ent(tgid, current->tgid),
                           __get_ent(sid, __get_sid()),
                           __get_stl(comm, current->comm, TASK_COMM_LEN),
                           __get_str(nodename, current->nsproxy->uts_ns->name.nodename),
                           __get_ent(sessionid, __get_sessionid()),
                           __get_ent(pid_inum, __get_pid_ns_inum()),
                           __get_ent(root_pid_inum, ROOT_PID_NS_INUM),
                           __get_ent(target_pid, target_pid),
                           __get_ent(sig, sig)
                   )
);

PRINT_EVENT_DEFINE(tkill,

                   PE_PROTO(char *exe_path, pid_t target_pid, int sig),

                   PE_ARGS(exe_path, target_pid, sig),

                   PE_printk("200" RS "%d" RS "%s" RS "%d" RS "%d" RS "%d" RS "%d" RS "%d" RS "%s" RS "%s" RS "%u" RS "%u" RS "%u" RS "%d" RS "%d",
                           __get_ent(uid, __get_current_uid()),
                           __get_str(exe_path, exe_path),
                           __get_ent(pid, current->pid),
                           __get_ent(ppid, current->real_parent->tgid),
                           __get_ent(pgid, __get_pgid()),
                           __get_ent(tgid, current->tgid),
                           __get_ent(sid, __get_sid()),
                           __get_stl(comm, current->comm, TASK_COMM_LEN),
                           __get_str(nodename, current->nsproxy->uts_ns->name.nodename),
                           __get_ent(sessionid, __get_sessionid()),
                           __get_ent(pid_inum, __get_pid_ns_inum()),
                           __get_ent(root_pid_inum, ROOT_PID_NS_INUM),
                           __get_ent(target_pid, target_pid),
                           __get_ent(sig, sig)
                   )
);

PRINT_EVENT_DEFINE(exit,

                   PE_PROTO(char *exe_path),

                   PE_ARGS(exe_path),

                   PE_printk("60" RS "%d" RS "%s" RS "%d" RS "%d" RS "%d" RS "%d" RS "%d" RS "%s" RS "%s" RS "%u" RS "%u" RS "%u",
                           __get_ent(uid, __get_current_uid()),
                           __get_str(exe_path, exe_path),
                           __get_ent(pid, current->pid),
                           __get_ent(ppid, current->real_parent->tgid),
                           __get_ent(pgid, __get_pgid()),
                           __get_ent(tgid, current->tgid),
                           __get_ent(sid, __get_sid()),
                           __get_stl(comm, current->comm, TASK_COMM_LEN),
                           __get_str(nodename, current->nsproxy->uts_ns->name.nodename),
                           __get_ent(sessionid, __get_sessionid()),
                           __get_ent(pid_inum, __get_pid_ns_inum()),
                           __get_ent(root_pid_inum, ROOT_PID_NS_INUM)
                   )
);

PRINT_EVENT_DEFINE(exit_group,

                   PE_PROTO(char *exe_path),

                   PE_ARGS(exe_path),

                   PE_printk("231" RS "%d" RS "%s" RS "%d" RS "%d" RS "%d" RS "%d" RS "%d" RS "%s" RS "%s" RS "%u" RS "%u" RS "%u",
                           __get_ent(uid, __get_current_uid()),
                           __get_str(exe_path, exe_path),
                           __get_ent(pid, current->pid),
                           __get_ent(ppid, current->real_parent->tgid),
                           __get_ent(pgid, __get_pgid()),
                           __get_ent(tgid, current->tgid),
                           __get_ent(sid, __get_sid()),
                           __get_stl(comm, current->comm, TASK_COMM_LEN),
                           __get_str(nodename, current->nsproxy->uts_ns->name.nodename),
                           __get_ent(sessionid, __get_sessionid()),
                           __get_ent(pid_inum, __get_pid_ns_inum()),
                           __get_ent(root_pid_inum, ROOT_PID_NS_INUM)
                   )
);

PRINT_EVENT_DEFINE(security_path_rmdir,

                   PE_PROTO(char *exe_path, char *file),

                   PE_ARGS(exe_path, file),

                   PE_printk("606" RS "%d" RS "%s" RS "%d" RS "%d" RS "%d" RS "%d" RS "%d" RS "%s" RS "%s" RS "%u" RS "%u" RS "%u" RS "%s",
                           __get_ent(uid, __get_current_uid()),
                           __get_str(exe_path, exe_path),
                           __get_ent(pid, current->pid),
                           __get_ent(ppid, current->real_parent->tgid),
                           __get_ent(pgid, __get_pgid()),
                           __get_ent(tgid, current->tgid),
                           __get_ent(sid, __get_sid()),
                           __get_stl(comm, current->comm, TASK_COMM_LEN),
                           __get_str(nodename, current->nsproxy->uts_ns->name.nodename),
                           __get_ent(sessionid, __get_sessionid()),
                           __get_ent(pid_inum, __get_pid_ns_inum()),
                           __get_ent(root_pid_inum, ROOT_PID_NS_INUM),
                           __get_str(file, file)
                   )
);

PRINT_EVENT_DEFINE(security_path_unlink,

                   PE_PROTO(char *exe_path, char *file),

                   PE_ARGS(exe_path, file),

                   PE_printk("605" RS "%d" RS "%s" RS "%d" RS "%d" RS "%d" RS "%d" RS "%d" RS "%s" RS "%s" RS "%u" RS "%u" RS "%u" RS "%s",
                           __get_ent(uid, __get_current_uid()),
                           __get_str(exe_path, exe_path),
                           __get_ent(pid, current->pid),
                           __get_ent(ppid, current->real_parent->tgid),
                           __get_ent(pgid, __get_pgid()),
                           __get_ent(tgid, current->tgid),
                           __get_ent(sid, __get_sid()),
                           __get_stl(comm, current->comm, TASK_COMM_LEN),
                           __get_str(nodename, current->nsproxy->uts_ns->name.nodename),
                           __get_ent(sessionid, __get_sessionid()),
                           __get_ent(pid_inum, __get_pid_ns_inum()),
                           __get_ent(root_pid_inum, ROOT_PID_NS_INUM),
                           __get_str(file, file)
                   )
);

PRINT_EVENT_DEFINE(write,

                   PE_PROTO(char *exe_path, char *file, char *buf),

                   PE_ARGS(exe_path, file, buf),

                   PE_printk("1" RS "%d" RS "%s" RS "%d" RS "%d" RS "%d" RS "%d" RS "%d" RS "%s" RS "%s" RS "%u" RS "%u" RS "%u" RS "%s" RS "%s",
                           __get_ent(uid, __get_current_uid()),
                           __get_str(exe_path, exe_path),
                           __get_ent(pid, current->pid),
                           __get_ent(ppid, current->real_parent->tgid),
                           __get_ent(pgid, __get_pgid()),
                           __get_ent(tgid, current->tgid),
                           __get_ent(sid, __get_sid()),
                           __get_stl(comm, current->comm, TASK_COMM_LEN),
                           __get_str(nodename, current->nsproxy->uts_ns->name.nodename),
                           __get_ent(sessionid, __get_sessionid()),
                           __get_ent(pid_inum, __get_pid_ns_inum()),
                           __get_ent(root_pid_inum, ROOT_PID_NS_INUM),

                           __get_str(file, file),
                           __get_str(buf, buf)
                   )
);


PRINT_EVENT_DEFINE(file_permission_write,

                   PE_PROTO(char *exe_path, char *file, char *s_id),

                   PE_ARGS(exe_path, file, s_id),

                   PE_printk("608" RS "%d" RS "%s" RS "%d" RS "%d" RS "%d" RS "%d" RS "%d" RS "%s" RS "%s" RS "%u" RS "%u" RS "%u" RS "%s" RS "%s",
                           __get_ent(uid, __get_current_uid()),
                           __get_str(exe_path, exe_path),
                           __get_ent(pid, current->pid),
                           __get_ent(ppid, current->real_parent->tgid),
                           __get_ent(pgid, __get_pgid()),
                           __get_ent(tgid, current->tgid),
                           __get_ent(sid, __get_sid()),
                           __get_stl(comm, current->comm, TASK_COMM_LEN),
                           __get_str(nodename, current->nsproxy->uts_ns->name.nodename),
                           __get_ent(sessionid, __get_sessionid()),
                           __get_ent(pid_inum, __get_pid_ns_inum()),
                           __get_ent(root_pid_inum, ROOT_PID_NS_INUM),

                           __get_str(file, file),
                           __get_str(s_id, s_id)
                   )
);

PRINT_EVENT_DEFINE(file_permission_read,

                   PE_PROTO(char *exe_path, char *file, char *s_id),

                   PE_ARGS(exe_path, file, s_id),

                   PE_printk("609" RS "%d" RS "%s" RS "%d" RS "%d" RS "%d" RS "%d" RS "%d" RS "%s" RS "%s" RS "%u" RS "%u" RS "%u" RS "%s" RS "%s",
                           __get_ent(uid, __get_current_uid()),
                           __get_str(exe_path, exe_path),
                           __get_ent(pid, current->pid),
                           __get_ent(ppid, current->real_parent->tgid),
                           __get_ent(pgid, __get_pgid()),
                           __get_ent(tgid, current->tgid),
                           __get_ent(sid, __get_sid()),
                           __get_stl(comm, current->comm, TASK_COMM_LEN),
                           __get_str(nodename, current->nsproxy->uts_ns->name.nodename),
                           __get_ent(sessionid, __get_sessionid()),
                           __get_ent(pid_inum, __get_pid_ns_inum()),
                           __get_ent(root_pid_inum, ROOT_PID_NS_INUM),

                           __get_str(file, file),
                           __get_str(s_id, s_id)
                   )
);

PRINT_EVENT_DEFINE(mount,
                   PE_PROTO(char * exe_path, char * pid_tree, const char * dev_name, char * file_path, const char * fstype, unsigned long  flags),

                   PE_ARGS(exe_path, pid_tree, dev_name, file_path, fstype, flags),

                   PE_printk("165" RS "%d" RS "%s" RS "%d" RS "%d" RS "%d" RS "%d" RS "%d" RS "%s" RS "%s" RS "%u" RS "%u" RS "%u" RS "%s" RS "%s" RS "%s" RS "%s" RS "%lu",
                           __get_ent(uid, __get_current_uid()),
                           __get_str(exe_path, exe_path),
                           __get_ent(pid, current->pid),
                           __get_ent(ppid, current->real_parent->tgid),
                           __get_ent(pgid, __get_pgid()),
                           __get_ent(tgid, current->tgid),
                           __get_ent(sid, __get_sid()),
                           __get_stl(comm, current->comm, TASK_COMM_LEN),
                           __get_str(nodename, current->nsproxy->uts_ns->name.nodename),
                           __get_ent(sessionid, __get_sessionid()),
                           __get_ent(pid_inum, __get_pid_ns_inum()),
                           __get_ent(root_pid_inum, ROOT_PID_NS_INUM),

                           __get_str(pid_tree, pid_tree),
                           __get_str(dev_name, dev_name),
                           __get_str(file_path, file_path),
                           __get_str(fstype, fstype),
                           __get_ent(flags, flags)
                   )
);

PRINT_EVENT_DEFINE(udev,
                   PE_PROTO(char * exe_path, char * product, char * manufacturer, char * serial, int action),

                   PE_ARGS(exe_path, product, manufacturer, serial, action),

                   PE_printk("610" RS "%d" RS "%s" RS "%d" RS "%d" RS "%d" RS "%d" RS "%d" RS "%s" RS "%s" RS "%u" RS "%u" RS "%u" RS "%s" RS "%s" RS "%s" RS "%d",
                           __get_ent(uid, __get_current_uid()),
                           __get_str(exe_path, exe_path),
                           __get_ent(pid, current->pid),
                           __get_ent(ppid, current->real_parent->tgid),
                           __get_ent(pgid, __get_pgid()),
                           __get_ent(tgid, current->tgid),
                           __get_ent(sid, __get_sid()),
                           __get_stl(comm, current->comm, TASK_COMM_LEN),
                           __get_str(nodename, current->nsproxy->uts_ns->name.nodename),
                           __get_ent(sessionid, __get_sessionid()),
                           __get_ent(pid_inum, __get_pid_ns_inum()),
                           __get_ent(root_pid_inum, ROOT_PID_NS_INUM),

                           __get_str(product, product),
                           __get_str(manufacturer, manufacturer),
                           __get_str(serial, serial),
                           __get_ent(action, action)
                   )
);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 17, 0)
PRINT_EVENT_DEFINE(memfd_create,

                   PE_PROTO(char *exe_path, char *fdname, unsigned long flags),

                   PE_ARGS(exe_path, fdname, flags),

                   PE_printk("356" RS "%d" RS "%s" RS "%d" RS "%d" RS "%d" RS "%d" RS "%d" RS "%s" RS "%s" RS "%u" RS "%u" RS "%u" RS "%s" RS "%lu",
                           __get_ent(uid, __get_current_uid()),
                           __get_str(exe_path, exe_path),
                           __get_ent(pid, current->pid),
                           __get_ent(ppid, current->real_parent->tgid),
                           __get_ent(pgid, __get_pgid()),
                           __get_ent(tgid, current->tgid),
                           __get_ent(sid, __get_sid()),
                           __get_stl(comm, current->comm, TASK_COMM_LEN),
                           __get_str(nodename, current->nsproxy->uts_ns->name.nodename),
                           __get_ent(sessionid, __get_sessionid()),
                           __get_ent(pid_inum, __get_pid_ns_inum()),
                           __get_ent(root_pid_inum, ROOT_PID_NS_INUM),
                           __get_str(fdname, fdname),
                           __get_ent(flags, flags)
                   )
);
#endif

#endif /* _KPROBE_PRINT_H */

/* SPDX-License-Identifier: GPL-2.0 */
#undef PRINT_EVENT_SYSTEM
#define PRINT_EVENT_SYSTEM kprobe_print

#if !defined(_KPROBE_PRINT_H) || defined(TRACE_HEADER_MULTI_READ)
#define _KPROBE_PRINT_H

#include "trace.h"
#include "struct_wrap.h"

#define RS "\x1e"

PRINT_EVENT_DEFINE(security_inode_create,

                   PE_PROTO(char * exe_path, char * pathstr),

                   PE_ARGS(exe_path, pathstr),

                   PE_STRUCT__entry(
                           __field(int, uid)
                           __string(exe_path, exe_path)
                           __string(pathstr, pathstr)
                           __field(int, pid)
                           __field(int, ppid)
                           __field(int, pgid)
                           __field(int, tgid)
                           __field(int, sid)
                           __array(char, comm, TASK_COMM_LEN)
                           __string(nodename, current->nsproxy->uts_ns->name.nodename)
                           __field(unsigned int, sessionid)
                   ),

                   PE_fast_assign(
                           __entry->uid = get_current_uid();
                           __assign_str(exe_path, exe_path);
                           __assign_str(pathstr, pathstr);
                           __entry->pid = current->pid;
                           __entry->ppid = current->real_parent->pid;
                           __entry->pgid = __get_pgid();
                           __entry->sid = __get_sid();
                           __entry->tgid = current->tgid;
                           memcpy(__entry->comm, current->comm, TASK_COMM_LEN);
                           __assign_str(nodename, current->nsproxy->uts_ns->name.nodename);
                           __entry->sessionid = __get_sessionid();
                   ),

                   PE_printk(
                           "%d" RS "602" RS "%s" RS "%d" RS "%d" RS "%d" RS "%d" RS "%d" RS "%s" RS "%s" RS "%u" RS "%s",
                           __entry->uid, __get_str(exe_path), __entry->pid,
                           __entry->ppid, __entry->pgid, __entry->tgid, __entry->sid,
                           __entry->comm, __get_str(nodename), __entry->sessionid, __get_str(pathstr))
);

PRINT_EVENT_DEFINE(dns,

                   PE_PROTO(int dport,
                           __be32 dip, char * exe_path,
                           __be32 sip, int sport, int qr, int opcode, int rcode,
                           char * query),

                   PE_ARGS(dport, dip, exe_path,
                           sip, sport, qr, opcode, rcode,
                           query),

                   PE_STRUCT__entry(
                           __field(int, uid)
                           __field(int, dport)
                           __field(__be32, dip)
                           __string(exe_path, exe_path)
                           __field(int, pid)
                           __field(int, ppid)
                           __field(int, pgid)
                           __field(int, tgid)
                           __field(int, sid)
                           __array(char, comm, TASK_COMM_LEN)
                           __string(nodename, current->nsproxy->uts_ns->name.nodename)
                           __field(__be32, sip)
                           __field(int, sport)
                           __field(int, qr)
                           __field(int, opcode)
                           __field(int, rcode)
                           __string(query, query)
                           __field(unsigned int, sessionid)
                   ),

                   PE_fast_assign(
                           __entry->uid = get_current_uid();
                           __entry->dport = dport;
                           __entry->dip = dip;
                           __assign_str(exe_path, exe_path);
                           __entry->pid = current->pid;
                           __entry->ppid = current->real_parent->pid;
                           __entry->pgid = __get_pgid();
                           __entry->sid = __get_sid();
                           __entry->tgid = current->tgid;
                           memcpy(__entry->comm, current->comm, TASK_COMM_LEN);
                           __assign_str(nodename, current->nsproxy->uts_ns->name.nodename);
                           __entry->sip = sip;
                           __entry->sport = sport;
                           __entry->qr = qr;
                           __entry->opcode = opcode;
                           __entry->rcode = rcode;
                           __assign_str(query, query);
                           __entry->sessionid = __get_sessionid();
                   ),

                   PE_printk(
                           "%d" RS "601" RS "%s" RS "%d" RS "%d" RS "%d" RS "%d" RS "%d" RS "%s" RS "%s" RS "%u" RS "%s" RS "2" RS "%d.%d.%d.%d" RS "%d" RS "%d.%d.%d.%d" RS "%d" RS "%d" RS "%d" RS "%d",
                           __entry->uid, __get_str(exe_path),
                           __entry->pid, __entry->ppid, __entry->pgid, __entry->tgid, __entry->sid,
                           __entry->comm, __get_str(nodename), __entry->sessionid, __get_str(query),
                           NIPQUAD(__entry->dip), __entry->dport, NIPQUAD(__entry->sip),
                           __entry->sport, __entry->qr, __entry->opcode, __entry->rcode)
);

#if IS_ENABLED(CONFIG_IPV6)
PRINT_EVENT_DEFINE(dns6,

                   PE_PROTO(int dport,
                           struct in6_addr *dip, char * exe_path,
                           struct in6_addr *sip, int sport, int qr, int opcode, int rcode,
                           char * query),

                   PE_ARGS(dport, dip, exe_path,
                           sip, sport, qr, opcode, rcode,
                           query),

                   PE_STRUCT__entry(
                           __field(int, uid)
                           __field(int, dport)
                           __field(struct in6_addr, dip)
                           __string(exe_path, exe_path)
                           __field(int, pid)
                           __field(int, ppid)
                           __field(int, pgid)
                           __field(int, tgid)
                           __field(int, sid)
                           __array(char, comm, TASK_COMM_LEN)
                           __string(nodename, current->nsproxy->uts_ns->name.nodename)
                           __field(struct in6_addr, sip)
                           __field(int, sport)
                           __field(int, qr)
                           __field(int, opcode)
                           __field(int, rcode)
                           __string(query, query)
                           __field(unsigned int, sessionid)
                   ),

                   PE_fast_assign(
                           __entry->uid = get_current_uid();
                           __entry->dport = dport;
                           memcpy(&__entry->dip, dip, sizeof(*dip));
                           __assign_str(exe_path, exe_path);
                           __entry->pid = current->pid;
                           __entry->ppid = current->real_parent->pid;
                           __entry->pgid = __get_pgid();
                           __entry->sid = __get_sid();
                           __entry->tgid = current->tgid;
                           memcpy(__entry->comm, current->comm, TASK_COMM_LEN);
                           __assign_str(nodename, current->nsproxy->uts_ns->name.nodename);
                           memcpy(&__entry->sip, sip, sizeof(*sip));
                           __entry->sport = sport;
                           __entry->qr = qr;
                           __entry->opcode = opcode;
                           __entry->rcode = rcode;
                           __assign_str(query, query);
                           __entry->sessionid = __get_sessionid();
                   ),

                   PE_printk(
                           "%d" RS "601" RS "%s" RS "%d" RS "%d" RS "%d" RS "%d" RS "%d" RS "%s" RS "%s" RS "%u" RS "%s" RS "10" RS "%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x" RS "%d" RS "%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x" RS "%d" RS "%d" RS "%d" RS "%d",
                           __entry->uid, __get_str(exe_path), __entry->pid, __entry->ppid,
                           __entry->pgid, __entry->tgid, __entry->sid,
                           __entry->comm, __get_str(nodename), __entry->sessionid,
                           __get_str(query), NIP6(__entry->dip), __entry->dport,
                           NIP6(__entry->sip), __entry->sport, __entry->qr, __entry->opcode,__entry->rcode)
);
#endif

PRINT_EVENT_DEFINE(execve,

                   PE_PROTO(char * pname, char * exe_path, char * pgid_exe_path, char * argv,
                            char * tmp_stdin, char * tmp_stdout,
                            __be32 dip, int dport, __be32 sip, int sport,
                           char * pid_tree, char * tty_name, pid_t socket_pid, char * socket_pname,
                           char * ssh_connection, char * ld_preload, int retval),

                   PE_ARGS(pname, exe_path, pgid_exe_path, argv,
                           tmp_stdin, tmp_stdout,
                           dip, dport, sip, sport,
                           pid_tree, tty_name, socket_pid, socket_pname,
                           ssh_connection, ld_preload, retval),

                   PE_STRUCT__entry(
                           __field(int, uid)
                           __string(pname, pname)
                           __string(exe_path, exe_path)
                           __string(pgid_exe_path, pgid_exe_path)
                           __string(argv, argv)
                           __field(int, pid)
                           __field(int, ppid)
                           __field(int, pgid)
                           __field(int, tgid)
                           __field(int, sid)
                           __array(char, comm, TASK_COMM_LEN)
                           __string(nodename, current->nsproxy->uts_ns->name.nodename)
                           __string(tmp_stdin, tmp_stdin)
                           __string(tmp_stdout, tmp_stdout)
                           __field(unsigned int, sessionid)
                           __field(__be32, dip)
                           __field(int, dport)
                           __field(__be32, sip)
                           __field(int, sport)
                           __string(pid_tree, pid_tree)
                           __string(tty_name, tty_name)
                           __field(pid_t, socket_pid)
                           __string(socket_pname, socket_pname)
                           __string(ssh_connection, ssh_connection)
                           __string(ld_preload, ld_preload)
                           __field(int, retval)
                   ),

                   PE_fast_assign(
                           __entry->uid = get_current_uid();
                           __assign_str(pname, pname);
                           __assign_str(exe_path, exe_path);
                           __assign_str(pgid_exe_path, pgid_exe_path);
                           __assign_str(argv, argv);
                           __entry->pid = current->pid;
                           __entry->ppid = current->real_parent->pid;
                           __entry->pgid = __get_pgid();
                           __entry->sid = __get_sid();
                           __entry->tgid = current->tgid;
                           memcpy(__entry->comm, current->comm, TASK_COMM_LEN);
                           __assign_str(nodename, current->nsproxy->uts_ns->name.nodename);
                           __assign_str(tmp_stdin, tmp_stdin);
                           __assign_str(tmp_stdout, tmp_stdout);
                           __entry->sessionid = __get_sessionid();
                           __entry->dip = dip;
                           __entry->dport = dport;
                           __entry->sip = sip;
                           __entry->sport = sport;
                           __assign_str(pid_tree, pid_tree);
                           __assign_str(tty_name, tty_name);
                           __entry->socket_pid = socket_pid;
                           __assign_str(socket_pname, socket_pname);
                           __assign_str(ssh_connection, ssh_connection);
                           __assign_str(ld_preload, ld_preload);
                           __entry->retval = retval;
                   ),

                   PE_printk(
                           "%d" RS "59" RS "%s" RS "%d" RS "%d" RS "%d" RS "%d" RS "%d" RS "%s" RS "%s" RS "%u" RS "%s" RS "%s" RS "%s" RS "%s" RS "%s" RS "%s" RS "%d.%d.%d.%d" RS "%d" RS "%d.%d.%d.%d" RS "%d" RS "2" RS "%s" RS "%s" RS "%d" RS "%s" RS "%s" RS "%d",
                           __entry->uid, __get_str(exe_path), __entry->pid,
                           __entry->ppid, __entry->pgid, __entry->tgid, __entry->sid, __entry->comm,
                           __get_str(nodename), __entry->sessionid, __get_str(socket_pname),__get_str(argv),
                           __get_str(pname),  __get_str(pgid_exe_path), __get_str(tmp_stdin), __get_str(tmp_stdout),
                           NIPQUAD(__entry->dip), __entry->dport, NIPQUAD(__entry->sip),
                           __entry->sport, __get_str(pid_tree), __get_str(tty_name), __entry->socket_pid,
                           __get_str(ssh_connection), __get_str(ld_preload), __entry->retval)
);

PRINT_EVENT_DEFINE(execve_nosocket,

                   PE_PROTO(char * pname, char * exe_path, char * pgid_exe_path, char * argv,
                            char * tmp_stdin, char * tmp_stdout, char * pid_tree,
                            char * tty_name, char * ssh_connection, char * ld_preload, int retval),

                   PE_ARGS(pname, exe_path, pgid_exe_path, argv,
                           tmp_stdin, tmp_stdout,
                           pid_tree, tty_name,
                           ssh_connection, ld_preload, retval),

                   PE_STRUCT__entry(
                           __field(int, uid)
                           __string(pname, pname)
                           __string(exe_path, exe_path)
                           __string(pgid_exe_path, pgid_exe_path)
                           __string(argv, argv)
                           __field(int, pid)
                           __field(int, ppid)
                           __field(int, pgid)
                           __field(int, tgid)
                           __field(int, sid)
                           __array(char, comm, TASK_COMM_LEN)
                           __string(nodename, current->nsproxy->uts_ns->name.nodename)
                           __string(tmp_stdin, tmp_stdin)
                           __string(tmp_stdout, tmp_stdout)
                           __field(unsigned int, sessionid)
                           __string(pid_tree, pid_tree)
                           __string(tty_name, tty_name)
                           __string(ssh_connection, ssh_connection)
                           __string(ld_preload, ld_preload)
                           __field(int, retval)
                   ),

                   PE_fast_assign(
                           __entry->uid = get_current_uid();
                           __assign_str(pname, pname);
                           __assign_str(exe_path, exe_path);
                           __assign_str(pgid_exe_path, pgid_exe_path);
                           __assign_str(argv, argv);
                           __entry->pid = current->pid;
                           __entry->ppid = current->real_parent->pid;
                           __entry->pgid = __get_pgid();
                           __entry->sid = __get_sid();
                           __entry->tgid = current->tgid;
                           memcpy(__entry->comm, current->comm, TASK_COMM_LEN);
                           __assign_str(nodename, current->nsproxy->uts_ns->name.nodename);
                           __assign_str(tmp_stdin, tmp_stdin);
                           __assign_str(tmp_stdout, tmp_stdout);
                           __entry->sessionid = __get_sessionid();
                           __assign_str(pid_tree, pid_tree);
                           __assign_str(tty_name, tty_name);
                           __assign_str(ssh_connection, ssh_connection);
                           __assign_str(ld_preload, ld_preload);
                           __entry->retval = retval;
                   ),

                   PE_printk(
                           "%d" RS "59" RS "%s" RS "%d" RS "%d" RS "%d" RS "%d" RS "%d"  RS "%s" RS "%s" RS "%u" RS "-1" RS "%s" RS "%s" RS "%s" RS "%s" RS "%s" RS "-1" RS "-1" RS "-1" RS "-1" RS "-1" RS "%s" RS "%s" RS "-1" RS "%s" RS "%s" RS "%d",
                           __entry->uid, __get_str(exe_path), __entry->pid,
                           __entry->ppid, __entry->pgid, __entry->tgid, __entry->sid, __entry->comm,
                           __get_str(nodename), __entry->sessionid, __get_str(argv), __get_str(pname),
                           __get_str(pgid_exe_path), __get_str(tmp_stdin), __get_str(tmp_stdout),
                           __get_str(pid_tree), __get_str(tty_name), __get_str(ssh_connection),
                           __get_str(ld_preload), __entry->retval)
);

#if IS_ENABLED(CONFIG_IPV6)
PRINT_EVENT_DEFINE(execve6,

                   PE_PROTO(char * pname, char * exe_path, char * pgid_exe_path, char * argv,
                            char * tmp_stdin, char * tmp_stdout,
                            struct in6_addr *dip, int dport, struct in6_addr *sip, int sport,
                           char * pid_tree, char * tty_name, pid_t socket_pid, char * socket_pname,
                           char * ssh_connection, char * ld_preload, int retval),

                   PE_ARGS(pname, exe_path, pgid_exe_path, argv,
                           tmp_stdin, tmp_stdout,
                           dip, dport, sip, sport,
                           pid_tree, tty_name, socket_pid, socket_pname,
                           ssh_connection, ld_preload, retval),

                   PE_STRUCT__entry(
                           __field(int, uid)
                           __string(pname, pname)
                           __string(exe_path, exe_path)
                           __string(pgid_exe_path, pgid_exe_path)
                           __string(argv, argv)
                           __field(int, pid)
                           __field(int, ppid)
                           __field(int, pgid)
                           __field(int, tgid)
                           __field(int, sid)
                           __array(char, comm, TASK_COMM_LEN)
                           __string(nodename, current->nsproxy->uts_ns->name.nodename)
                           __string(tmp_stdin, tmp_stdin)
                           __string(tmp_stdout, tmp_stdout)
                           __field(unsigned int, sessionid)
                           __field(struct in6_addr, dip)
                           __field(int, dport)
                           __field(struct in6_addr, sip)
                           __field(int, sport)
                           __string(pid_tree, pid_tree)
                           __string(tty_name, tty_name)
                           __field(pid_t, socket_pid)
                           __string(socket_pname, socket_pname)
                           __string(ssh_connection, ssh_connection)
                           __string(ld_preload, ld_preload)
                           __field(int, retval)
                   ),

                   PE_fast_assign(
                           __entry->uid = get_current_uid();
                           __assign_str(pname, pname);
                           __assign_str(exe_path, exe_path);
                           __assign_str(pgid_exe_path, pgid_exe_path);
                           __assign_str(argv, argv);
                           __entry->pid = current->pid;
                           __entry->ppid = current->real_parent->pid;
                           __entry->pgid = __get_pgid();
                           __entry->sid = __get_sid();
                           __entry->tgid = current->tgid;
                           memcpy(__entry->comm, current->comm, TASK_COMM_LEN);
                           __assign_str(nodename, current->nsproxy->uts_ns->name.nodename);
                           __assign_str(tmp_stdin, tmp_stdin);
                           __assign_str(tmp_stdout, tmp_stdout);
                           __entry->sessionid = __get_sessionid();
                           memcpy(&__entry->dip, dip, sizeof(*dip));
                           __entry->dport = dport;
                           memcpy(&__entry->sip, sip, sizeof(*sip));
                           __entry->sport = sport;
                           __assign_str(pid_tree, pid_tree);
                           __assign_str(tty_name, tty_name);
                           __entry->socket_pid = socket_pid;
                           __assign_str(socket_pname, socket_pname);
                           __assign_str(ssh_connection, ssh_connection);
                           __assign_str(ld_preload, ld_preload);
                           __entry->retval = retval;
                   ),

                   PE_printk(
                           "%d" RS "59" RS "%s" RS "%d" RS "%d" RS "%d" RS "%d" RS "%d" RS "%s" RS "%s" RS "%u" RS "%s" RS "%s" RS "%s" RS "%s" RS "%s" RS "%s" RS "%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x" RS "%d" RS "%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x" RS "%d" RS "10" RS "%s" RS "%s" RS "%d" RS "%s" RS "%s" RS "%d",
                           __entry->uid, __get_str(exe_path), __entry->pid,
                           __entry->ppid, __entry->pgid, __entry->tgid, __entry->sid, __entry->comm,
                           __get_str(nodename), __entry->sessionid, __get_str(socket_pname), __get_str(argv),
                           __get_str(pname), __get_str(pgid_exe_path), __get_str(tmp_stdin), __get_str(tmp_stdout),
                           NIP6(__entry->dip), __entry->dport, NIP6(__entry->sip),
                           __entry->sport, __get_str(pid_tree), __get_str(tty_name), __entry->socket_pid,
                           __get_str(ssh_connection), __get_str(ld_preload), __entry->retval)
);
#endif

PRINT_EVENT_DEFINE(connect4,

                   PE_PROTO(int data_type,
                           int dport, __be32 dip, char * exe_path,
                           __be32 sip, int sport, int retval),

                   PE_ARGS(data_type,
                           dport, dip, exe_path,
                           sip, sport, retval),

                   PE_STRUCT__entry(
                           __field(int, uid)
                           __field(int, data_type)
                           __field(int, dport)
                           __field(__be32, dip)
                           __string(exe_path, exe_path)
                           __field(int, pid)
                           __field(int, ppid)
                           __field(int, pgid)
                           __field(int, tgid)
                           __field(int, sid)
                           __array(char, comm, TASK_COMM_LEN)
                           __string(nodename, current->nsproxy->uts_ns->name.nodename)
                           __field(__be32, sip)
                           __field(int, sport)
                           __field(int, retval)
                           __field(unsigned int, sessionid)
                   ),

                   PE_fast_assign(
                           __entry->uid = get_current_uid();
                           __entry->data_type = data_type;
                           __entry->dport = dport;
                           __entry->dip = dip;
                           __assign_str(exe_path, exe_path);
                           __entry->pid = current->pid;
                           __entry->ppid = current->real_parent->pid;
                           __entry->pgid = __get_pgid();
                           __entry->sid = __get_sid();
                           __entry->tgid = current->tgid;
                           memcpy(__entry->comm, current->comm, TASK_COMM_LEN);
                           __assign_str(nodename, current->nsproxy->uts_ns->name.nodename);
                           __entry->sip = sip;
                           __entry->sport = sport;
                           __entry->retval = retval;
                           __entry->sessionid = __get_sessionid();
                   ),

                   PE_printk(
                           "%d" RS "42" RS "%s" RS "%d" RS "%d" RS "%d" RS "%d" RS "%d" RS "%s" RS "%s" RS "%u" RS "%d" RS "2" RS "%d.%d.%d.%d" RS "%d" RS "%d.%d.%d.%d" RS "%d" RS "%d",
                           __entry->uid, __get_str(exe_path), __entry->pid, __entry->ppid,
                           __entry->pgid, __entry->tgid, __entry->sid, __entry->comm, __get_str(nodename),
                           __entry->sessionid, __entry->data_type, NIPQUAD(__entry->dip),
                           __entry->dport, NIPQUAD(__entry->sip), __entry->sport, __entry->retval)
);

#if IS_ENABLED(CONFIG_IPV6)
PRINT_EVENT_DEFINE(connect6,

                   PE_PROTO(int data_type,
                           int dport, struct in6_addr *dip, char * exe_path,
                           struct in6_addr *sip, int sport, int retval),

                   PE_ARGS(data_type,
                           dport, dip, exe_path,
                           sip, sport, retval),

                   PE_STRUCT__entry(
                           __field(int, uid)
                           __field(int, data_type)
                           __field(int, dport)
                           __field(struct in6_addr, dip)
                           __string(exe_path, exe_path)
                           __field(int, pid)
                           __field(int, ppid)
                           __field(int, pgid)
                           __field(int, tgid)
                           __field(int, sid)
                           __array(char, comm, TASK_COMM_LEN)
                           __string(nodename, current->nsproxy->uts_ns->name.nodename)
                           __field(struct in6_addr, sip)
                           __field(int, sport)
                           __field(int, retval)
                           __field(unsigned int, sessionid)
                   ),

                   PE_fast_assign(
                           __entry->uid = get_current_uid();
                           __entry->data_type = data_type;
                           __entry->dport = dport;
                           memcpy(&__entry->dip, dip, sizeof(*dip));
                           __assign_str(exe_path, exe_path);
                           __entry->pid = current->pid;
                           __entry->ppid = current->real_parent->pid;
                           __entry->pgid = __get_pgid();
                           __entry->sid = __get_sid();
                           __entry->tgid = current->tgid;
                           memcpy(__entry->comm, current->comm, TASK_COMM_LEN);
                           __assign_str(nodename, current->nsproxy->uts_ns->name.nodename);
                           memcpy(&__entry->sip, sip, sizeof(*sip));
                           __entry->sport = sport;
                           __entry->retval = retval;
                           __entry->sessionid = __get_sessionid();
                   ),

                   PE_printk(
                           "%d" RS "42" RS "%s" RS "%d" RS "%d" RS "%d" RS "%d" RS "%d" RS "%s" RS "%s" RS "%u" RS "%d" RS "10" RS "%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x" RS "%d" RS "%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x" RS "%d" RS "%d",
                           __entry->uid, __get_str(exe_path), __entry->pid, __entry->ppid, __entry->pgid,
                           __entry->tgid, __entry->sid,__entry->comm, __get_str(nodename),__entry->sessionid,
                           __entry->data_type, NIP6(__entry->dip), __entry->dport, NIP6(__entry->sip),
                           __entry->sport, __entry->retval)
);
#endif

PRINT_EVENT_DEFINE(ptrace,

                   PE_PROTO(long request,
                           long owner_pid, void *addr, char *data_res, char *exe_path, char *pid_tree),

                   PE_ARGS(request,
                           owner_pid, addr, data_res, exe_path, pid_tree),

                   PE_STRUCT__entry(
                           __field(int, uid)
                           __field(long, request)
                           __field(long, owner_pid)
                           __field(long, addr)
                           __string(data_res, data_res)
                           __string(exe_path, exe_path)
                           __string(pid_tree, pid_tree)
                           __field(int, pid)
                           __field(int, ppid)
                           __field(int, pgid)
                           __field(int, tgid)
                           __field(int, sid)
                           __array(char, comm, TASK_COMM_LEN)
                           __string(nodename, current->nsproxy->uts_ns->name.nodename)
                           __field(unsigned int, sessionid)
                   ),

                   PE_fast_assign(
                           __entry->uid = get_current_uid();
                           __entry->request = request;
                           __entry->owner_pid = owner_pid;
                           __entry->addr = (long) addr;
                           __assign_str(data_res, data_res);
                           __assign_str(exe_path, exe_path);
                           __assign_str(pid_tree, pid_tree);
                           __entry->pid = current->pid;
                           __entry->ppid = current->real_parent->tgid;
                           __entry->pgid = __get_pgid();
                           __entry->sid = __get_sid();
                           __entry->tgid = current->tgid;
                           memcpy(__entry->comm, current->comm, TASK_COMM_LEN);
                           __assign_str(nodename, current->nsproxy->uts_ns->name.nodename);
                           __entry->sessionid = __get_sessionid();
                   ),

                   PE_printk(
                           "%d" RS "101" RS "%s" RS "%d" RS "%d" RS "%d" RS "%d" RS "%d" RS "%s" RS "%s" RS "%u" RS "%ld" RS "%ld" RS "%ld" RS "%s" RS "%s",
                           __entry->uid, __get_str(exe_path),
                           __entry->pid, __entry->ppid, __entry->pgid, __entry->tgid, __entry->sid,
                           __entry->comm, __get_str(nodename), __entry->sessionid, __entry->request, __entry->owner_pid,
                           __entry->addr, __get_str(data_res),__get_str(pid_tree))
);

PRINT_EVENT_DEFINE(bind,
                   PE_PROTO(char * exe_path,
                           struct in_addr *in_addr, int sport, int retval),

                   PE_ARGS(exe_path, in_addr, sport, retval),

                   PE_STRUCT__entry(
                           __field(int, uid)
                           __string(exe_path, exe_path)
                           __field(int, pid)
                           __field(int, ppid)
                           __field(int, pgid)
                           __field(int, tgid)
                           __field(int, sid)
                           __array(char, comm, TASK_COMM_LEN)
                           __string(nodename, current->nsproxy->uts_ns->name.nodename)
                           __field(struct in_addr, in_addr)
                           __field(int, sport)
                           __field(int, retval)
                           __field(unsigned int, sessionid)
                   ),
                   PE_fast_assign(
                           __entry->uid = get_current_uid();
                           __assign_str(exe_path, exe_path);
                           __entry->pid = current->pid;
                           __entry->ppid = current->real_parent->pid;
                           __entry->pgid = __get_pgid();
                           __entry->sid = __get_sid();
                           __entry->tgid = current->tgid;
                           memcpy(__entry->comm, current->comm, TASK_COMM_LEN);
                           __assign_str(nodename, current->nsproxy->uts_ns->name.nodename);
                           memcpy(&__entry->in_addr, in_addr, sizeof(*in_addr));
                           __entry->sport = sport;
                           __entry->retval = retval;
                           __entry->sessionid = __get_sessionid();
                   ),
                   PE_printk(
                           "%d" RS "49" RS "%s" RS "%d" RS "%d" RS "%d" RS "%d" RS "%d" RS "%s" RS "%s" RS "%u" RS "2" RS "%d.%d.%d.%d" RS "%d" RS "%d",
                           __entry->uid, __get_str(exe_path), __entry->pid, __entry->ppid,
                           __entry->pgid, __entry->tgid, __entry->sid,
                           __entry->comm, __get_str(nodename),__entry->sessionid,
                           NIPQUAD(__entry->in_addr), __entry->sport,__entry->retval)

);

#if IS_ENABLED(CONFIG_IPV6)
PRINT_EVENT_DEFINE(bind6,
                   PE_PROTO(char * exe_path,
                           struct in6_addr *in6_addr, int sport, int retval),

                   PE_ARGS(exe_path, in6_addr, sport, retval),

                   PE_STRUCT__entry(
                           __field(int, uid)
                           __string(exe_path, exe_path)
                           __field(int, pid)
                           __field(int, ppid)
                           __field(int, pgid)
                           __field(int, tgid)
                           __field(int, sid)
                           __array(char, comm, TASK_COMM_LEN)
                           __string(nodename, current->nsproxy->uts_ns->name.nodename)
                           __field(struct in6_addr, in6_addr)
                           __field(int, sport)
                           __field(int, retval)
                           __field(unsigned int, sessionid)
                   ),
                   PE_fast_assign(
                           __entry->uid = get_current_uid();
                           __assign_str(exe_path, exe_path);
                           __entry->pid = current->pid;
                           __entry->ppid = current->real_parent->pid;
                           __entry->pgid = __get_pgid();
                           __entry->sid = __get_sid();
                           __entry->tgid = current->tgid;
                           memcpy(__entry->comm, current->comm, TASK_COMM_LEN);
                           __assign_str(nodename, current->nsproxy->uts_ns->name.nodename);
                           memcpy(&__entry->in6_addr, in6_addr, sizeof(*in6_addr));
                           __entry->sport = sport;
                           __entry->retval = retval;
                           __entry->sessionid = __get_sessionid();
                   ),
                   PE_printk(
                           "%d" RS "49" RS "%s" RS "%d" RS "%d" RS "%d" RS "%d" RS "%d" RS "%s" RS "%s" RS "%u" RS "2" RS "%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x" RS "%d" RS "%d",
                           __entry->uid, __get_str(exe_path), __entry->pid, __entry->ppid,
                           __entry->pgid, __entry->tgid, __entry->sid,
                           __entry->comm, __get_str(nodename),__entry->sessionid,
                           NIP6(__entry->in6_addr), __entry->sport, __entry->retval)

);
#endif


PRINT_EVENT_DEFINE(update_cred,

                   PE_PROTO(char * exe_path, char *pid_tree, int old_uid, int retval),

                   PE_ARGS(exe_path, pid_tree, old_uid, retval),

                   PE_STRUCT__entry(
                           __field(int, uid)
                           __string(exe_path, exe_path)
                           __string(pid_tree, pid_tree)
                           __field(int, pid)
                           __field(int, ppid)
                           __field(int, pgid)
                           __field(int, tgid)
                           __field(int, sid)
                           __array(char, comm, TASK_COMM_LEN)
                           __field(int, old_uid)
                           __string(nodename, current->nsproxy->uts_ns->name.nodename)
                           __field(unsigned int, sessionid)
                           __field(int, retval)
                   ),

                   PE_fast_assign(
                           __entry->uid = get_current_uid();
                           __assign_str(exe_path, exe_path);
                           __assign_str(pid_tree, pid_tree);
                           __entry->pid = current->pid;
                           __entry->ppid = current->real_parent->pid;
                           __entry->pgid = __get_pgid();
                           __entry->sid = __get_sid();
                           __entry->tgid = current->tgid;
                           memcpy(__entry->comm, current->comm, TASK_COMM_LEN);
                           __entry->old_uid = old_uid;
                           __assign_str(nodename, current->nsproxy->uts_ns->name.nodename);
                           __entry->sessionid = __get_sessionid();
                           __entry->retval = retval;
                   ),

                   PE_printk(
                           "%d" RS "604" RS "%s" RS "%d" RS "%d" RS "%d" RS "%d" RS "%d" RS "%s" RS "%s" RS "%u" RS "%s" RS "%d" RS "%d",
                           __entry->uid, __get_str(exe_path), __entry->pid,
                           __entry->ppid, __entry->pgid, __entry->tgid, __entry->sid, __entry->comm,
                           __get_str(nodename), __entry->sessionid, __get_str(pid_tree),
                           __entry->old_uid, __entry->retval)
);


PRINT_EVENT_DEFINE(do_init_module,

                   PE_PROTO(char * exe_path, char * mod_name, char * pid_tree, char * pwd),

                   PE_ARGS(exe_path, mod_name, pid_tree, pwd),

                   PE_STRUCT__entry(
                           __field(int, uid)
                           __string(exe_path, exe_path)
                           __string(mod_name, mod_name)
                           __string(pid_tree, pid_tree)
                           __string(pwd, pwd)
                           __field(int, pid)
                           __field(int, ppid)
                           __field(int, pgid)
                           __field(int, tgid)
                           __field(int, sid)
                           __array(char, comm, TASK_COMM_LEN)
                           __string(nodename, current->nsproxy->uts_ns->name.nodename)
                           __field(unsigned int, sessionid)
                   ),

                   PE_fast_assign(
                           __entry->uid = get_current_uid();
                           __assign_str(exe_path, exe_path);
                           __assign_str(mod_name, mod_name);
                           __assign_str(pid_tree, pid_tree);
                           __assign_str(pwd, pwd);
                           __entry->pid = current->pid;
                           __entry->ppid = current->real_parent->pid;
                           __entry->pgid = __get_pgid();
                           __entry->sid = __get_sid();
                           __entry->tgid = current->tgid;
                           memcpy(__entry->comm, current->comm, TASK_COMM_LEN);
                           __assign_str(nodename, current->nsproxy->uts_ns->name.nodename);
                           __entry->sessionid = __get_sessionid();
                   ),

                   PE_printk("%d" RS "603" RS "%s" RS "%d" RS "%d" RS "%d" RS "%d" RS "%d" RS "%s" RS "%s" RS "%u" RS "%s" RS "%s" RS "%s",
                           __entry->uid, __get_str(exe_path),__entry->pid,
                           __entry->ppid, __entry->pgid, __entry->tgid, __entry->sid, __entry->comm,
                           __get_str(nodename), __entry->sessionid, __get_str(mod_name),
                           __get_str(pid_tree), __get_str(pwd))
);

PRINT_EVENT_DEFINE(rename,

                   PE_PROTO(char * exe_path,char * pwd, char * oldname, char * newname),

                   PE_ARGS(exe_path, pwd, oldname, newname),

                   PE_STRUCT__entry(
                           __field(int, uid)
                           __string(exe_path, exe_path)
                           __string(pwd, pwd)
                           __string(oldname, oldname)
                           __string(newname, newname)
                           __field(int, pid)
                           __field(int, ppid)
                           __field(int, pgid)
                           __field(int, tgid)
                           __field(int, sid)
                           __array(char, comm, TASK_COMM_LEN)
                           __string(nodename, current->nsproxy->uts_ns->name.nodename)
                           __field(unsigned int, sessionid)
                   ),

                   PE_fast_assign(
                           __entry->uid = get_current_uid();
                           __assign_str(exe_path, exe_path);
                           __assign_str(pwd, pwd);
                           __assign_str(oldname, oldname);
                           __assign_str(newname, newname);
                           __entry->pid = current->pid;
                           __entry->ppid = current->real_parent->pid;
                           __entry->pgid = __get_pgid();
                           __entry->sid = __get_sid();
                           __entry->tgid = current->tgid;
                           memcpy(__entry->comm, current->comm, TASK_COMM_LEN);
                           __assign_str(nodename, current->nsproxy->uts_ns->name.nodename);
                           __entry->sessionid = __get_sessionid();
                   ),

                   PE_printk("%d" RS "82" RS "%s" RS "%d" RS "%d" RS "%d" RS "%d" RS "%d" RS "%s" RS "%s" RS "%u" RS "%s" RS "%s" RS "%s",
                           __entry->uid, __get_str(exe_path),__entry->pid, __entry->ppid,
                           __entry->pgid, __entry->tgid, __entry->sid, __entry->comm, __get_str(nodename),
                           __entry->sessionid, __get_str(pwd), __get_str(oldname), __get_str(newname))
);

PRINT_EVENT_DEFINE(link,

                   PE_PROTO(char * exe_path,char * pwd, char * oldname, char * newname),

                   PE_ARGS(exe_path, pwd, oldname, newname),

                   PE_STRUCT__entry(
                           __field(int, uid)
                           __string(exe_path, exe_path)
                           __string(pwd, pwd)
                           __string(oldname, oldname)
                           __string(newname, newname)
                           __field(int, pid)
                           __field(int, ppid)
                           __field(int, pgid)
                           __field(int, tgid)
                           __field(int, sid)
                           __array(char, comm, TASK_COMM_LEN)
                           __string(nodename, current->nsproxy->uts_ns->name.nodename)
                           __field(unsigned int, sessionid)
                   ),

                   PE_fast_assign(
                           __entry->uid = get_current_uid();
                           __assign_str(exe_path, exe_path);
                           __assign_str(pwd, pwd);
                           __assign_str(oldname, oldname);
                           __assign_str(newname, newname);
                           __entry->pid = current->pid;
                           __entry->ppid = current->real_parent->pid;
                           __entry->pgid = __get_pgid();
                           __entry->sid = __get_sid();
                           __entry->tgid = current->tgid;
                           memcpy(__entry->comm, current->comm, TASK_COMM_LEN);
                           __assign_str(nodename, current->nsproxy->uts_ns->name.nodename);
                           __entry->sessionid = __get_sessionid();
                   ),

                   PE_printk("%d" RS "86" RS "%s" RS "%d" RS "%d" RS "%d" RS "%d" RS "%d" RS "%s" RS "%s" RS "%u" RS "%s" RS "%s" RS "%s",
                           __entry->uid, __get_str(exe_path),__entry->pid, __entry->ppid, __entry->pgid,
                           __entry->tgid, __entry->sid, __entry->comm,__get_str(nodename), __entry->sessionid,
                           __get_str(pwd), __get_str(oldname), __get_str(newname))
);


PRINT_EVENT_DEFINE(mprotect,

                   PE_PROTO(char *exe_path, unsigned long prot, char *owner_file, int owner_pid, char *vm_file, char *pid_tree),

                   PE_ARGS(exe_path, prot, owner_file, owner_pid, vm_file, pid_tree),

                   PE_STRUCT__entry(
                           __field(int, uid)
                           __string(exe_path, exe_path)
                           __field(unsigned long, prot)
                           __field(int, owner_pid)
                           __string(owner_file, owner_file)
                           __string(vm_file, vm_file)
                           __string(pid_tree, pid_tree)
                           __field(int, pid)
                           __field(int, ppid)
                           __field(int, pgid)
                           __field(int, tgid)
                           __field(int, sid)
                           __array(char, comm, TASK_COMM_LEN)
                           __string(nodename, current->nsproxy->uts_ns->name.nodename)
                           __field(unsigned int, sessionid)
                   ),

                   PE_fast_assign(
                           __entry->uid = get_current_uid();
                           __assign_str(exe_path, exe_path);
                           __entry->prot = prot;
                           __entry->owner_pid = owner_pid;
                           __assign_str(owner_file, owner_file);
                           __assign_str(vm_file, vm_file);
                           __assign_str(pid_tree, pid_tree);
                           __entry->pid = current->pid;
                           __entry->ppid = current->real_parent->pid;
                           __entry->pgid = __get_pgid();
                           __entry->sid = __get_sid();
                           __entry->tgid = current->tgid;
                           memcpy(__entry->comm, current->comm, TASK_COMM_LEN);
                           __assign_str(nodename, current->nsproxy->uts_ns->name.nodename);
                           __entry->sessionid = __get_sessionid();
                   ),

                   PE_printk("%d" RS "10" RS "%s" RS "%d" RS "%d" RS "%d" RS "%d" RS "%d" RS "%s" RS "%s" RS "%u" RS "%lu" RS "%d" RS "%s" RS "%s" RS "%s",
                           __entry->uid, __get_str(exe_path),
                           __entry->pid, __entry->ppid, __entry->pgid, __entry->tgid, __entry->sid, __entry->comm,
                           __get_str(nodename), __entry->sessionid, __entry->prot,  __entry->owner_pid,
                           __get_str(owner_file), __get_str(vm_file), __get_str(pid_tree))
);


PRINT_EVENT_DEFINE(setsid,

                   PE_PROTO(char *exe_path),

                   PE_ARGS(exe_path),

                   PE_STRUCT__entry(
                           __field(int, uid)
                           __string(exe_path, exe_path)
                           __field(int, pid)
                           __field(int, ppid)
                           __field(int, pgid)
                           __field(int, tgid)
                           __field(int, sid)
                           __array(char, comm, TASK_COMM_LEN)
                           __string(nodename, current->nsproxy->uts_ns->name.nodename)
                           __field(unsigned int, sessionid)
                   ),

                   PE_fast_assign(
                           __entry->uid = get_current_uid();
                           __assign_str(exe_path, exe_path);
                           __entry->pid = current->pid;
                           __entry->ppid = current->real_parent->pid;
                           __entry->pgid = __get_pgid();
                           __entry->sid = __get_sid();
                           __entry->tgid = current->tgid;
                           memcpy(__entry->comm, current->comm, TASK_COMM_LEN);
                           __assign_str(nodename, current->nsproxy->uts_ns->name.nodename);
                           __entry->sessionid = __get_sessionid();
                   ),

                   PE_printk("%d" RS "112" RS "%s" RS "%d" RS "%d" RS "%d" RS "%d" RS "%d" RS "%s" RS "%s" RS "%u",
                           __entry->uid, __get_str(exe_path),
                           __entry->pid, __entry->ppid, __entry->pgid,
                           __entry->tgid, __entry->sid, __entry->comm,
                           __get_str(nodename), __entry->sessionid)
);

PRINT_EVENT_DEFINE(prctl,

                   PE_PROTO(char *exe_path, int option, char *newname),

                   PE_ARGS(exe_path, option, newname),

                   PE_STRUCT__entry(
                           __field(int, uid)
                           __string(exe_path, exe_path)
                           __field(int, pid)
                           __field(int, ppid)
                           __field(int, pgid)
                           __field(int, tgid)
                           __field(int, sid)
                           __array(char, comm, TASK_COMM_LEN)
                           __string(nodename, current->nsproxy->uts_ns->name.nodename)
                           __field(unsigned int, sessionid)
                           __field(int, option)
                           __string(newname, newname)
                   ),

                   PE_fast_assign(
                           __entry->uid = get_current_uid();
                           __assign_str(exe_path, exe_path);
                           __entry->pid = current->pid;
                           __entry->ppid = current->real_parent->pid;
                           __entry->pgid = __get_pgid();
                           __entry->sid = __get_sid();
                           __entry->tgid = current->tgid;
                           memcpy(__entry->comm, current->comm, TASK_COMM_LEN);
                           __assign_str(nodename, current->nsproxy->uts_ns->name.nodename);
                           __entry->sessionid = __get_sessionid();
                           __assign_str(newname, newname);
                           __entry->option = option;
                   ),

                   PE_printk("%d" RS "157" RS "%s" RS "%d" RS "%d" RS "%d" RS "%d" RS "%d" RS "%s" RS "%s" RS "%u" RS "%d" RS "%s",
                           __entry->uid, __get_str(exe_path),
                           __entry->pid, __entry->ppid, __entry->pgid,
                           __entry->tgid, __entry->sid, __entry->comm,
                           __get_str(nodename), __entry->sessionid, __entry->option, __get_str(newname))
);

PRINT_EVENT_DEFINE(open,

                   PE_PROTO(char *exe_path, char *filename, int flags, umode_t mode),

                   PE_ARGS(exe_path, filename, flags, mode),

                   PE_STRUCT__entry(
                           __field(int, uid)
                           __string(exe_path, exe_path)
                           __field(int, pid)
                           __field(int, ppid)
                           __field(int, pgid)
                           __field(int, tgid)
                           __field(int, sid)
                           __array(char, comm, TASK_COMM_LEN)
                           __string(nodename, current->nsproxy->uts_ns->name.nodename)
                           __field(unsigned int, sessionid)
                           __field(int, flags)
                           __field(umode_t, mode)
                           __string(filename, filename)
                   ),

                   PE_fast_assign(
                           __entry->uid = get_current_uid();
                           __assign_str(exe_path, exe_path);
                           __entry->pid = current->pid;
                           __entry->ppid = current->real_parent->pid;
                           __entry->pgid = __get_pgid();
                           __entry->sid = __get_sid();
                           __entry->tgid = current->tgid;
                           memcpy(__entry->comm, current->comm, TASK_COMM_LEN);
                           __assign_str(nodename, current->nsproxy->uts_ns->name.nodename);
                           __entry->sessionid = __get_sessionid();
                           __assign_str(filename, filename);
                           __entry->flags = flags;
                           __entry->mode = mode;
                   ),

                   PE_printk("%d" RS "2" RS "%s" RS "%d" RS "%d" RS "%d" RS "%d" RS "%d" RS "%s" RS "%s" RS "%u" RS "%d" RS "%d" RS "%s",
                           __entry->uid, __get_str(exe_path),
                           __entry->pid, __entry->ppid, __entry->pgid,
                           __entry->tgid, __entry->sid, __entry->comm,
                           __get_str(nodename), __entry->sessionid,
                           __entry->flags, __entry->mode, __get_str(filename))
);

PRINT_EVENT_DEFINE(nanosleep,

                   PE_PROTO(char *exe_path, time_t sec, long nsec),

                   PE_ARGS(exe_path, sec, nsec),

                   PE_STRUCT__entry(
                           __field(int, uid)
                           __string(exe_path, exe_path)
                           __field(int, pid)
                           __field(int, ppid)
                           __field(int, pgid)
                           __field(int, tgid)
                           __field(int, sid)
                           __array(char, comm, TASK_COMM_LEN)
                           __string(nodename, current->nsproxy->uts_ns->name.nodename)
                           __field(unsigned int, sessionid)
                           __field(time_t, sec)
                           __field(long, nsec)
                   ),

                   PE_fast_assign(
                           __entry->uid = get_current_uid();
                           __assign_str(exe_path, exe_path);
                           __entry->pid = current->pid;
                           __entry->ppid = current->real_parent->pid;
                           __entry->pgid = __get_pgid();
                           __entry->sid = __get_sid();
                           __entry->tgid = current->tgid;
                           memcpy(__entry->comm, current->comm, TASK_COMM_LEN);
                           __assign_str(nodename, current->nsproxy->uts_ns->name.nodename);
                           __entry->sessionid = __get_sessionid();
                           __entry->sec = sec;
                           __entry->nsec = nsec;
                   ),

                   PE_printk("%d" RS "2" RS "%s" RS "%d" RS "%d" RS "%d" RS "%d" RS "%d" RS "%s" RS "%s" RS "%u" RS "%ld" RS "%ld",
                           __entry->uid, __get_str(exe_path),
                           __entry->pid, __entry->ppid, __entry->pgid,
                           __entry->tgid, __entry->sid, __entry->comm,
                           __get_str(nodename), __entry->sessionid,
                           __entry->sec, __entry->nsec)
);

PRINT_EVENT_DEFINE(kill,

                   PE_PROTO(char *exe_path, pid_t target_pid, int sig),

                   PE_ARGS(exe_path, target_pid, sig),

                   PE_STRUCT__entry(
                           __field(int, uid)
                           __string(exe_path, exe_path)
                           __field(int, pid)
                           __field(int, ppid)
                           __field(int, pgid)
                           __field(int, tgid)
                           __field(int, sid)
                           __array(char, comm, TASK_COMM_LEN)
                           __string(nodename, current->nsproxy->uts_ns->name.nodename)
                           __field(unsigned int, sessionid)
                           __field(pid_t, target_pid)
                           __field(int, sig)
                   ),

                   PE_fast_assign(
                           __entry->uid = get_current_uid();
                           __assign_str(exe_path, exe_path);
                           __entry->pid = current->pid;
                           __entry->ppid = current->real_parent->pid;
                           __entry->pgid = __get_pgid();
                           __entry->sid = __get_sid();
                           __entry->tgid = current->tgid;
                           memcpy(__entry->comm, current->comm, TASK_COMM_LEN);
                           __assign_str(nodename, current->nsproxy->uts_ns->name.nodename);
                           __entry->sessionid = __get_sessionid();
                           __entry->target_pid = target_pid;
                           __entry->sig = sig;
                   ),

                   PE_printk("%d" RS "62" RS "%s" RS "%d" RS "%d" RS "%d" RS "%d" RS "%d" RS "%s" RS "%s" RS "%u" RS "%d" RS "%d",
                           __entry->uid, __get_str(exe_path),
                           __entry->pid, __entry->ppid, __entry->pgid,
                           __entry->tgid, __entry->sid, __entry->comm,
                           __get_str(nodename), __entry->sessionid,
                           __entry->target_pid, __entry->sig)
);

PRINT_EVENT_DEFINE(tkill,

                   PE_PROTO(char *exe_path, pid_t target_pid, int sig),

                   PE_ARGS(exe_path, target_pid, sig),

                   PE_STRUCT__entry(
                           __field(int, uid)
                           __string(exe_path, exe_path)
                           __field(int, pid)
                           __field(int, ppid)
                           __field(int, pgid)
                           __field(int, tgid)
                           __field(int, sid)
                           __array(char, comm, TASK_COMM_LEN)
                           __string(nodename, current->nsproxy->uts_ns->name.nodename)
                           __field(unsigned int, sessionid)
                           __field(pid_t, target_pid)
                           __field(int, sig)
                   ),

                   PE_fast_assign(
                           __entry->uid = get_current_uid();
                           __assign_str(exe_path, exe_path);
                           __entry->pid = current->pid;
                           __entry->ppid = current->real_parent->pid;
                           __entry->pgid = __get_pgid();
                           __entry->sid = __get_sid();
                           __entry->tgid = current->tgid;
                           memcpy(__entry->comm, current->comm, TASK_COMM_LEN);
                           __assign_str(nodename, current->nsproxy->uts_ns->name.nodename);
                           __entry->sessionid = __get_sessionid();
                           __entry->target_pid = target_pid;
                           __entry->sig = sig;
                   ),

                   PE_printk("%d" RS "200" RS "%s" RS "%d" RS "%d" RS "%d" RS "%d" RS "%d" RS "%s" RS "%s" RS "%u" RS "%d" RS "%d",
                           __entry->uid, __get_str(exe_path),
                           __entry->pid, __entry->ppid, __entry->pgid,
                           __entry->tgid, __entry->sid, __entry->comm,
                           __get_str(nodename), __entry->sessionid,
                           __entry->target_pid, __entry->sig)
);

PRINT_EVENT_DEFINE(exit,

                   PE_PROTO(char *exe_path),

                   PE_ARGS(exe_path),

                   PE_STRUCT__entry(
                           __field(int, uid)
                           __string(exe_path, exe_path)
                           __field(int, pid)
                           __field(int, ppid)
                           __field(int, pgid)
                           __field(int, tgid)
                           __field(int, sid)
                           __array(char, comm, TASK_COMM_LEN)
                           __string(nodename, current->nsproxy->uts_ns->name.nodename)
                           __field(unsigned int, sessionid)
                   ),

                   PE_fast_assign(
                           __entry->uid = get_current_uid();
                           __assign_str(exe_path, exe_path);
                           __entry->pid = current->pid;
                           __entry->ppid = current->real_parent->pid;
                           __entry->pgid = __get_pgid();
                           __entry->sid = __get_sid();
                           __entry->tgid = current->tgid;
                           memcpy(__entry->comm, current->comm, TASK_COMM_LEN);
                           __assign_str(nodename, current->nsproxy->uts_ns->name.nodename);
                           __entry->sessionid = __get_sessionid();
                   ),

                   PE_printk("%d" RS "60" RS "%s" RS "%d" RS "%d" RS "%d" RS "%d" RS "%d" RS "%s" RS "%s" RS "%u",
                           __entry->uid, __get_str(exe_path),
                           __entry->pid, __entry->ppid, __entry->pgid,
                           __entry->tgid, __entry->sid, __entry->comm,
                           __get_str(nodename), __entry->sessionid)
);

PRINT_EVENT_DEFINE(exit_group,

                   PE_PROTO(char *exe_path),

                   PE_ARGS(exe_path),

                   PE_STRUCT__entry(
                           __field(int, uid)
                           __string(exe_path, exe_path)
                           __field(int, pid)
                           __field(int, ppid)
                           __field(int, pgid)
                           __field(int, tgid)
                           __field(int, sid)
                           __array(char, comm, TASK_COMM_LEN)
                           __string(nodename, current->nsproxy->uts_ns->name.nodename)
                           __field(unsigned int, sessionid)
                   ),

                   PE_fast_assign(
                           __entry->uid = get_current_uid();
                           __assign_str(exe_path, exe_path);
                           __entry->pid = current->pid;
                           __entry->ppid = current->real_parent->pid;
                           __entry->pgid = __get_pgid();
                           __entry->sid = __get_sid();
                           __entry->tgid = current->tgid;
                           memcpy(__entry->comm, current->comm, TASK_COMM_LEN);
                           __assign_str(nodename, current->nsproxy->uts_ns->name.nodename);
                           __entry->sessionid = __get_sessionid();
                   ),

                   PE_printk("%d" RS "231" RS "%s" RS "%d" RS "%d" RS "%d" RS "%d" RS "%d" RS "%s" RS "%s" RS "%u",
                           __entry->uid, __get_str(exe_path),
                           __entry->pid, __entry->ppid, __entry->pgid,
                           __entry->tgid, __entry->sid, __entry->comm,
                           __get_str(nodename), __entry->sessionid)
);

PRINT_EVENT_DEFINE(security_path_rmdir,

                   PE_PROTO(char *exe_path, char *file),

                   PE_ARGS(exe_path, file),

                   PE_STRUCT__entry(
                           __field(int, uid)
                           __string(exe_path, exe_path)
                           __field(int, pid)
                           __field(int, ppid)
                           __field(int, pgid)
                           __field(int, tgid)
                           __field(int, sid)
                           __array(char, comm, TASK_COMM_LEN)
                           __string(nodename, current->nsproxy->uts_ns->name.nodename)
                           __field(unsigned int, sessionid)
                           __string(file, file)
                   ),

                   PE_fast_assign(
                           __entry->uid = get_current_uid();
                           __assign_str(exe_path, exe_path);
                           __entry->pid = current->pid;
                           __entry->ppid = current->real_parent->pid;
                           __entry->pgid = __get_pgid();
                           __entry->sid = __get_sid();
                           __entry->tgid = current->tgid;
                           memcpy(__entry->comm, current->comm, TASK_COMM_LEN);
                           __assign_str(nodename, current->nsproxy->uts_ns->name.nodename);
                           __entry->sessionid = __get_sessionid();
                           __assign_str(file, file);
                   ),

                   PE_printk("%d" RS "606" RS "%s" RS "%d" RS "%d" RS "%d" RS "%d" RS "%d" RS "%s" RS "%s" RS "%u" RS "%s",
                           __entry->uid, __get_str(exe_path),
                           __entry->pid, __entry->ppid, __entry->pgid,
                           __entry->tgid, __entry->sid, __entry->comm,
                           __get_str(nodename), __entry->sessionid, __get_str(file))
);

PRINT_EVENT_DEFINE(security_path_unlink,

                   PE_PROTO(char *exe_path, char *file),

                   PE_ARGS(exe_path, file),

                   PE_STRUCT__entry(
                           __field(int, uid)
                           __string(exe_path, exe_path)
                           __field(int, pid)
                           __field(int, ppid)
                           __field(int, pgid)
                           __field(int, tgid)
                           __field(int, sid)
                           __array(char, comm, TASK_COMM_LEN)
                           __string(nodename, current->nsproxy->uts_ns->name.nodename)
                           __field(unsigned int, sessionid)
                           __string(file, file)
                   ),

                   PE_fast_assign(
                           __entry->uid = get_current_uid();
                           __assign_str(exe_path, exe_path);
                           __entry->pid = current->pid;
                           __entry->ppid = current->real_parent->pid;
                           __entry->pgid = __get_pgid();
                           __entry->sid = __get_sid();
                           __entry->tgid = current->tgid;
                           memcpy(__entry->comm, current->comm, TASK_COMM_LEN);
                           __assign_str(nodename, current->nsproxy->uts_ns->name.nodename);
                           __entry->sessionid = __get_sessionid();
                           __assign_str(file, file);
                   ),

                   PE_printk("%d" RS "605" RS "%s" RS "%d" RS "%d" RS "%d" RS "%d" RS "%d" RS "%s" RS "%s" RS "%u" RS "%s",
                           __entry->uid, __get_str(exe_path),
                           __entry->pid, __entry->ppid, __entry->pgid,
                           __entry->tgid, __entry->sid, __entry->comm,
                           __get_str(nodename), __entry->sessionid, __get_str(file))
);

#endif /* _KPROBE_PRINT_H */

/* This part must be outside protection */
#include "define_trace.h"

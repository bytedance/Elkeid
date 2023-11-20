/* SPDX-License-Identifier: GPL-2.0 */
#undef PRINT_EVENT_SYSTEM
#define PRINT_EVENT_SYSTEM kprobe_print

#if !defined(_KPROBE_PRINT_H) || defined(TRACE_HEADER_MULTI_READ)
#define _KPROBE_PRINT_H

PRINT_EVENT_DEFINE(call_usermodehelper_exec,

                   PE_PROTO(const char * exe, char * argv, int wait),

                   PE_ARGS(exe, argv, wait),

                   PE_STRUCT__entry(
                           __string(exe, exe)
                           __string(argv, argv)
                           __field(int, wait)
                   ),

                   PE_fast_assign(
                           __assign_str(exe, exe);
                           __assign_str(argv, argv);
                           __entry->wait = wait;
                   ),

                   PE_printk("607" RS "%s" RS "%s" RS "%d",
                           __get_str(exe, exe), __get_str(argv, argv), __get_ent(wait, wait))
)

PRINT_EVENT_DEFINE(security_inode4_create,

                   PE_PROTO(char * exe_path, char * pathstr, __be32 dip,
                                   int dport, __be32 sip, int sport, pid_t socket_pid, char * s_id),

                   PE_ARGS(exe_path, pathstr, dip, dport, sip, sport, socket_pid, s_id),

                   PE_STRUCT__entry(
                           __field(int, uid)
                           __string(exe_path, exe_path)
                           __string(pathstr, pathstr)
                           __field(int, pid)
                           __field(int, ppid)
                           __field(int, pgid)
                           __field(int, tgid)
                           __field(int, sid)
                           __field(__be32, dip)
                           __field(int, dport)
                           __field(__be32, sip)
                           __field(int, sport)
                           __field(pid_t, socket_pid)
                           __array(char, comm, TASK_COMM_LEN)
                           __string(nodename, current->nsproxy->uts_ns->name.nodename)
                           __field(unsigned int, sessionid)
                           __field(unsigned int, pid_inum)
                           __field(unsigned int, root_pid_inum)
                           __string(s_id, s_id)
                   ),

                   PE_fast_assign(
                           __entry->uid = __get_current_uid();
                           __assign_str(exe_path, exe_path);
                           __assign_str(pathstr, pathstr);
                           __entry->pid = current->pid;
                           __entry->ppid = current->real_parent->tgid;
                           __entry->pgid = __get_pgid();
                           __entry->sid = __get_sid();
                           __entry->tgid = current->tgid;
                           __entry->dip = dip;
                           __entry->dport = dport;
                           __entry->sip = sip;
                           __entry->sport = sport;
                           __entry->socket_pid = socket_pid;
                           memcpy(__entry->comm, current->comm, TASK_COMM_LEN);
                           __assign_str(nodename, current->nsproxy->uts_ns->name.nodename);
                           __entry->sessionid = __get_sessionid();
                           __entry->pid_inum = __get_pid_ns_inum();
                           __entry->root_pid_inum = ROOT_PID_NS_INUM;
                           __assign_str(s_id, s_id);
                   ),


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
)

PRINT_EVENT_DEFINE(security_inode_create_nosocket,

                   PE_PROTO(char * exe_path, char * pathstr, char * s_id),

                   PE_ARGS(exe_path, pathstr, s_id),

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
                           __field(unsigned int, pid_inum)
                           __field(unsigned int, root_pid_inum)
                           __string(s_id, s_id)
                   ),

                   PE_fast_assign(
                           __entry->uid = __get_current_uid();
                           __assign_str(exe_path, exe_path);
                           __assign_str(pathstr, pathstr);
                           __entry->pid = current->pid;
                           __entry->ppid = current->real_parent->tgid;
                           __entry->pgid = __get_pgid();
                           __entry->sid = __get_sid();
                           __entry->tgid = current->tgid;
                           memcpy(__entry->comm, current->comm, TASK_COMM_LEN);
                           __assign_str(nodename, current->nsproxy->uts_ns->name.nodename);
                           __entry->sessionid = __get_sessionid();
                           __entry->pid_inum = __get_pid_ns_inum();
                           __entry->root_pid_inum = ROOT_PID_NS_INUM;
                           __assign_str(s_id, s_id);
                   ),


                   PE_printk("602" RS "%d" RS "%s" RS "%d" RS "%d" RS "%d" RS "%d" RS "%d" RS "%s" RS "%s" RS "%u" RS "%u" RS "%u" RS "%s" RS "-1" RS "-1" RS "-1" RS "-1" RS "-1" RS "-1" RS "%s",
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
)


#if IS_ENABLED(CONFIG_IPV6)
PRINT_EVENT_DEFINE(security_inode6_create,


                   PE_PROTO(char * exe_path, char * pathstr, struct in6_addr *dip, int dport, struct in6_addr *sip,
                           int sport, pid_t socket_pid, char * s_id),

                   PE_ARGS(exe_path, pathstr, dip, dport, sip, sport, socket_pid, s_id),

                   PE_STRUCT__entry(
                           __field(int, uid)
                           __string(exe_path, exe_path)
                           __string(pathstr, pathstr)
                           __field(int, pid)
                           __field(int, ppid)
                           __field(int, pgid)
                           __field(int, tgid)
                           __field(int, sid)
                           __field(struct in6_addr, dip)
                           __field(int, dport)
                           __field(struct in6_addr, sip)
                           __field(int, sport)
                           __field(pid_t, socket_pid)
                           __array(char, comm, TASK_COMM_LEN)
                           __string(nodename, current->nsproxy->uts_ns->name.nodename)
                           __field(unsigned int, sessionid)
                           __field(unsigned int, pid_inum)
                           __field(unsigned int, root_pid_inum)
                           __string(s_id, s_id)
                   ),

                   PE_fast_assign(
                           __entry->uid = __get_current_uid();
                           __assign_str(exe_path, exe_path);
                           __assign_str(pathstr, pathstr);
                           __entry->pid = current->pid;
                           __entry->ppid = current->real_parent->tgid;
                           __entry->pgid = __get_pgid();
                           __entry->sid = __get_sid();
                           __entry->tgid = current->tgid;
                           memcpy(&__entry->dip, dip, sizeof(*dip));
                           __entry->dport = dport;
                           memcpy(&__entry->sip, sip, sizeof(*sip));
                           __entry->sport = sport;
                           __entry->socket_pid = socket_pid;
                           memcpy(__entry->comm, current->comm, TASK_COMM_LEN);
                           __assign_str(nodename, current->nsproxy->uts_ns->name.nodename);
                           __entry->sessionid = __get_sessionid();
                           __entry->pid_inum = __get_pid_ns_inum();
                           __entry->root_pid_inum = ROOT_PID_NS_INUM;
                           __assign_str(s_id, s_id);
                   ),

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
                           NIP6(__get_ent(dip, dip)), 
                           __get_ent(dport, dport),
                           NIP6(__get_ent(sip, sip)),
                           __get_ent(sport, sport),
                           __get_ent(socket_pid, socket_pid),
                           __get_str(s_id, s_id)
                   )
)
#endif

PRINT_EVENT_DEFINE(dns,

                   PE_PROTO(int dport,
                           __be32 dip, char * exe_path,
                           __be32 sip, int sport, int opcode, int rcode,
                           char * query),

                   PE_ARGS(dport, dip, exe_path,
                           sip, sport, opcode, rcode,
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
                           __field(int, opcode)
                           __field(int, rcode)
                           __string(query, query)
                           __field(unsigned int, sessionid)
                           __field(unsigned int, pid_inum)
                           __field(unsigned int, root_pid_inum)
                   ),

                   PE_fast_assign(
                           __entry->uid = __get_current_uid();
                           __entry->dport = dport;
                           __entry->dip = dip;
                           __assign_str(exe_path, exe_path);
                           __entry->pid = current->pid;
                           __entry->ppid = current->real_parent->tgid;
                           __entry->pgid = __get_pgid();
                           __entry->sid = __get_sid();
                           __entry->tgid = current->tgid;
                           memcpy(__entry->comm, current->comm, TASK_COMM_LEN);
                           __assign_str(nodename, current->nsproxy->uts_ns->name.nodename);
                           __entry->sip = sip;
                           __entry->sport = sport;
                           __entry->opcode = opcode;
                           __entry->rcode = rcode;
                           __assign_str(query, query);
                           __entry->sessionid = __get_sessionid();
                           __entry->pid_inum = __get_pid_ns_inum();
                           __entry->root_pid_inum = ROOT_PID_NS_INUM;
                   ),

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
)

#if IS_ENABLED(CONFIG_IPV6)
PRINT_EVENT_DEFINE(dns6,

                   PE_PROTO(int dport,
                           struct in6_addr *dip, char * exe_path,
                           struct in6_addr *sip, int sport, int opcode, int rcode,
                           char * query),

                   PE_ARGS(dport, dip, exe_path,
                           sip, sport, opcode, rcode,
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
                           __field(int, opcode)
                           __field(int, rcode)
                           __string(query, query)
                           __field(unsigned int, sessionid)
                           __field(unsigned int, pid_inum)
                           __field(unsigned int, root_pid_inum)
                   ),

                   PE_fast_assign(
                           __entry->uid = __get_current_uid();
                           __entry->dport = dport;
                           memcpy(&__entry->dip, dip, sizeof(*dip));
                           __assign_str(exe_path, exe_path);
                           __entry->pid = current->pid;
                           __entry->ppid = current->real_parent->tgid;
                           __entry->pgid = __get_pgid();
                           __entry->sid = __get_sid();
                           __entry->tgid = current->tgid;
                           memcpy(__entry->comm, current->comm, TASK_COMM_LEN);
                           __assign_str(nodename, current->nsproxy->uts_ns->name.nodename);
                           memcpy(&__entry->sip, sip, sizeof(*sip));
                           __entry->sport = sport;
                           __entry->opcode = opcode;
                           __entry->rcode = rcode;
                           __assign_str(query, query);
                           __entry->sessionid = __get_sessionid();
                           __entry->pid_inum = __get_pid_ns_inum();
                           __entry->root_pid_inum = ROOT_PID_NS_INUM;
                   ),

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
                           NIP6(__get_ent(dip, dip)),
                           __get_ent(dport, dport),
                           NIP6(__get_ent(sip, sip)),
                           __get_ent(sport, sport),
                           __get_ent(opcode, opcode),
                           __get_ent(rcode, rcode)
                   )
)
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

                   PE_STRUCT__entry(
                           __field(int, uid)
                           __string(pname, pname)
                           __string(exe_path, exe_path)
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
                           __field(unsigned int, pid_inum)
                           __field(unsigned int, root_pid_inum)
                           __field(__be32, dip)
                           __field(int, dport)
                           __field(__be32, sip)
                           __field(int, sport)
                           __string(pid_tree, pid_tree)
                           __string(tty_name, tty_name)
                           __field(pid_t, socket_pid)
                           __string(ssh_connection, ssh_connection)
                           __string(ld_preload, ld_preload)
                           __field(int, retval)
                   ),

                   PE_fast_assign(
                           __entry->uid = __get_current_uid();
                           __assign_str(pname, pname);
                           __assign_str(exe_path, exe_path);
                           __assign_str(argv, argv);
                           __entry->pid = current->pid;
                           __entry->ppid = current->real_parent->tgid;
                           __entry->pgid = __get_pgid();
                           __entry->sid = __get_sid();
                           __entry->tgid = current->tgid;
                           memcpy(__entry->comm, current->comm, TASK_COMM_LEN);
                           __assign_str(nodename, current->nsproxy->uts_ns->name.nodename);
                           __assign_str(tmp_stdin, tmp_stdin);
                           __assign_str(tmp_stdout, tmp_stdout);
                           __entry->sessionid = __get_sessionid();
                           __entry->pid_inum = __get_pid_ns_inum();
                           __entry->root_pid_inum = ROOT_PID_NS_INUM;
                           __entry->dip = dip;
                           __entry->dport = dport;
                           __entry->sip = sip;
                           __entry->sport = sport;
                           __assign_str(pid_tree, pid_tree);
                           __assign_str(tty_name, tty_name);
                           __entry->socket_pid = socket_pid;
                           __assign_str(ssh_connection, ssh_connection);
                           __assign_str(ld_preload, ld_preload);
                           __entry->retval = retval;
                   ),


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
)

PRINT_EVENT_DEFINE(execve_nosocket,

                   PE_PROTO(char * pname, char * exe_path, char * argv,
                            char * tmp_stdin, char * tmp_stdout, char * pid_tree,
                            char * tty_name, char * ssh_connection, char * ld_preload, int retval),

                   PE_ARGS(pname, exe_path, argv,
                           tmp_stdin, tmp_stdout,
                           pid_tree, tty_name,
                           ssh_connection, ld_preload,
                           retval),

                   PE_STRUCT__entry(
                           __field(int, uid)
                           __string(pname, pname)
                           __string(exe_path, exe_path)
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
                           __field(unsigned int, pid_inum)
                           __field(unsigned int, root_pid_inum)
                           __string(pid_tree, pid_tree)
                           __string(tty_name, tty_name)
                           __string(ssh_connection, ssh_connection)
                           __string(ld_preload, ld_preload)
                           __field(int, retval)
                   ),

                   PE_fast_assign(
                           __entry->uid = __get_current_uid();
                           __assign_str(pname, pname);
                           __assign_str(exe_path, exe_path);
                           __assign_str(argv, argv);
                           __entry->pid = current->pid;
                           __entry->ppid = current->real_parent->tgid;
                           __entry->pgid = __get_pgid();
                           __entry->sid = __get_sid();
                           __entry->tgid = current->tgid;
                           memcpy(__entry->comm, current->comm, TASK_COMM_LEN);
                           __assign_str(nodename, current->nsproxy->uts_ns->name.nodename);
                           __assign_str(tmp_stdin, tmp_stdin);
                           __assign_str(tmp_stdout, tmp_stdout);
                           __entry->sessionid = __get_sessionid();
                           __entry->pid_inum = __get_pid_ns_inum();
                           __entry->root_pid_inum = ROOT_PID_NS_INUM;
                           __assign_str(pid_tree, pid_tree);
                           __assign_str(tty_name, tty_name);
                           __assign_str(ssh_connection, ssh_connection);
                           __assign_str(ld_preload, ld_preload);
                           __entry->retval = retval;
                   ),

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
)

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

                   PE_STRUCT__entry(
                           __field(int, uid)
                           __string(pname, pname)
                           __string(exe_path, exe_path)
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
                           __field(unsigned int, pid_inum)
                           __field(unsigned int, root_pid_inum)
                           __field(struct in6_addr, dip)
                           __field(int, dport)
                           __field(struct in6_addr, sip)
                           __field(int, sport)
                           __string(pid_tree, pid_tree)
                           __string(tty_name, tty_name)
                           __field(pid_t, socket_pid)
                           __string(ssh_connection, ssh_connection)
                           __string(ld_preload, ld_preload)
                           __field(int, retval)
                   ),

                   PE_fast_assign(
                           __entry->uid = __get_current_uid();
                           __assign_str(pname, pname);
                           __assign_str(exe_path, exe_path);
                           __assign_str(argv, argv);
                           __entry->pid = current->pid;
                           __entry->ppid = current->real_parent->tgid;
                           __entry->pgid = __get_pgid();
                           __entry->sid = __get_sid();
                           __entry->tgid = current->tgid;
                           memcpy(__entry->comm, current->comm, TASK_COMM_LEN);
                           __assign_str(nodename, current->nsproxy->uts_ns->name.nodename);
                           __assign_str(tmp_stdin, tmp_stdin);
                           __assign_str(tmp_stdout, tmp_stdout);
                           __entry->sessionid = __get_sessionid();
                           __entry->pid_inum = __get_pid_ns_inum();
                           __entry->root_pid_inum = ROOT_PID_NS_INUM;
                           memcpy(&__entry->dip, dip, sizeof(*dip));
                           __entry->dport = dport;
                           memcpy(&__entry->sip, sip, sizeof(*sip));
                           __entry->sport = sport;
                           __assign_str(pid_tree, pid_tree);
                           __assign_str(tty_name, tty_name);
                           __entry->socket_pid = socket_pid;
                           __assign_str(ssh_connection, ssh_connection);
                           __assign_str(ld_preload, ld_preload);
                           __entry->retval = retval;
                   ),

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
                           NIP6(__get_ent(dip, dip)),
                           __get_ent(dport, dport),
                           NIP6(__get_ent(sip, sip)),
                           __get_ent(sport, sport),
                           __get_str(pid_tree, pid_tree),
                           __get_str(tty_name, tty_name),
                           __get_ent(socket_pid, socket_pid),
                           __get_str(ssh_connection, ssh_connection),
                           __get_str(ld_preload, ld_preload),
                           __get_ent(retval, retval)
                   )
)
#endif

PRINT_EVENT_DEFINE(accept,

                   PE_PROTO(int dport, __be32 dip, char * exe_path,
                                  __be32 sip, int sport, int retval),

                   PE_ARGS(dport, dip, exe_path,
                                 sip, sport, retval),

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
                           __field(int, retval)
                           __field(unsigned int, sessionid)
                           __field(unsigned int, pid_inum)
                           __field(unsigned int, root_pid_inum)
                   ),

                   PE_fast_assign(
                           __entry->uid = __get_current_uid();
                           __entry->dport = dport;
                           __entry->dip = dip;
                           __assign_str(exe_path, exe_path);
                           __entry->pid = current->pid;
                           __entry->ppid = current->real_parent->pid;
                           __entry->pgid = __get_pgid();
                           __entry->sid = __get_sid();
                           __entry->tgid = current->tgid;
                           __entry->sessionid = __get_sessionid();
                           __entry->pid_inum = __get_pid_ns_inum();
                           __entry->root_pid_inum = ROOT_PID_NS_INUM;
                           memcpy(__entry->comm, current->comm, TASK_COMM_LEN);
                           __assign_str(nodename, current->nsproxy->uts_ns->name.nodename);
                           __entry->sip = sip;
                           __entry->sport = sport;
                           __entry->retval = retval;
                           __entry->sessionid = __get_sessionid();
                   ),

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
)

#if IS_ENABLED(CONFIG_IPV6)
PRINT_EVENT_DEFINE(accept6,

                   PE_PROTO(int dport, struct in6_addr *dip, char * exe_path,
                           struct in6_addr *sip, int sport, int retval),

                   PE_ARGS(dport, dip, exe_path,
                           sip, sport, retval),

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
                           __field(int, retval)
                           __field(unsigned int, sessionid)
                           __field(unsigned int, pid_inum)
                           __field(unsigned int, root_pid_inum)
                   ),

                   PE_fast_assign(
                           __entry->uid = __get_current_uid();
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
                           __entry->pid_inum = __get_pid_ns_inum();
                           __entry->root_pid_inum = ROOT_PID_NS_INUM;
                   ),

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

                           NIP6(__get_ent(dip, dip)),
                           __get_ent(dport, dport),
                           NIP6(__get_ent(sip, sip)),
                           __get_ent(sport, sport),
                           __get_ent(retval, retval) )
)
#endif

PRINT_EVENT_DEFINE(connect4,

                   PE_PROTO(
                           int dport, __be32 dip, char * exe_path,
                           __be32 sip, int sport, int retval),

                   PE_ARGS(
                           dport, dip, exe_path,
                           sip, sport, retval),

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
                           __field(int, retval)
                           __field(unsigned int, sessionid)
                           __field(unsigned int, pid_inum)
                           __field(unsigned int, root_pid_inum)
                   ),

                   PE_fast_assign(
                           __entry->uid = __get_current_uid();
                           __entry->dport = dport;
                           __entry->dip = dip;
                           __assign_str(exe_path, exe_path);
                           __entry->pid = current->pid;
                           __entry->ppid = current->real_parent->tgid;
                           __entry->pgid = __get_pgid();
                           __entry->sid = __get_sid();
                           __entry->tgid = current->tgid;
                           memcpy(__entry->comm, current->comm, TASK_COMM_LEN);
                           __assign_str(nodename, current->nsproxy->uts_ns->name.nodename);
                           __entry->sip = sip;
                           __entry->sport = sport;
                           __entry->retval = retval;
                           __entry->sessionid = __get_sessionid();
                           __entry->pid_inum = __get_pid_ns_inum();
                           __entry->root_pid_inum = ROOT_PID_NS_INUM;
                   ),

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
)

#if IS_ENABLED(CONFIG_IPV6)
PRINT_EVENT_DEFINE(connect6,

                   PE_PROTO(
                           int dport, struct in6_addr *dip, char * exe_path,
                           struct in6_addr *sip, int sport, int retval),

                   PE_ARGS(
                           dport, dip, exe_path,
                           sip, sport, retval),

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
                           __field(int, retval)
                           __field(unsigned int, sessionid)
                           __field(unsigned int, pid_inum)
                           __field(unsigned int, root_pid_inum)
                   ),

                   PE_fast_assign(
                           __entry->uid = __get_current_uid();
                           __entry->dport = dport;
                           memcpy(&__entry->dip, dip, sizeof(*dip));
                           __assign_str(exe_path, exe_path);
                           __entry->pid = current->pid;
                           __entry->ppid = current->real_parent->tgid;
                           __entry->pgid = __get_pgid();
                           __entry->sid = __get_sid();
                           __entry->tgid = current->tgid;
                           memcpy(__entry->comm, current->comm, TASK_COMM_LEN);
                           __assign_str(nodename, current->nsproxy->uts_ns->name.nodename);
                           memcpy(&__entry->sip, sip, sizeof(*sip));
                           __entry->sport = sport;
                           __entry->retval = retval;
                           __entry->sessionid = __get_sessionid();
                           __entry->pid_inum = __get_pid_ns_inum();
                           __entry->root_pid_inum = ROOT_PID_NS_INUM;
                   ),

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

                           NIP6(__get_ent(dip, dip)),
                           __get_ent(dport, dport),
                           NIP6(__get_ent(sip, sip)),
                           __get_ent(sport, sport),
                           __get_ent(retval, retval)
                   )
)
#endif

PRINT_EVENT_DEFINE(ptrace,

                   PE_PROTO(long request, long owner_pid, void *addr, char *data_res, char *exe_path, char *pid_tree),

                   PE_ARGS(request, owner_pid, addr, data_res, exe_path, pid_tree),

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
                           __field(unsigned int, pid_inum)
                           __field(unsigned int, root_pid_inum)
                   ),

                   PE_fast_assign(
                           __entry->uid = __get_current_uid();
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
                           __entry->pid_inum = __get_pid_ns_inum();
                           __entry->root_pid_inum = ROOT_PID_NS_INUM;
                   ),

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
                           __get_ent(addr, (long)addr),
                           __get_str(data_res, data_res),
                           __get_str(pid_tree, pid_tree)
                   )
)

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
                           __field(unsigned int, pid_inum)
                           __field(unsigned int, root_pid_inum)
                   ),

                   PE_fast_assign(
                           __entry->uid = __get_current_uid();
                           __assign_str(exe_path, exe_path);
                           __entry->pid = current->pid;
                           __entry->ppid = current->real_parent->tgid;
                           __entry->pgid = __get_pgid();
                           __entry->sid = __get_sid();
                           __entry->tgid = current->tgid;
                           memcpy(__entry->comm, current->comm, TASK_COMM_LEN);
                           __assign_str(nodename, current->nsproxy->uts_ns->name.nodename);
                           memcpy(&__entry->in_addr, in_addr, sizeof(*in_addr));
                           __entry->sport = sport;
                           __entry->retval = retval;
                           __entry->sessionid = __get_sessionid();
                           __entry->pid_inum = __get_pid_ns_inum();
                           __entry->root_pid_inum = ROOT_PID_NS_INUM;
                   ),

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

                           NIPQUAD(__get_ent(in_addr, *in_addr)),
                           __get_ent(sport, sport),
                           __get_ent(retval, retval)
                   )

)

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
                           __field(unsigned int, pid_inum)
                           __field(unsigned int, root_pid_inum)
                   ),
                   PE_fast_assign(
                           __entry->uid = __get_current_uid();
                           __assign_str(exe_path, exe_path);
                           __entry->pid = current->pid;
                           __entry->ppid = current->real_parent->tgid;
                           __entry->pgid = __get_pgid();
                           __entry->sid = __get_sid();
                           __entry->tgid = current->tgid;
                           memcpy(__entry->comm, current->comm, TASK_COMM_LEN);
                           __assign_str(nodename, current->nsproxy->uts_ns->name.nodename);
                           memcpy(&__entry->in6_addr, in6_addr, sizeof(*in6_addr));
                           __entry->sport = sport;
                           __entry->retval = retval;
                           __entry->sessionid = __get_sessionid();
                           __entry->pid_inum = __get_pid_ns_inum();
                           __entry->root_pid_inum = ROOT_PID_NS_INUM;
                   ),

                   PE_printk("49" RS "%d" RS "%s" RS "%d" RS "%d" RS "%d" RS "%d" RS "%d" RS "%s" RS "%s" RS "%u" RS "%u" RS "%u" RS "10" RS "%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x" RS "%d" RS "%d",
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

                           NIP6(__get_ent(in6_addr, in6_addr)),
                           __get_ent(sport, sport),
                           __get_ent(retval, retval)
                   )

)
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
                           __field(unsigned int, pid_inum)
                           __field(unsigned int, root_pid_inum)
                           __field(int, retval)
                   ),

                   PE_fast_assign(
                           __entry->uid = __get_current_uid();
                           __assign_str(exe_path, exe_path);
                           __assign_str(pid_tree, pid_tree);
                           __entry->pid = current->pid;
                           __entry->ppid = current->real_parent->tgid;
                           __entry->pgid = __get_pgid();
                           __entry->sid = __get_sid();
                           __entry->tgid = current->tgid;
                           memcpy(__entry->comm, current->comm, TASK_COMM_LEN);
                           __entry->old_uid = old_uid;
                           __assign_str(nodename, current->nsproxy->uts_ns->name.nodename);
                           __entry->sessionid = __get_sessionid();
                           __entry->pid_inum = __get_pid_ns_inum();
                           __entry->root_pid_inum = ROOT_PID_NS_INUM;
                           __entry->retval = retval;
                   ),

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
)

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
                           __field(unsigned int, pid_inum)
                           __field(unsigned int, root_pid_inum)
                   ),

                   PE_fast_assign(
                           __entry->uid = __get_current_uid();
                           __assign_str(exe_path, exe_path);
                           __assign_str(mod_name, mod_name);
                           __assign_str(pid_tree, pid_tree);
                           __assign_str(pwd, pwd);
                           __entry->pid = current->pid;
                           __entry->ppid = current->real_parent->tgid;
                           __entry->pgid = __get_pgid();
                           __entry->sid = __get_sid();
                           __entry->tgid = current->tgid;
                           memcpy(__entry->comm, current->comm, TASK_COMM_LEN);
                           __assign_str(nodename, current->nsproxy->uts_ns->name.nodename);
                           __entry->sessionid = __get_sessionid();
                           __entry->pid_inum = __get_pid_ns_inum();
                           __entry->root_pid_inum = ROOT_PID_NS_INUM;
                   ),

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
)

PRINT_EVENT_DEFINE(rename,

                   PE_PROTO(char * exe_path,char * oldname, char * newname, char * s_id),

                   PE_ARGS(exe_path, oldname, newname, s_id),

                   PE_STRUCT__entry(
                           __field(int, uid)
                           __string(exe_path, exe_path)
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
                           __field(unsigned int, pid_inum)
                           __field(unsigned int, root_pid_inum)
                           __string(s_id, s_id)
                   ),

                   PE_fast_assign(
                           __entry->uid = __get_current_uid();
                           __assign_str(exe_path, exe_path);
                           __assign_str(oldname, oldname);
                           __assign_str(newname, newname);
                           __entry->pid = current->pid;
                           __entry->ppid = current->real_parent->tgid;
                           __entry->pgid = __get_pgid();
                           __entry->sid = __get_sid();
                           __entry->tgid = current->tgid;
                           memcpy(__entry->comm, current->comm, TASK_COMM_LEN);
                           __assign_str(nodename, current->nsproxy->uts_ns->name.nodename);
                           __entry->sessionid = __get_sessionid();
                           __entry->pid_inum = __get_pid_ns_inum();
                           __entry->root_pid_inum = ROOT_PID_NS_INUM;
                           __assign_str(s_id, s_id);
                   ),

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
)

PRINT_EVENT_DEFINE(link,

                   PE_PROTO(char * exe_path, char * oldname, char * newname, char * s_id),

                   PE_ARGS(exe_path, oldname, newname, s_id),

                   PE_STRUCT__entry(
                           __field(int, uid)
                           __string(exe_path, exe_path)
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
                           __field(unsigned int, pid_inum)
                           __field(unsigned int, root_pid_inum)
                           __string(s_id, s_id)
                   ),

                   PE_fast_assign(
                           __entry->uid = __get_current_uid();
                           __assign_str(exe_path, exe_path);
                           __assign_str(oldname, oldname);
                           __assign_str(newname, newname);
                           __entry->pid = current->pid;
                           __entry->ppid = current->real_parent->tgid;
                           __entry->pgid = __get_pgid();
                           __entry->sid = __get_sid();
                           __entry->tgid = current->tgid;
                           memcpy(__entry->comm, current->comm, TASK_COMM_LEN);
                           __assign_str(nodename, current->nsproxy->uts_ns->name.nodename);
                           __entry->sessionid = __get_sessionid();
                           __entry->pid_inum = __get_pid_ns_inum();
                           __entry->root_pid_inum = ROOT_PID_NS_INUM;
                           __assign_str(s_id, s_id);
                   ),

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
)

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
                           __field(unsigned int, pid_inum)
                           __field(unsigned int, root_pid_inum)
                   ),

                   PE_fast_assign(
                           __entry->uid = __get_current_uid();
                           __assign_str(exe_path, exe_path);
                           __entry->prot = prot;
                           __entry->owner_pid = owner_pid;
                           __assign_str(owner_file, owner_file);
                           __assign_str(vm_file, vm_file);
                           __assign_str(pid_tree, pid_tree);
                           __entry->pid = current->pid;
                           __entry->ppid = current->real_parent->tgid;
                           __entry->pgid = __get_pgid();
                           __entry->sid = __get_sid();
                           __entry->tgid = current->tgid;
                           memcpy(__entry->comm, current->comm, TASK_COMM_LEN);
                           __assign_str(nodename, current->nsproxy->uts_ns->name.nodename);
                           __entry->sessionid = __get_sessionid();
                           __entry->pid_inum = __get_pid_ns_inum();
                           __entry->root_pid_inum = ROOT_PID_NS_INUM;
                   ),

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
)

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
                           __field(unsigned int, pid_inum)
                           __field(unsigned int, root_pid_inum)
                   ),

                   PE_fast_assign(
                           __entry->uid = __get_current_uid();
                           __assign_str(exe_path, exe_path);
                           __entry->pid = current->pid;
                           __entry->ppid = current->real_parent->tgid;
                           __entry->pgid = __get_pgid();
                           __entry->sid = __get_sid();
                           __entry->tgid = current->tgid;
                           memcpy(__entry->comm, current->comm, TASK_COMM_LEN);
                           __assign_str(nodename, current->nsproxy->uts_ns->name.nodename);
                           __entry->sessionid = __get_sessionid();
                           __entry->pid_inum = __get_pid_ns_inum();
                           __entry->root_pid_inum = ROOT_PID_NS_INUM;
                   ),

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

)

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
                           __field(unsigned int, pid_inum)
                           __field(unsigned int, root_pid_inum)
                           __field(int, option)
                           __string(newname, newname)
                   ),

                   PE_fast_assign(
                           __entry->uid = __get_current_uid();
                           __assign_str(exe_path, exe_path);
                           __entry->pid = current->pid;
                           __entry->ppid = current->real_parent->tgid;
                           __entry->pgid = __get_pgid();
                           __entry->sid = __get_sid();
                           __entry->tgid = current->tgid;
                           memcpy(__entry->comm, current->comm, TASK_COMM_LEN);
                           __assign_str(nodename, current->nsproxy->uts_ns->name.nodename);
                           __entry->sessionid = __get_sessionid();
                           __entry->pid_inum = __get_pid_ns_inum();
                           __entry->root_pid_inum = ROOT_PID_NS_INUM;
                           __assign_str(newname, newname);
                           __entry->option = option;
                   ),


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
)

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
                           __field(unsigned int, pid_inum)
                           __field(unsigned int, root_pid_inum)
                           __field(int, flags)
                           __field(umode_t, mode)
                           __string(filename, filename)
                   ),

                   PE_fast_assign(
                           __entry->uid = __get_current_uid();
                           __assign_str(exe_path, exe_path);
                           __entry->pid = current->pid;
                           __entry->ppid = current->real_parent->tgid;
                           __entry->pgid = __get_pgid();
                           __entry->sid = __get_sid();
                           __entry->tgid = current->tgid;
                           memcpy(__entry->comm, current->comm, TASK_COMM_LEN);
                           __assign_str(nodename, current->nsproxy->uts_ns->name.nodename);
                           __entry->sessionid = __get_sessionid();
                           __entry->pid_inum = __get_pid_ns_inum();
                           __entry->root_pid_inum = ROOT_PID_NS_INUM;
                           __assign_str(filename, filename);
                           __entry->flags = flags;
                           __entry->mode = mode;
                   ),

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
)

PRINT_EVENT_DEFINE(nanosleep,

                   PE_PROTO(char *exe_path, long long sec, long nsec),

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
                           __field(unsigned int, pid_inum)
                           __field(unsigned int, root_pid_inum)
                           __field(long long, sec)
                           __field(long, nsec)
                   ),

                   PE_fast_assign(
                           __entry->uid = __get_current_uid();
                           __assign_str(exe_path, exe_path);
                           __entry->pid = current->pid;
                           __entry->ppid = current->real_parent->tgid;
                           __entry->pgid = __get_pgid();
                           __entry->sid = __get_sid();
                           __entry->tgid = current->tgid;
                           memcpy(__entry->comm, current->comm, TASK_COMM_LEN);
                           __assign_str(nodename, current->nsproxy->uts_ns->name.nodename);
                           __entry->sessionid = __get_sessionid();
                           __entry->pid_inum = __get_pid_ns_inum();
                           __entry->root_pid_inum = ROOT_PID_NS_INUM;
                           __entry->sec = sec;
                           __entry->nsec = nsec;
                   ),

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
)

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
                           __field(unsigned int, pid_inum)
                           __field(unsigned int, root_pid_inum)
                           __field(pid_t, target_pid)
                           __field(int, sig)
                   ),

                   PE_fast_assign(
                           __entry->uid = __get_current_uid();
                           __assign_str(exe_path, exe_path);
                           __entry->pid = current->pid;
                           __entry->ppid = current->real_parent->tgid;
                           __entry->pgid = __get_pgid();
                           __entry->sid = __get_sid();
                           __entry->tgid = current->tgid;
                           memcpy(__entry->comm, current->comm, TASK_COMM_LEN);
                           __assign_str(nodename, current->nsproxy->uts_ns->name.nodename);
                           __entry->sessionid = __get_sessionid();
                           __entry->pid_inum = __get_pid_ns_inum();
                           __entry->root_pid_inum = ROOT_PID_NS_INUM;
                           __entry->target_pid = target_pid;
                           __entry->sig = sig;
                   ),

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
)

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
                           __field(unsigned int, pid_inum)
                           __field(unsigned int, root_pid_inum)
                           __field(pid_t, target_pid)
                           __field(int, sig)
                   ),

                   PE_fast_assign(
                           __entry->uid = __get_current_uid();
                           __assign_str(exe_path, exe_path);
                           __entry->pid = current->pid;
                           __entry->ppid = current->real_parent->tgid;
                           __entry->pgid = __get_pgid();
                           __entry->sid = __get_sid();
                           __entry->tgid = current->tgid;
                           memcpy(__entry->comm, current->comm, TASK_COMM_LEN);
                           __assign_str(nodename, current->nsproxy->uts_ns->name.nodename);
                           __entry->sessionid = __get_sessionid();
                           __entry->pid_inum = __get_pid_ns_inum();
                           __entry->root_pid_inum = ROOT_PID_NS_INUM;
                           __entry->target_pid = target_pid;
                           __entry->sig = sig;
                   ),

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
)

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
                           __field(unsigned int, pid_inum)
                           __field(unsigned int, root_pid_inum)
                   ),

                   PE_fast_assign(
                           __entry->uid = __get_current_uid();
                           __assign_str(exe_path, exe_path);
                           __entry->pid = current->pid;
                           __entry->ppid = current->real_parent->tgid;
                           __entry->pgid = __get_pgid();
                           __entry->sid = __get_sid();
                           __entry->tgid = current->tgid;
                           memcpy(__entry->comm, current->comm, TASK_COMM_LEN);
                           __assign_str(nodename, current->nsproxy->uts_ns->name.nodename);
                           __entry->sessionid = __get_sessionid();
                           __entry->pid_inum = __get_pid_ns_inum();
                           __entry->root_pid_inum = ROOT_PID_NS_INUM;
                   ),

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
)

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
                           __field(unsigned int, pid_inum)
                           __field(unsigned int, root_pid_inum)
                   ),

                   PE_fast_assign(
                           __entry->uid = __get_current_uid();
                           __assign_str(exe_path, exe_path);
                           __entry->pid = current->pid;
                           __entry->ppid = current->real_parent->tgid;
                           __entry->pgid = __get_pgid();
                           __entry->sid = __get_sid();
                           __entry->tgid = current->tgid;
                           memcpy(__entry->comm, current->comm, TASK_COMM_LEN);
                           __assign_str(nodename, current->nsproxy->uts_ns->name.nodename);
                           __entry->sessionid = __get_sessionid();
                           __entry->pid_inum = __get_pid_ns_inum();
                           __entry->root_pid_inum = ROOT_PID_NS_INUM;
                   ),

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
)

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
                           __field(unsigned int, pid_inum)
                           __field(unsigned int, root_pid_inum)
                           __string(file, file)
                   ),

                   PE_fast_assign(
                           __entry->uid = __get_current_uid();
                           __assign_str(exe_path, exe_path);
                           __entry->pid = current->pid;
                           __entry->ppid = current->real_parent->tgid;
                           __entry->pgid = __get_pgid();
                           __entry->sid = __get_sid();
                           __entry->tgid = current->tgid;
                           memcpy(__entry->comm, current->comm, TASK_COMM_LEN);
                           __assign_str(nodename, current->nsproxy->uts_ns->name.nodename);
                           __entry->sessionid = __get_sessionid();
                           __entry->pid_inum = __get_pid_ns_inum();
                           __entry->root_pid_inum = ROOT_PID_NS_INUM;
                           __assign_str(file, file);
                   ),

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
)

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
                           __field(unsigned int, pid_inum)
                           __field(unsigned int, root_pid_inum)
                           __string(file, file)
                   ),

                   PE_fast_assign(
                           __entry->uid = __get_current_uid();
                           __assign_str(exe_path, exe_path);
                           __entry->pid = current->pid;
                           __entry->ppid = current->real_parent->tgid;
                           __entry->pgid = __get_pgid();
                           __entry->sid = __get_sid();
                           __entry->tgid = current->tgid;
                           memcpy(__entry->comm, current->comm, TASK_COMM_LEN);
                           __assign_str(nodename, current->nsproxy->uts_ns->name.nodename);
                           __entry->sessionid = __get_sessionid();
                           __entry->pid_inum = __get_pid_ns_inum();
                           __entry->root_pid_inum = ROOT_PID_NS_INUM;
                           __assign_str(file, file);
                   ),

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
)

PRINT_EVENT_DEFINE(write,

                   PE_PROTO(char *exe_path, char *file, char *buf),

                   PE_ARGS(exe_path, file, buf),

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
                           __field(unsigned int, pid_inum)
                           __field(unsigned int, root_pid_inum)

                           __string(file, file)
                           __string(buf, buf)
                   ),

                   PE_fast_assign(
                           __entry->uid = __get_current_uid();
                           __assign_str(exe_path, exe_path);
                           __entry->pid = current->pid;
                           __entry->ppid = current->real_parent->tgid;
                           __entry->pgid = __get_pgid();
                           __entry->sid = __get_sid();
                           __entry->tgid = current->tgid;
                           memcpy(__entry->comm, current->comm, TASK_COMM_LEN);
                           __assign_str(nodename, current->nsproxy->uts_ns->name.nodename);
                           __entry->sessionid = __get_sessionid();
                           __entry->pid_inum = __get_pid_ns_inum();
                           __entry->root_pid_inum = ROOT_PID_NS_INUM;

                           __assign_str(file, file);
                           __assign_str(buf, buf);
                   ),

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
)

PRINT_EVENT_DEFINE(mount,
                   PE_PROTO(char * exe_path, char * pid_tree, const char * dev_name, char * file_path, const char * fstype, unsigned long  flags),

                   PE_ARGS(exe_path, pid_tree, dev_name, file_path, fstype, flags),

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
                           __field(unsigned int, pid_inum)
                           __field(unsigned int, root_pid_inum)

                           __string(pid_tree, pid_tree)
                           __string(dev_name, dev_name)
                           __string(file_path, file_path)
                           __string(fstype, fstype)
                           __field(unsigned long, flags)
                   ),

                   PE_fast_assign(
                           __entry->uid = __get_current_uid();
                           __assign_str(exe_path, exe_path);
                           __entry->pid = current->pid;
                           __entry->ppid = current->real_parent->tgid;
                           __entry->pgid = __get_pgid();
                           __entry->sid = __get_sid();
                           __entry->tgid = current->tgid;
                           memcpy(__entry->comm, current->comm, TASK_COMM_LEN);
                           __assign_str(nodename, current->nsproxy->uts_ns->name.nodename);
                           __entry->sessionid = __get_sessionid();
                           __entry->pid_inum = __get_pid_ns_inum();
                           __entry->root_pid_inum = ROOT_PID_NS_INUM;

                           __assign_str(pid_tree, pid_tree);
                           __assign_str(dev_name, dev_name);
                           __assign_str(file_path, file_path);
                           __assign_str(fstype, fstype);
                           __entry->flags = flags;
                   ),

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
)

PRINT_EVENT_DEFINE(udev,
                   PE_PROTO(char * exe_path, char * product, char * manufacturer, char * serial, int action),

                   PE_ARGS(exe_path, product, manufacturer, serial, action),

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
                           __field(unsigned int, pid_inum)
                           __field(unsigned int, root_pid_inum)

                           __string(product, product)
                           __string(manufacturer, manufacturer)
                           __string(serial, serial)
                           __field(int, action)
                   ),

                   PE_fast_assign(
                           __entry->uid = __get_current_uid();
                           __assign_str(exe_path, exe_path);
                           __entry->pid = current->pid;
                           __entry->ppid = current->real_parent->tgid;
                           __entry->pgid = __get_pgid();
                           __entry->sid = __get_sid();
                           __entry->tgid = current->tgid;
                           memcpy(__entry->comm, current->comm, TASK_COMM_LEN);
                           __assign_str(nodename, current->nsproxy->uts_ns->name.nodename);
                           __entry->sessionid = __get_sessionid();
                           __entry->pid_inum = __get_pid_ns_inum();
                           __entry->root_pid_inum = ROOT_PID_NS_INUM;

                           __assign_str(product, product);
                           __assign_str(manufacturer, manufacturer);
                           __assign_str(serial, serial);
                   ),

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
)

PRINT_EVENT_DEFINE(privilege_escalation,
                   PE_PROTO(int parent_pid, char * pid_tree, char * p_cred , char * c_cred),

                   PE_ARGS(parent_pid, pid_tree, p_cred, c_cred),

                   PE_STRUCT__entry(
                           __field(int, uid)
                           __field(int, pid)
                           __field(int, ppid)
                           __field(int, pgid)
                           __field(int, tgid)
                           __field(int, sid)
                           __array(char, comm, TASK_COMM_LEN)
                           __string(nodename, current->nsproxy->uts_ns->name.nodename)
                           __field(unsigned int, sessionid)
                           __field(unsigned int, pid_inum)
                           __field(unsigned int, root_pid_inum)
                           __field(int, parent_pid)
                           __string(pid_tree, pid_tree)
                           __string(p_cred, p_cred)
                           __string(c_cred, c_cred)
                   ),

                   PE_fast_assign(
                           __entry->uid = __get_current_uid();
                           __entry->pid = current->pid;
                           __entry->ppid = current->real_parent->tgid;
                           __entry->pgid = __get_pgid();
                           __entry->sid = __get_sid();
                           __entry->tgid = current->tgid;
                           memcpy(__entry->comm, current->comm, TASK_COMM_LEN);
                           __assign_str(nodename, current->nsproxy->uts_ns->name.nodename);
                           __entry->sessionid = __get_sessionid();
                           __entry->pid_inum = __get_pid_ns_inum();
                           __entry->root_pid_inum = ROOT_PID_NS_INUM;
                           __entry->parent_pid = parent_pid;
                           __assign_str(pid_tree, pid_tree);
                           __assign_str(p_cred, p_cred);
                           __assign_str(c_cred, c_cred);
                   ),


                   PE_printk("611" RS "%d" RS "-1" RS "%d" RS "%d" RS "%d" RS "%d" RS "%d" RS "%s" RS "%s" RS "%u" RS "%u" RS "%u" RS "%d" RS "%s" RS "%s" RS "%s",
                           __get_ent(uid, __get_current_uid()),
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

                           __get_ent(parent_pid, parent_pid),
                           __get_str(pid_tree, pid_tree),
                           __get_str(p_cred, p_cred),
                           __get_str(c_cred, c_cred)
                   )
)

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 17, 0)
PRINT_EVENT_DEFINE(memfd_create,

                   PE_PROTO(char *exe_path, char *fdname, unsigned long flags),

                   PE_ARGS(exe_path, fdname, flags),

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
                           __field(unsigned int, pid_inum)
                           __field(unsigned int, root_pid_inum)
                           __string(fdname, fdname)
                           __field(unsigned long, flags)
                   ),

                   PE_fast_assign(
                           __entry->uid = __get_current_uid();
                           __assign_str(exe_path, exe_path);
                           __entry->pid = current->pid;
                           __entry->ppid = current->real_parent->tgid;
                           __entry->pgid = __get_pgid();
                           __entry->sid = __get_sid();
                           __entry->tgid = current->tgid;
                           memcpy(__entry->comm, current->comm, TASK_COMM_LEN);
                           __assign_str(nodename, current->nsproxy->uts_ns->name.nodename);
                           __entry->sessionid = __get_sessionid();
                           __entry->pid_inum = __get_pid_ns_inum();
                           __entry->root_pid_inum = ROOT_PID_NS_INUM;
                           __assign_str(fdname, fdname);
                           __entry->flags = flags;
                   ),

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
)
#endif

/* Port Scan Attack Detector for ipv4 (tcp) */
PRINT_EVENT_DEFINE(psad4,

                   PE_PROTO(__be32 sip, int sport, __be32 dip, int dport, int flags),

                   PE_ARGS(sip, sport, dip, dport, flags),

                   PE_STRUCT__entry(
                           __field(__be32, sip)
                           __field(int, sport)
                           __field(__be32, dip)
                           __field(int, dport)
                           __field(int, flags)
                   ),

                   PE_fast_assign(
                           __entry->sip = sip;
                           __entry->sport = sport;
                           __entry->dip = dip;
                           __entry->dport = dport;
                           __entry->flags = flags;
                   ),

                   PE_printk("612" RS "2" RS "%d.%d.%d.%d" RS "%d" RS "%d.%d.%d.%d" RS "%d" RS "%d",
                           NIPQUAD(__get_ent(sip, sip)),
                           __get_ent(sport, sport),
                           NIPQUAD(__get_ent(dip, dip)),
                           __get_ent(dport, dport),
                           __get_ent(flags, flags)
                   )
)

#if IS_ENABLED(CONFIG_IPV6)
PRINT_EVENT_DEFINE(psad6,

                   PE_PROTO(const struct in6_addr *sip, int sport, const struct in6_addr *dip, int dport, int flags),

                   PE_ARGS(sip, sport, dip, dport, flags),

                   PE_STRUCT__entry(
                           __field(struct in6_addr, sip)
                           __field(int, sport)
                           __field(struct in6_addr, dip)
                           __field(int, dport)
                           __field(int, flags)
                   ),

                   PE_fast_assign(
                           memcpy(&__entry->sip, sip, sizeof(*sip));
                           memcpy(&__entry->dip, dip, sizeof(*dip));
                           __entry->sport = sport;
                           __entry->dport = dport;
                           __entry->flags = flags;
                   ),

                   PE_printk("612" RS "10" RS "%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x" RS "%d" RS "%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x" RS "%d" RS "%d",
                           NIP6(__get_ent(sip, sip)),
                           __get_ent(sport, sport),
                           NIP6(__get_ent(dip, dip)),
                           __get_ent(dport, dport),
                           __get_ent(flags, flags)
                   )
)
#endif

#endif /* _KPROBE_PRINT_H */

/* This part must be outside protection */
#include "define_trace.h"

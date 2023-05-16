/* SPDX-License-Identifier: GPL-2.0 */

#ifndef ENTRY_COMMON
#define ENTRY_COMMON(xid)                                                       \
                     ENTRY_XID(xid),                                            \
                     ENTRY_U32(uid, __tid->xids.uid),                           \
                     ENTRY_STL(exe_path, __tid->exe_path, __tid->exe_path_len), \
                     ENTRY_U32(pid, (pid_t)bpf_get_current_pid_tgid()),         \
                     ENTRY_U32(ppid, __tid->ppid),                              \
                     ENTRY_U32(pgid, __tid->pgid),                              \
                     ENTRY_U32(tgid, (pid_t)(bpf_get_current_pid_tgid() >> 32)),\
                     ENTRY_U32(sid, __tid->sid),                                \
                     ENTRY_U32(epoch, __tid->epoch),                            \
                     ENTRY_STL(comm, __tid->comm, TASK_COMM_LEN),               \
                     ENTRY_STL(nodename, __tid->node, __tid->node_len),         \
                     ENTRY_U64(mntns_id, __tid->mntns_id),                      \
                     ENTRY_U64(root_mntns_id, __tid->root_mntns_id)
#endif

SD_XFER_DEFINE( NAME(prctl),

                PROT(ELEMENT(void *, ctx),
                     ELEMENT(int, option),
                     ELEMENT(char *, newname),
                     ELEMENT(int, newname_len)
                ),

                XFER(ENTRY_COMMON(157),
                     ENTRY_INT(option, option),
                     ENTRY_STL(newname, newname, newname_len)
                )
)

SD_XFER_DEFINE( NAME(execve0),

                PROT(ELEMENT(void *, ctx),
                     ELEMENT(char *, cwd),
                     ELEMENT(int, cwd_len),
                     ELEMENT(char *, tmp_stdin),
                     ELEMENT(int, in_len),
                     ELEMENT(char *, tmp_stdout),
                     ELEMENT(int, out_len),
                     ELEMENT(char *, tty_name),
                     ELEMENT(int, tty_len),
                     ELEMENT(char *, ssh_conn),
                     ELEMENT(int, ssh_conn_len),
                     ELEMENT(char *, ld_preload),
                     ELEMENT(int, ld_preload_len),
                     ELEMENT(char *, ld_lib_path),
                     ELEMENT(int, ld_lib_path_len),
                     ELEMENT(int, retval)
                ),

                XFER(ENTRY_COMMON(59),
                     ENTRY_STL(args, __tid->args, __tid->args_len),
                     ENTRY_STL(cwd, cwd, cwd_len),
                     ENTRY_STL(tmp_stdin, tmp_stdin, in_len), /* max 256 */
                     ENTRY_STL(tmp_stdout, tmp_stdout, out_len),
                     ENTRY_S8(dip, -1),
                     ENTRY_S8(dport, -1),
                     ENTRY_S8(sip, -1),
                     ENTRY_S8(sport, -1),
                     ENTRY_S16(sa_family, -1),
                     ENTRY_STL(pidtree, __tid->pidtree, __tid->pidtree_len),
                     ENTRY_STL(tty_name, tty_name, tty_len), /* max 64 */
                     ENTRY_S32(socket_pid, -1),
                     ENTRY_STL(ssh_conn, ssh_conn, ssh_conn_len),
                     ENTRY_STL(ld_preload, ld_preload, ld_preload_len),
                     ENTRY_STL(ld_lib_path, ld_lib_path, ld_lib_path_len),
                     ENTRY_INT(retval, retval)
                )
)

SD_XFER_DEFINE( NAME(execve4),

                PROT(ELEMENT(void *, ctx),
                     ELEMENT(char *, cwd),
                     ELEMENT(int, cwd_len),
                     ELEMENT(char *, tmp_stdin),
                     ELEMENT(int, in_len),
                     ELEMENT(char *, tmp_stdout),
                     ELEMENT(int, out_len),
                     ELEMENT(__be32, dip),
                     ELEMENT(int, dport),
                     ELEMENT(__be32, sip),
                     ELEMENT(int, sport),
                     ELEMENT(int, socket_pid),
                     ELEMENT(char *, tty_name),
                     ELEMENT(int, tty_len),
                     ELEMENT(char *, ssh_conn),
                     ELEMENT(int, ssh_conn_len),
                     ELEMENT(char *, ld_preload),
                     ELEMENT(int, ld_preload_len),
                     ELEMENT(char *, ld_lib_path),
                     ELEMENT(int, ld_lib_path_len),
                     ELEMENT(int, retval)
                ),

                XFER(ENTRY_COMMON(59),
                     ENTRY_STL(args, __tid->args, __tid->args_len),
                     ENTRY_STL(cwd, cwd, cwd_len),
                     ENTRY_STL(tmp_stdin, tmp_stdin, in_len), /* max 256 */
                     ENTRY_STL(tmp_stdout, tmp_stdout, out_len),
                     ENTRY_IP4(dip, dip),
                     ENTRY_U16(dport, dport),
                     ENTRY_IP4(sip, sip),
                     ENTRY_U16(sport, sport),
                     ENTRY_U16(sa_family, 2),
                     ENTRY_STL(pidtree, __tid->pidtree, __tid->pidtree_len),
                     ENTRY_STL(tty_name, tty_name, tty_len), /* max 64 */
                     ENTRY_S32(socket_pid, socket_pid),
                     ENTRY_STL(ssh_conn, ssh_conn, ssh_conn_len),
                     ENTRY_STL(ld_preload, ld_preload, ld_preload_len),
                     ENTRY_STL(ld_lib_path, ld_lib_path, ld_lib_path_len),
                     ENTRY_INT(retval, retval)
                )
)

#if IS_ENABLED(CONFIG_IPV6)
SD_XFER_DEFINE( NAME(execve6),

                PROT(ELEMENT(void *, ctx),
                     ELEMENT(char *, cwd),
                     ELEMENT(int, cwd_len),
                     ELEMENT(char *, tmp_stdin),
                     ELEMENT(int, in_len),
                     ELEMENT(char *, tmp_stdout),
                     ELEMENT(int, out_len),
                     ELEMENT(struct in6_addr *, dip),
                     ELEMENT(int, dport),
                     ELEMENT(struct in6_addr *, sip),
                     ELEMENT(int, sport),
                     ELEMENT(int, socket_pid),
                     ELEMENT(char *, tty_name),
                     ELEMENT(int, tty_len),
                     ELEMENT(char *, ssh_conn),
                     ELEMENT(int, ssh_conn_len),
                     ELEMENT(char *, ld_preload),
                     ELEMENT(int, ld_preload_len),
                     ELEMENT(char *, ld_lib_path),
                     ELEMENT(int, ld_lib_path_len),
                     ELEMENT(int, retval)
                ),

                XFER(ENTRY_COMMON(59),
                     ENTRY_STL(args, __tid->args, __tid->args_len),
                     ENTRY_STL(cwd, cwd, cwd_len),
                     ENTRY_STL(tmp_stdin, tmp_stdin, in_len), /* max 256 */
                     ENTRY_STL(tmp_stdout, tmp_stdout, out_len),
                     ENTRY_IP6(dip, dip),
                     ENTRY_U16(dport, dport),
                     ENTRY_IP6(sip, sip),
                     ENTRY_U16(sport, sport),
                     ENTRY_U16(sa_family, 10),
                     ENTRY_STL(pidtree, __tid->pidtree, __tid->pidtree_len),
                     ENTRY_STL(tty_name, tty_name, tty_len), /* max 64 */
                     ENTRY_S32(socket_pid, socket_pid),
                     ENTRY_STL(ssh_conn, ssh_conn, ssh_conn_len),
                     ENTRY_STL(ld_preload, ld_preload, ld_preload_len),
                     ENTRY_STL(ld_lib_path, ld_lib_path, ld_lib_path_len),
                     ENTRY_INT(retval, retval)
                )
)
#endif

SD_XFER_DEFINE( NAME(connect4),

                PROT(ELEMENT(void *, ctx),
                     ELEMENT(__be32, dip),
                     ELEMENT(int, dport),
                     ELEMENT(__be32, sip),
                     ELEMENT(int, sport),
                     ELEMENT(int, retval)
                 ),

                XFER(ENTRY_COMMON(42),
                     ENTRY_U16(sa_family, 2),
                     ENTRY_IP4(dip, dip),
                     ENTRY_U16(dport, dport),
                     ENTRY_IP4(sip, sip),
                     ENTRY_U16(sport, sport),
                     ENTRY_INT(retval, retval),
                     ENTRY_STL(pidtree, __tid->pidtree, __tid->pidtree_len)
                )
)

#if IS_ENABLED(CONFIG_IPV6)
SD_XFER_DEFINE( NAME(connect6),

                PROT(ELEMENT(void *, ctx),
                     ELEMENT(struct in6_addr *, dip),
                     ELEMENT(int, dport),
                     ELEMENT(struct in6_addr *, sip),
                     ELEMENT(int, sport),
                     ELEMENT(int, retval)
                 ),

                XFER(ENTRY_COMMON(42),
                     ENTRY_U16(sa_family, 10),
                     ENTRY_IP6(dip, dip),
                     ENTRY_U16(dport, dport),
                     ENTRY_IP6(sip, sip),
                     ENTRY_U16(sport, sport),
                     ENTRY_INT(retval, retval),
                     ENTRY_STL(pidtree, __tid->pidtree, __tid->pidtree_len)
                )
)
#endif

SD_XFER_DEFINE( NAME(dns4),

                PROT(ELEMENT(void *, ctx),
                     ELEMENT(__be32, dip),
                     ELEMENT(int, dport),
                     ELEMENT(__be32, sip),
                     ELEMENT(int, sport),
                     ELEMENT(int, opcode),
                     ELEMENT(int, rcode),
                     ELEMENT(char *, dom),
                     ELEMENT(int, dom_len),
                     ELEMENT(int, type)
                ),

                XFER(ENTRY_COMMON(601),
                     ENTRY_STL(dom, dom, dom_len),
                     ENTRY_U16(sa_family, 2),
                     ENTRY_IP4(dip, dip),
                     ENTRY_U16(dport, dport),
                     ENTRY_IP4(sip, sip),
                     ENTRY_U16(sport, sport),
                     ENTRY_INT(opcode, opcode),
                     ENTRY_INT(rcode, rcode),
                     ENTRY_INT(type, type),
                     ENTRY_STL(pidtree, __tid->pidtree, __tid->pidtree_len)
                )
)

#if IS_ENABLED(CONFIG_IPV6)
SD_XFER_DEFINE( NAME(dns6),

                PROT(ELEMENT(void *, ctx),
                     ELEMENT(struct in6_addr *, dip),
                     ELEMENT(int, dport),
                     ELEMENT(struct in6_addr *, sip),
                     ELEMENT(int, sport),
                     ELEMENT(int, opcode),
                     ELEMENT(int, rcode),
                     ELEMENT(char *, name),
                     ELEMENT(int, name_len),
                     ELEMENT(int, type)
                ),

                XFER(ENTRY_COMMON(601),
                     ENTRY_STL(name, name, name_len),
                     ENTRY_U16(sa_family, 10),
                     POINTER_IP6(dip, dip),
                     ENTRY_U16(dport, dport),
                     POINTER_IP6(sip, sip),
                     ENTRY_U16(sport, sport),
                     ENTRY_INT(opcode, opcode),
                     ENTRY_INT(rcode, rcode),
                     ENTRY_INT(type, type),
                     ENTRY_STL(pidtree, __tid->pidtree, __tid->pidtree_len)
                )
)
#endif

SD_XFER_DEFINE( NAME(create4),

                PROT(ELEMENT(void *, ctx),
                     ELEMENT(char *, pathstr),
                     ELEMENT(int, pathstr_len),
                     ELEMENT(__be32, dip),
                     ELEMENT(int, dport),
                     ELEMENT(__be32, sip),
                     ELEMENT(int, sport),
                     ELEMENT(pid_t, socket_pid),
                     ELEMENT(char *, s_id)
                ),

                XFER(ENTRY_COMMON(602),
                     ENTRY_STL(pathstr, pathstr, pathstr_len),
                     ENTRY_IP4(dip, dip),
                     ENTRY_U16(dport, dport),
                     ENTRY_IP4(sip, sip),
                     ENTRY_U16(sport, sport),
                     ENTRY_U16(sa_family, 2),
                     ENTRY_U32(socket_pid, socket_pid),
                     ENTRY_STL(s_id, s_id, 32),
                     ENTRY_STL(pidtree, __tid->pidtree, __tid->pidtree_len)
                )
)

SD_XFER_DEFINE( NAME(create0),

                PROT(ELEMENT(void *, ctx),
                     ELEMENT(char *, pathstr),
                     ELEMENT(int, pathstr_len),
                     ELEMENT(char *, s_id)
                ),

                XFER(ENTRY_COMMON(602),
                     ENTRY_STL(pathstr, pathstr, pathstr_len),
                     ENTRY_S8(dip, -1),
                     ENTRY_S8(dport, -1),
                     ENTRY_S8(sip, -1),
                     ENTRY_S8(sport, -1),
                     ENTRY_S8(sa_family, -1),
                     ENTRY_S8(socket_pid, -1),
                     ENTRY_STL(s_id, s_id, 32),
                     ENTRY_STL(pidtree, __tid->pidtree, __tid->pidtree_len)
                )
)

#if IS_ENABLED(CONFIG_IPV6)
SD_XFER_DEFINE( NAME(create6),

                PROT(ELEMENT(void *, ctx),
                     ELEMENT(char *, pathstr),
                     ELEMENT(int, pathstr_len),
                     ELEMENT(struct in6_addr *, dip),
                     ELEMENT(int, dport),
                     ELEMENT(struct in6_addr *, sip),
                     ELEMENT(int, sport),
                     ELEMENT(pid_t, socket_pid),
                     ELEMENT(char *, s_id)
                ),

                XFER(ENTRY_COMMON(602),
                     ENTRY_STL(pathstr, pathstr, pathstr_len),
                     ENTRY_IP6(dip, dip),
                     ENTRY_U16(dport, dport),
                     ENTRY_IP6(sip, sip),
                     ENTRY_U16(sport, sport),
                     ENTRY_U16(sa_family, 10),
                     ENTRY_U32(socket_pid, socket_pid),
                     ENTRY_STL(s_id, s_id, 32),
                     ENTRY_STL(pidtree, __tid->pidtree, __tid->pidtree_len)
                )
)
#endif

SD_XFER_DEFINE( NAME(rename),

                PROT(ELEMENT(void *, ctx),
                     ELEMENT(char *, oldname),
                     ELEMENT(int, oldname_len),
                     ELEMENT(char *, newname),
                     ELEMENT(int, newname_len),
                     ELEMENT(char *, s_id)
                ),

                XFER(ENTRY_COMMON(82),
                     ENTRY_STL(oldname, oldname, oldname_len),
                     ENTRY_STL(newname, newname, newname_len),
                     ENTRY_STL(s_id, s_id, 32)
                )
)

SD_XFER_DEFINE( NAME(link),

                PROT(ELEMENT(void *, ctx),
                     ELEMENT(char *, oldname),
                     ELEMENT(int, oldname_len),
                     ELEMENT(char *, newname),
                     ELEMENT(int, newname_len),
                     ELEMENT(char *, s_id)
                ),

                XFER(ENTRY_COMMON(86),
                     ENTRY_STL(oldname, oldname, oldname_len),
                     ENTRY_STL(newname, newname, newname_len),
                     ENTRY_STL(s_id, s_id, 32)
                )
)

SD_XFER_DEFINE( NAME(bind4),

                PROT(ELEMENT(void *, ctx),
                     ELEMENT(__be32, sip),
                     ELEMENT(int, sport),
                     ELEMENT(int, retval)
                ),

                XFER(ENTRY_COMMON(49),
                     ENTRY_U16(sa_family, 2),
                     ENTRY_IP4(sip, sip),
                     ENTRY_U16(sport, sport),
                     ENTRY_INT(retval, retval),
                     ENTRY_STL(pidtree, __tid->pidtree, __tid->pidtree_len)
                )
)

#if IS_ENABLED(CONFIG_IPV6)
SD_XFER_DEFINE( NAME(bind6),

                PROT(ELEMENT(void *, ctx),
                     ELEMENT(struct in6_addr *, in6_addr),
                     ELEMENT(int, sport),
                     ELEMENT(int, retval)
                ),

                XFER(ENTRY_COMMON(49),
                     ENTRY_U16(sa_family, 10),
                     ENTRY_IP6(in6_addr, in6_addr),
                     ENTRY_U16(sport, sport),
                     ENTRY_INT(retval, retval),
                     ENTRY_STL(pidtree, __tid->pidtree, __tid->pidtree_len)
                )
)
#endif

SD_XFER_DEFINE( NAME(accept4),

                PROT(ELEMENT(void *, ctx),
                     ELEMENT(__be32, dip),
                     ELEMENT(int, dport),
                     ELEMENT(__be32, sip),
                     ELEMENT(int, sport),
                     ELEMENT(int, retval)
                ),

                XFER(ENTRY_COMMON(43),
                     ENTRY_U16(sa_family, 2),
                     ENTRY_IP4(dip, dip),
                     ENTRY_U16(dport, dport),
                     ENTRY_IP4(sip, sip),
                     ENTRY_U16(sport, sport),
                     ENTRY_INT(retval, retval)
                )
)

#if IS_ENABLED(CONFIG_IPV6)
SD_XFER_DEFINE( NAME(accept6),

                PROT(ELEMENT(void *, ctx),
                     ELEMENT(struct in6_addr *, dip),
                     ELEMENT(int, dport),
                     ELEMENT(struct in6_addr *, sip),
                     ELEMENT(int, sport),
                     ELEMENT(int, retval)
                ),

                XFER(ENTRY_COMMON(43),
                     ENTRY_U16(sa_family, 10),
                     ENTRY_IP6(dip, dip),
                     ENTRY_U16(dport, dport),
                     ENTRY_IP6(sip, sip),
                     ENTRY_U16(sport, sport),
                     ENTRY_INT(retval, retval)
                )
)
#endif

SD_XFER_DEFINE( NAME(call_usermodehelper_exec),

                PROT(ELEMENT(void *, ctx),
                     ELEMENT(char *, exe),
                     ELEMENT(int, exe_len),
                     ELEMENT(char *, argv),
                     ELEMENT(int, argv_len),
                     ELEMENT(int, wait)
                ),

                XFER(ENTRY_XID(607),
                     ENTRY_STL(exe, exe, exe_len),
                     ENTRY_STL(argv, argv, argv_len),
                     ENTRY_INT(wait, wait)
                )
)

SD_XFER_DEFINE( NAME(init_module),

                PROT(ELEMENT(void *, ctx),
                     ELEMENT(char *, mod),
                     ELEMENT(int, mod_len),
                     ELEMENT(char *, pwd),
                     ELEMENT(int, pwd_len)
                ),

                XFER(ENTRY_COMMON(603),
                     ENTRY_STL(mod, mod, mod_len),
                     ENTRY_STL(pidtree, __tid->pidtree, __tid->pidtree_len),
                     ENTRY_STL(pwd, pwd, pwd_len)
                )
)

SD_XFER_DEFINE( NAME(mount),

                PROT(ELEMENT(void *, ctx),
                     ELEMENT(char *, dev_name),
                     ELEMENT(int, dev_len),
                     ELEMENT(char *, file_path),
                     ELEMENT(int, path_len),
                     ELEMENT(char *, fsid),
                     ELEMENT(char *, fstype),
                     ELEMENT(int, type_len),
                     ELEMENT(unsigned long, flags),
                     ELEMENT(char *, option),
                     ELEMENT(int, option_len)
                ),

                XFER(ENTRY_COMMON(165),
                     ENTRY_STL(pidtree, __tid->pidtree, __tid->pidtree_len),
                     ENTRY_STL(dev_name, dev_name, dev_len),
                     ENTRY_STL(file_path, file_path, path_len),
                     ENTRY_STL(fsid, fsid, 32),
                     ENTRY_STL(fstype, fstype, type_len),
                     ENTRY_INT(flags, flags),
                     ENTRY_STL(option, option, option_len)
                )
)


SD_XFER_DEFINE( NAME(ptrace),

                PROT(ELEMENT(void *, ctx),
                     ELEMENT(long, request),
                     ELEMENT(long, owner_pid),
                     ELEMENT(void *, addr),
                     ELEMENT(char *, data_res),
                     ELEMENT(int, data_len)
                ),

                XFER(ENTRY_COMMON(101),
                     ENTRY_INT(request, request),
                     ENTRY_U32(owner_pid, owner_pid),
                     ENTRY_ULONG(addr, (unsigned long)addr),
                     ENTRY_STL(data_res, data_res, data_len),
                     ENTRY_STL(pidtree, __tid->pidtree, __tid->pidtree_len)
                )
)

SD_XFER_DEFINE( NAME(memfd_create),

                PROT(ELEMENT(void *, ctx),
                     ELEMENT(char *, fdname),
                     ELEMENT(int, name_len),
                     ELEMENT(unsigned long, flags)
                ),

                XFER(ENTRY_COMMON(356),
                     ENTRY_STL(fdname, fdname, name_len),
                     ENTRY_INT(flags, flags)
                )
)

SD_XFER_DEFINE( NAME(setsid),

                PROT(ELEMENT(void *, ctx),
                     ELEMENT(int, newsid)
                ),

                XFER(ENTRY_COMMON(112),
                     ENTRY_INT(newsid, newsid),
                     ENTRY_STL(pidtree, __tid->pidtree, __tid->pidtree_len)
                )
)

SD_XFER_DEFINE( NAME(commit_creds),

                PROT(ELEMENT(void *, ctx),
                     ELEMENT(int, v_uid),
                     ELEMENT(int, v_euid)
                ),

                XFER(ENTRY_COMMON(604),
                     ENTRY_STL(pidtree, __tid->pidtree, __tid->pidtree_len),
                     ENTRY_U32(v_uid, v_uid),
                     ENTRY_INT(v_euid, v_euid)
                )
)

SD_XFER_DEFINE( NAME(privilege_escalation),

                PROT(ELEMENT(void *, ctx),
                     ELEMENT(int, task_pid),
                     ELEMENT(struct cred_xids *, p_cred),
                     ELEMENT(struct cred_xids *, c_cred)
                ),

                XFER(ENTRY_COMMON(611),
                     ENTRY_INT(task_pid, task_pid),
                     ENTRY_STL(pidtree, __tid->pidtree, __tid->pidtree_len),
                     ENTRY_XIDS(p_cred, p_cred),
                     ENTRY_XIDS(c_cred, c_cred)
                )
)

#if 0 /* TODO for phase 3 */

SD_XFER_DEFINE( NAME(udev),

                PROT(ELEMENT(void *, ctx),
                     ELEMENT(char *, product),
                     ELEMENT(int, prod_len),
                     ELEMENT(char *, manufacturer),
                     ELEMENT(int, manu_len),
                     ELEMENT(char *, serial),
                     ELEMENT(int, serial_len),
                     ELEMENT(int, action)
                ),

                XFER(ENTRY_COMMON(610),
                     ENTRY_STL(product, product, prod_len),
                     ENTRY_STL(manufacturer, manufacturer, manu_len),
                     ENTRY_STL(serial, serial, serial_len),
                     ENTRY_INT(action, action)
                )
)

SD_XFER_DEFINE( NAME(mprotect),

                PROT(ELEMENT(char *, exe_path),
                     ELEMENT(unsigned long, prot),
                     ELEMENT(char *, owner_file),
                     ELEMENT(int, owner_pid),
                     ELEMENT(char *, vm_file),
                     ELEMENT(char *, pid_tree)
                ),

                XFER(ENTRY_COMMON(10),
                     ENTRY_U32(prot, prot),
                     ENTRY_U32(owner_pid, owner_pid),
                     ENTRY_STR(owner_file, owner_file),
                     ENTRY_STR(vm_file, vm_file),
                     ENTRY_STR(pid_tree, pid_tree)
                )
)

SD_XFER_DEFINE( NAME(open),

                PROT(ELEMENT(char *, exe_path),
                     ELEMENT(char *, filename),
                     ELEMENT(int, flags),
                     ELEMENT(umode_t, mode)
                ),

                XFER(ENTRY_COMMON(2),
                     ENTRY_INT(flags, flags),
                     ENTRY_INT(mode, mode),
                     ENTRY_STR(filename, filename)
                )
)

SD_XFER_DEFINE( NAME(nanosleep),

                PROT(ELEMENT(char *, exe_path),
                     ELEMENT(long long, sec),
                     ELEMENT(long, nsec)
                ),

                XFER(ENTRY_COMMON(35),
                     ENTRY_INT(sec, sec),
                     ENTRY_INT(nsec, nsec)
                )
)

SD_XFER_DEFINE( NAME(kill),

                PROT(ELEMENT(char *, exe_path),
                     ELEMENT(int, killpid),
                     ELEMENT(int, killsig),
                     ELEMENT(int, killret)
                ),

                XFER(ENTRY_COMMON(62),
                     ENTRY_INT(killpid, killpid),
                     ENTRY_INT(killsig, killsig),
                     ENTRY_INT(killret, killret)
                )
)

SD_XFER_DEFINE( NAME(tkill),

                PROT(ELEMENT(char *, exe_path),
                     ELEMENT(int, killtid),
                     ELEMENT(int, killsig),
                     ELEMENT(int, killret)
                ),

                XFER(ENTRY_COMMON(200),
                     ENTRY_INT(killtid, killtid),
                     ENTRY_INT(killsig, killsig),
                     ENTRY_INT(killret, killret)
                )
)

SD_XFER_DEFINE( NAME(tgkill),

                PROT(ELEMENT(char *, exe_path),
                     ELEMENT(int, kiltgid),
                     ELEMENT(int, killtid),
                     ELEMENT(int, killsig),
                     ELEMENT(int, killret)
                ),

                XFER(ENTRY_COMMON(201),
                     ENTRY_INT(kiltgid, kiltgid),
                     ENTRY_INT(killtid, killtid),
                     ENTRY_INT(killsig, killsig),
                     ENTRY_INT(killret, killret)
                )
)

SD_XFER_DEFINE( NAME(exit),

                PROT(ELEMENT(char *, exe_path)),

                XFER(ENTRY_COMMON(60))
)

SD_XFER_DEFINE( NAME(exit_group),

                PROT(ELEMENT(char *, exe_path)),

                XFER(ENTRY_COMMON(231))
)

SD_XFER_DEFINE( NAME(security_path_rmdir),

                PROT(ELEMENT(char *, exe_path), ELEMENT(char *, file)),

                XFER(ENTRY_COMMON(606), ENTRY_STR(file, file))
)

SD_XFER_DEFINE( NAME(security_path_unlink),

                PROT(ELEMENT(char *, exe_path), ELEMENT(char *, file)),

                XFER(ENTRY_COMMON(605), ENTRY_STR(file, file))
)

SD_XFER_DEFINE( NAME(write),

                PROT(ELEMENT(char *, exe_path),
                     ELEMENT(char *, file),
                     ELEMENT(char *, buf),
                     ELEMENT(int, len)
                ),

                XFER(ENTRY_COMMON(1),
                     ENTRY_STR(file, file),
                     ENTRY_STL(buf, buf, len)
               )
)

SD_XFER_DEFINE( NAME(file_permission_write),

                PROT(ELEMENT(char *, exe_path), ELEMENT(char *, file), ELEMENT(char *, s_id)),

                XFER(ENTRY_COMMON(608), ENTRY_STR(file, file), ENTRY_STL(s_id, s_id, 32))
)

SD_XFER_DEFINE( NAME(file_permission_read),

                PROT(ELEMENT(char *, exe_path), ELEMENT(char *, file), ELEMENT(char *, s_id)),

                XFER(ENTRY_COMMON(609), ENTRY_STR(file, file), ENTRY_STL(s_id, s_id, 32))
)

SD_XFER_DEFINE( NAME(chmod),
                PROT(ELEMENT(char *, exe_path),
                     ELEMENT(char *, pid_tree),
                     ELEMENT(char *, file_path),
                     ELEMENT(char *, fsid),
                     ELEMENT(int, mode),
                     ELEMENT(int, retval)
                ),

                XFER(ENTRY_COMMON(90),
                     ENTRY_STR(pid_tree, pid_tree),
                     ENTRY_STR(file_path, file_path),
                     ENTRY_STL(fsid, fsid, 32),
                     ENTRY_INT(mode, mode),
                     ENTRY_INT(retval, retval)
                )
)

#endif

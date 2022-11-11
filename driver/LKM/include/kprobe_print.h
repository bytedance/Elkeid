/* SPDX-License-Identifier: GPL-2.0 */

#ifndef ENTRY_COMMON
#define ENTRY_COMMON(xid)                                                           \
                     ENTRY_XID(xid),                                                \
                     ENTRY_U32(uid, __get_current_uid()),                           \
                     ENTRY_STR(exe_path, exe_path),                                 \
                     ENTRY_U32(pid, current->pid),                                  \
                     ENTRY_U32(ppid, current->real_parent->tgid),                   \
                     ENTRY_U32(pgid, __get_pgid()),                                 \
                     ENTRY_U32(tgid, current->tgid),                                \
                     ENTRY_U32(sid, __get_sid()),                                   \
                     ENTRY_U32(epoch, smith_query_sid()),                           \
                     ENTRY_STL(comm, current->comm, TASK_COMM_LEN),                 \
                     ENTRY_STL(nodename, current->nsproxy->uts_ns->name.nodename, __NEW_UTS_LEN),\
                     ENTRY_U64(mntns_id, smith_query_mntns()),                      \
                     ENTRY_U64(root_mntns_id, ROOT_MNT_NS_ID)
#endif

SD_XFER_DEFINE( NAME(call_usermodehelper_exec),

                PROT(ELEMENT(char *, exe),
                     ELEMENT(char *, argv),
                     ELEMENT(int, wait)
                ),

                XFER(ENTRY_XID(607),
                     ENTRY_STR(exe, exe),
                     ENTRY_STR(argv, argv),
                     ENTRY_INT(wait, wait)
                )
)

SD_XFER_DEFINE( NAME(security_inode4_create),

                PROT(ELEMENT(char *, exe_path),
                     ELEMENT(char *, pathstr),
                     ELEMENT(__be32, dip),
                     ELEMENT(int, dport),
                     ELEMENT(__be32, sip),
                     ELEMENT(int, sport),
                     ELEMENT(pid_t, socket_pid),
                     ELEMENT(char *, s_id),
                     ELEMENT(char *, pid_tree)
                ),

                XFER(ENTRY_COMMON(602),
                     ENTRY_STR(pathstr, pathstr),
                     ENTRY_IP4(dip, dip),
                     ENTRY_U16(dport, dport),
                     ENTRY_IP4(sip, sip),
                     ENTRY_U16(sport, sport),
                     ENTRY_U16(sa_family, 2),
                     ENTRY_U32(socket_pid, socket_pid),
                     ENTRY_STL(s_id, s_id, 32),
                     ENTRY_STR(pid_tree, pid_tree)
                )
)

SD_XFER_DEFINE( NAME(security_inode_create_nosocket),

                PROT(ELEMENT(char *, exe_path),
                     ELEMENT(char *, pathstr),
                     ELEMENT(char *, s_id),
                     ELEMENT(char *, pid_tree)
                ),

                XFER(ENTRY_COMMON(602),
                     ENTRY_STR(pathstr, pathstr),
                     ENTRY_S8(dip, -1),
                     ENTRY_S8(dport, -1),
                     ENTRY_S8(sip, -1),
                     ENTRY_S8(sport, -1),
                     ENTRY_S8(sa_family, -1),
                     ENTRY_S8(socket_pid, -1),
                     ENTRY_STL(s_id, s_id, 32),
                     ENTRY_STR(pid_tree, pid_tree)
                )
)


#if IS_ENABLED(CONFIG_IPV6)
SD_XFER_DEFINE( NAME(security_inode6_create),

                PROT(ELEMENT(char *, exe_path),
                     ELEMENT(char *, pathstr),
                     ELEMENT(struct in6_addr *, dip),
                     ELEMENT(int, dport),
                     ELEMENT(struct in6_addr *, sip),
                     ELEMENT(int, sport),
                     ELEMENT(pid_t, socket_pid),
                     ELEMENT(char, * s_id),
                     ELEMENT(char *, pid_tree)
                ),

                XFER(ENTRY_COMMON(602),
                     ENTRY_STR(pathstr, pathstr),
                     ENTRY_IP6(dip, dip),
                     ENTRY_U16(dport, dport),
                     ENTRY_IP6(sip, sip),
                     ENTRY_U16(sport, sport),
                     ENTRY_U16(sa_family, 10),
                     ENTRY_U32(socket_pid, socket_pid),
                     ENTRY_STL(s_id, s_id, 32),
                     ENTRY_STR(pid_tree, pid_tree)
                )
)
#endif

SD_XFER_DEFINE( NAME(dns),

                PROT(ELEMENT(int, dport),
                     ELEMENT(__be32, dip),
                     ELEMENT(char *, exe_path),
                     ELEMENT(__be32, sip),
                     ELEMENT(int, sport),
                     ELEMENT(int, opcode),
                     ELEMENT(int, rcode),
                     ELEMENT(char *, query),
                     ELEMENT(int, type),
                     ELEMENT(char *, pid_tree)
                ),

                XFER(ENTRY_COMMON(601),
                     ENTRY_STR(query, query),
                     ENTRY_U16(sa_family, 2),
                     ENTRY_IP4(dip, dip),
                     ENTRY_U16(dport, dport),
                     ENTRY_IP4(sip, sip),
                     ENTRY_U16(sport, sport),
                     ENTRY_INT(opcode, opcode),
                     ENTRY_INT(rcode, rcode),
                     ENTRY_INT(type, type),
                     ENTRY_STR(pid_tree, pid_tree)
                   )
)

#if IS_ENABLED(CONFIG_IPV6)
SD_XFER_DEFINE( NAME(dns6),

                PROT(ELEMENT(int, dport),
                     ELEMENT(struct in6_addr *, dip),
                     ELEMENT(char *, exe_path),
                     ELEMENT(struct in6_addr *, sip),
                     ELEMENT(int, sport),
                     ELEMENT(int, opcode),
                     ELEMENT(int, rcode),
                     ELEMENT(char *, query),
                     ELEMENT(int, type),
                     ELEMENT(char *, pid_tree)
                ),

                XFER(ENTRY_COMMON(601),
                     ENTRY_STR(query, query),
                     ENTRY_U16(sa_family, 10),
                     POINTER_IP6(dip, dip),
                     ENTRY_U16(dport, dport),
                     POINTER_IP6(sip, sip),
                     ENTRY_U16(sport, sport),
                     ENTRY_INT(opcode, opcode),
                     ENTRY_INT(rcode, rcode),
                     ENTRY_INT(type, type),
                     ENTRY_STR(pid_tree, pid_tree)
                )
)
#endif

SD_XFER_DEFINE( NAME(execve),

                PROT(ELEMENT(char *, pname),
                     ELEMENT(char *, exe_path),
                     ELEMENT(char *, argv),
                     ELEMENT(char *, tmp_stdin),
                     ELEMENT(char *, tmp_stdout),
                     ELEMENT(__be32, dip),
                     ELEMENT(int, dport),
                     ELEMENT(__be32, sip),
                     ELEMENT(int, sport),
                     ELEMENT(char *, pid_tree),
                     ELEMENT(char *, tty_name),
                     ELEMENT(pid_t, socket_pid),
                     ELEMENT(char *, ssh_connection),
                     ELEMENT(char *, ld_preload),
                     ELEMENT(char *, ld_library_path),
                     ELEMENT(int, retval)
                ),

                XFER(ENTRY_COMMON(59),
                     ENTRY_STR(argv, argv),
                     ENTRY_STR(pname, pname),
                     ENTRY_STR(tmp_stdin, tmp_stdin),
                     ENTRY_STR(tmp_stdout, tmp_stdout),
                     ENTRY_IP4(dip, dip),
                     ENTRY_U16(dport, dport),
                     ENTRY_IP4(sip, sip),
                     ENTRY_U16(sport, sport),
                     ENTRY_U16(sa_family, 2),
                     ENTRY_STR(pid_tree, pid_tree),
                     ENTRY_STL(tty_name, tty_name, 64),
                     ENTRY_U32(socket_pid, socket_pid),
                     ENTRY_STR(ssh_connection, ssh_connection),
                     ENTRY_STR(ld_preload, ld_preload),
                     ENTRY_STR(ld_library_path, ld_library_path),
                     ENTRY_INT(retval, retval)
                )
)

SD_XFER_DEFINE( NAME(execve_nosocket),

                PROT(ELEMENT(char *, pname),
                     ELEMENT(char *, exe_path),
                     ELEMENT(char *, argv),
                     ELEMENT(char *, tmp_stdin),
                     ELEMENT(char *, tmp_stdout),
                     ELEMENT(char *, pid_tree),
                     ELEMENT(char *, tty_name),
                     ELEMENT(char *, ssh_connection),
                     ELEMENT(char *, ld_preload),
                     ELEMENT(char *, ld_library_path),
                     ELEMENT(int, retval)
                ),

                XFER(ENTRY_COMMON(59),
                     ENTRY_STR(argv, argv),
                     ENTRY_STR(pname, pname),
                     ENTRY_STR(tmp_stdin, tmp_stdin),
                     ENTRY_STR(tmp_stdout, tmp_stdout),
                     ENTRY_S8(dip, -1),
                     ENTRY_S8(dport, -1),
                     ENTRY_S8(sip, -1),
                     ENTRY_S8(sport, -1),
                     ENTRY_S16(sa_family, -1),
                     ENTRY_STR(pid_tree, pid_tree),
                     ENTRY_STL(tty_name, tty_name, 64),
                     ENTRY_S32(socket_pid, -1),
                     ENTRY_STR(ssh_connection, ssh_connection),
                     ENTRY_STR(ld_preload, ld_preload),
                     ENTRY_STR(ld_library_path, ld_library_path),
                     ENTRY_INT(retval, retval)
                )
)

#if IS_ENABLED(CONFIG_IPV6)
SD_XFER_DEFINE( NAME(execve6),

                PROT(ELEMENT(char *, pname),
                     ELEMENT(char *, exe_path),
                     ELEMENT(char *, argv),
                     ELEMENT(char *, tmp_stdin),
                     ELEMENT(char *, tmp_stdout),
                     ELEMENT(struct in6_addr *, dip),
                     ELEMENT(int, dport),
                     ELEMENT(struct in6_addr *, sip),
                     ELEMENT(int, sport),
                     ELEMENT(char *, pid_tree),
                     ELEMENT(char *, tty_name),
                     ELEMENT(pid_t, socket_pid),
                     ELEMENT(char *, ssh_connection),
                     ELEMENT(char *, ld_preload),
                     ELEMENT(char *, ld_library_path),
                     ELEMENT(int, retval)
                ),

                XFER(ENTRY_COMMON(59),
                     ENTRY_STR(argv, argv),
                     ENTRY_STR(pname, pname),
                     ENTRY_STR(tmp_stdin, tmp_stdin),
                     ENTRY_STR(tmp_stdout, tmp_stdout),
                     ENTRY_IP6(dip, dip),
                     ENTRY_U16(dport, dport),
                     ENTRY_IP6(sip, sip),
                     ENTRY_U16(sport, sport),
                     ENTRY_U16(sa_family, 10),
                     ENTRY_STR(pid_tree, pid_tree),
                     ENTRY_STL(tty_name, tty_name, 64),
                     ENTRY_U32(socket_pid, socket_pid),
                     ENTRY_STR(ssh_connection, ssh_connection),
                     ENTRY_STR(ld_preload, ld_preload),
                     ENTRY_STR(ld_library_path, ld_library_path),
                     ENTRY_INT(retval, retval)
                )
)
#endif

SD_XFER_DEFINE( NAME(accept),

                PROT(ELEMENT(int, dport),
                     ELEMENT(__be32, dip),
                     ELEMENT(char *, exe_path),
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

                PROT(ELEMENT(int, dport),
                     ELEMENT(struct in6_addr *, dip),
                     ELEMENT(char *, exe_path),
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

SD_XFER_DEFINE( NAME(connect4),

                PROT(ELEMENT(int, dport),
                     ELEMENT(__be32, dip),
                     ELEMENT(char *, exe_path),
                     ELEMENT(__be32, sip),
                     ELEMENT(int, sport),
                     ELEMENT(int, retval),
                     ELEMENT(char *, pid_tree)
                 ),

                XFER(ENTRY_COMMON(42),
                     ENTRY_U16(sa_family, 2),
                     ENTRY_IP4(dip, dip),
                     ENTRY_U16(dport, dport),
                     ENTRY_IP4(sip, sip),
                     ENTRY_U16(sport, sport),
                     ENTRY_INT(retval, retval),
                     ENTRY_STR(pid_tree, pid_tree)
                )
)

#if IS_ENABLED(CONFIG_IPV6)
SD_XFER_DEFINE( NAME(connect6),

                PROT(ELEMENT(int, dport),
                     ELEMENT(struct in6_addr *, dip),
                     ELEMENT(char *, exe_path),
                     ELEMENT(struct in6_addr *, sip),
                     ELEMENT(int, sport),
                     ELEMENT(int, retval),
                     ELEMENT(char *, pid_tree)
                ),

                XFER(ENTRY_COMMON(42),
                     ENTRY_U16(sa_family, 10),
                     ENTRY_IP6(dip, dip),
                     ENTRY_U16(dport, dport),
                     ENTRY_IP6(sip, sip),
                     ENTRY_U16(sport, sport),
                     ENTRY_INT(retval, retval),
                     ENTRY_STR(pid_tree, pid_tree)
                )
)
#endif

SD_XFER_DEFINE( NAME(ptrace),

                PROT(ELEMENT(long, request),
                     ELEMENT(long, owner_pid),
                     ELEMENT(void *, addr),
                     ELEMENT(char *, data_res),
                     ELEMENT(char *, exe_path),
                     ELEMENT(char *, pid_tree)
                ),

                XFER(ENTRY_COMMON(101),
                     ENTRY_INT(request, request),
                     ENTRY_U32(owner_pid, owner_pid),
                     ENTRY_ULONG(addr, (unsigned long)addr),
                     ENTRY_STR(data_res, data_res),
                     ENTRY_STR(pid_tree, pid_tree)
                )
)

SD_XFER_DEFINE( NAME(bind),

                PROT(ELEMENT(char *, exe_path),
                     ELEMENT(struct in_addr *, in_addr),
                     ELEMENT(int, sport),
                     ELEMENT(int, retval),
                     ELEMENT(char *, pid_tree)
                ),

                XFER(ENTRY_COMMON(49),
                     ENTRY_U16(sa_family, 2),
                     ENTRY_IP4(in_addr, in_addr->s_addr),
                     ENTRY_U16(sport, sport),
                     ENTRY_INT(retval, retval),
                     ENTRY_STR(pid_tree, pid_tree)
                )
)

#if IS_ENABLED(CONFIG_IPV6)
SD_XFER_DEFINE( NAME(bind6),

                PROT(ELEMENT(char *, exe_path),
                     ELEMENT(struct in6_addr *, in6_addr),
                     ELEMENT(int, sport),
                     ELEMENT(int, retval),
                     ELEMENT(char *, pid_tree)
                ),

                XFER(ENTRY_COMMON(49),
                     ENTRY_U16(sa_family, 10),
                     ENTRY_IP6(in6_addr, in6_addr),
                     ENTRY_U16(sport, sport),
                     ENTRY_INT(retval, retval),
                     ENTRY_STR(pid_tree, pid_tree)
                )
)
#endif

SD_XFER_DEFINE( NAME(update_cred),

                PROT(ELEMENT(char *, exe_path),
                     ELEMENT(char *, pid_tree),
                     ELEMENT(int, old_uid),
                     ELEMENT(int, retval)
                ),

                XFER(ENTRY_COMMON(604),
                     ENTRY_STR(pid_tree, pid_tree),
                     ENTRY_U32(old_uid, old_uid),
                     ENTRY_INT(retval, retval)
                )
)

SD_XFER_DEFINE( NAME(do_init_module),

                PROT(ELEMENT(char *, exe_path),
                     ELEMENT(char *, mod_name),
                     ELEMENT(char *, pid_tree),
                     ELEMENT(char *, pwd)
                ),

                XFER(ENTRY_COMMON(603),
                     ENTRY_STR(mod_name, mod_name),
                     ENTRY_STR(pid_tree, pid_tree),
                     ENTRY_STR(pwd, pwd)
                )
)

SD_XFER_DEFINE( NAME(rename),

                PROT(ELEMENT(char *, exe_path),
                     ELEMENT(char *, oldname),
                     ELEMENT(char *, newname),
                     ELEMENT(char *, s_id)
                ),

                XFER(ENTRY_COMMON(82),
                     ENTRY_STR(oldname, oldname),
                     ENTRY_STR(newname, newname),
                     ENTRY_STL(s_id, s_id, 32)
                )
)

SD_XFER_DEFINE( NAME(link),

                PROT(ELEMENT(char *, exe_path),
                     ELEMENT(char *, oldname),
                     ELEMENT(char *, newname),
                     ELEMENT(char *, s_id)
                ),

                XFER(ENTRY_COMMON(86),
                     ENTRY_STR(oldname, oldname),
                     ENTRY_STR(newname, newname),
                     ENTRY_STL(s_id, s_id, 32)
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

SD_XFER_DEFINE( NAME(setsid),

                PROT(ELEMENT(char *, exe_path),
                     ELEMENT(int, newsid),
                     ELEMENT(char *, pid_tree)
                ),

                XFER(ENTRY_COMMON(112),
                     ENTRY_INT(newsid, newsid),
                     ENTRY_STR(pid_tree, pid_tree)
                )

)

SD_XFER_DEFINE( NAME(prctl),

                PROT(ELEMENT(char *, exe_path),
                     ELEMENT(int, option),
                     ELEMENT(char *, newname)
                ),

                XFER(ENTRY_COMMON(157),
                     ENTRY_INT(option, option),
                     ENTRY_STR(newname, newname)
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

                PROT(ELEMENT(char *, exe_path), ELEMENT(char *, file), ELEMENT(char *, buf)),

                XFER(ENTRY_COMMON(1), ENTRY_STR(file, file), ENTRY_STR(buf, buf))
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

SD_XFER_DEFINE( NAME(mount),
                PROT(ELEMENT(char *, exe_path),
                     ELEMENT(char *, pid_tree),
                     ELEMENT(char *, dev_name),
                     ELEMENT(char *, file_path),
                     ELEMENT(char *, fsid),
                     ELEMENT(char *, fstype),
                     ELEMENT(unsigned long, flags),
                     ELEMENT(char *, option)
                ),

                XFER(ENTRY_COMMON(165),
                     ENTRY_STR(pid_tree, pid_tree),
                     ENTRY_STR(dev_name, dev_name),
                     ENTRY_STR(file_path, file_path),
                     ENTRY_STL(fsid, fsid, 32),
                     ENTRY_STR(fstype, fstype),
                     ENTRY_INT(flags, flags),
                     ENTRY_STR(option, option)
                )
)

SD_XFER_DEFINE( NAME(udev),

                PROT(ELEMENT(char *, exe_path),
                     ELEMENT(char *, product),
                     ELEMENT(char *, manufacturer),
                     ELEMENT(char *, serial),
                     ELEMENT(int, action)
                ),

                XFER(ENTRY_COMMON(610),
                     ENTRY_STR(product, product),
                     ENTRY_STR(manufacturer, manufacturer),
                     ENTRY_STR(serial, serial),
                     ENTRY_INT(action, action)
                )
)

SD_XFER_DEFINE( NAME(privilege_escalation),

                PROT(ELEMENT(char *, exe_path),
                     ELEMENT(int, parent_pid),
                     ELEMENT(char *, pid_tree),
                     ELEMENT(char *, p_cred),
                     ELEMENT(char *, c_cred)
                ),

                XFER(ENTRY_COMMON(611),
                     ENTRY_INT(parent_pid, parent_pid),
                     ENTRY_STR(pid_tree, pid_tree),
                     ENTRY_STR(p_cred, p_cred),
                     ENTRY_STR(c_cred, c_cred)
                )
)

SD_XFER_DEFINE( NAME(memfd_create),

                PROT(ELEMENT(char *, exe_path),
                     ELEMENT(char *, fdname),
                     ELEMENT(unsigned long, flags)
                ),

                XFER(ENTRY_COMMON(356),
                     ENTRY_STR(fdname, fdname),
                     ENTRY_INT(flags, flags)
                )
)

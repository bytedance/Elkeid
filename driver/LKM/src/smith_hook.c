// SPDX-License-Identifier: GPL-3.0
/*
 * smith_hook.c
 *
 * Hook some kernel function
 */
#include "../include/smith_hook.h"

#define CREATE_PRINT_EVENT

#include "../include/kprobe_print.h"

#define EXIT_PROTECT 0
#define SANDBOX 0
#define SMITH_MAX_ARG_STRINGS (16)

// Hook on-off
int CONNECT_HOOK = 1;
int BIND_HOOK = 1;
int EXECVE_HOOK = 1;
int CREATE_FILE_HOOK = 1;
int PTRACE_HOOK = 1;
int DO_INIT_MODULE_HOOK = 1;
int UPDATE_CRED_HOOK = 1;

int RENAME_HOOK = 1;
int LINK_HOOK = 1;
int SETSID_HOOK = 1;
int PRCTL_HOOK = 1;
int MEMFD_CREATE_HOOK = 1;

int DNS_HOOK = 0;
int CALL_USERMODEHELPER = 0;
int ACCEPT_HOOK = 0;
int OPEN_HOOK = 0;
int MPROTECT_HOOK = 0;
int NANOSLEEP_HOOK = 0;
int KILL_HOOK = 0;
int RM_HOOK = 0;
int EXIT_HOOK = 0;

int FAKE_SLEEP = 0;
int FAKE_RM = 0;

int PID_TREE_LIMIT = 12;
int PID_TREE_LIMIT_LOW = 8;
int EXECVE_GET_SOCK_PID_LIMIT = 8;
int EXECVE_GET_SOCK_FD_LIMIT = 8;

char connect_syscall_kprobe_state = 0x0;
char execve_kretprobe_state = 0x0;
char bind_kprobe_state = 0x0;
char compat_execve_kretprobe_state = 0x0;
char create_file_kprobe_state = 0x0;
char ptrace_kprobe_state = 0x0;
char udp_recvmsg_kprobe_state = 0x0;
char udpv6_recvmsg_kprobe_state = 0x0;
char do_init_module_kprobe_state = 0x0;
char update_cred_kprobe_state = 0x0;
char ip4_datagram_connect_kprobe_state = 0x0;
char ip6_datagram_connect_kprobe_state = 0x0;
char tcp_v4_connect_kprobe_state = 0x0;
char tcp_v6_connect_kprobe_state = 0x0;
char mprotect_kprobe_state = 0x0;
char rename_kprobe_state = 0x0;
char renameat_kprobe_state = 0x0;
char renameat2_kprobe_state = 0x0;
char link_kprobe_state = 0x0;
char linkat_kprobe_state = 0x0;
char setsid_kprobe_state = 0x0;
char prctl_kprobe_state = 0x0;
char memfd_create_kprobe_state = 0x0;
char accept_kretprobe_state = 0x0;
char accept4_kretprobe_state = 0x0;
char open_kprobe_state = 0x0;
char nanosleep_kprobe_state = 0x0;
char kill_kprobe_state = 0x0;
char tkill_kprobe_state = 0x0;
char exit_kprobe_state = 0x0;
char exit_group_kprobe_state = 0x0;
char security_path_rmdir_kprobe_state = 0x0;
char security_path_unlink_kprobe_state = 0x0;
char call_usermodehelper_exec_kprobe_state = 0x0;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 19, 0)
char execveat_kretprobe_state = 0x0;
char compat_execveat_kretprobe_state = 0x0;
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 0, 0)
struct user_arg_ptr {
#ifdef CONFIG_COMPAT
	bool is_compat;
#endif
	union {
		const char __user *const __user *native;
#ifdef CONFIG_COMPAT
		const compat_uptr_t __user *compat;
#endif
	} ptr;
};

#if EXIT_PROTECT == 1
void exit_protect_action(void)
{
	__module_get(THIS_MODULE);
}
#endif

const char __user *get_user_arg_ptr(struct user_arg_ptr argv, int nr)
{
	const char __user *native;

#ifdef CONFIG_COMPAT
	if (argv.is_compat) {
		compat_uptr_t compat;

		if (smith_get_user(compat, argv.ptr.compat + nr))
		    return ERR_PTR(-EFAULT);

		return compat_ptr(compat);
	}
#endif

	if (smith_get_user(native, argv.ptr.native + nr))
	    return ERR_PTR(-EFAULT);

	return native;
}

//count execve argv num
int count(struct user_arg_ptr argv, int max)
{
	int i = 0;
	if (argv.ptr.native != NULL) {
		for (;;) {
			const char __user *p = get_user_arg_ptr(argv, i);
			if (!p)
				break;
			if (IS_ERR(p))
				return -EFAULT;
			if (++i >= max)
				break;
			if (fatal_signal_pending(current))
				return -ERESTARTNOHAND;
		}
	}
	return i;
}
#endif

//count execve argv num
int execve_count(char **argv, int max)
{
    int i = 0;

    if (argv != NULL) {
        for (;;) {
            char *p;
            if (smith_get_user(p, argv))
                return -EFAULT;
            if (!p)
                break;
            argv++;
            if (++i >= max)
                break;
            if (fatal_signal_pending(current))
                return -ERESTARTNOHAND;
        }
    }
    return i;
}

/* 
 *  in atomic state we can't call get_files_struct(), since it
 *  will call task_lock() internally
 *
 *  with the task was already referenced by us, the racing
 *  possiblity with actuall fdtable-destruction is very little.
 */
static struct files_struct *smith_get_files_struct(struct task_struct *task)
{
    struct files_struct *files = task->files;
    if (!files)
        return NULL;

    if (atomic_add_unless(&files->count, 1, 0) > 0)
        return files;

    /* we are in the race of files-destroy */
    return NULL;
}

static void (*put_files_struct_sym) (struct files_struct * files);
static void smith_put_files_struct(struct files_struct *files)
{
    if (put_files_struct_sym) {
        put_files_struct_sym(files);
    } else {
        /* just for reminder, the actual execution won't be here,
           since the ko won't load if put_files_sturct is absent */
        atomic_dec(&files->count);
    }
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 11, 0)
#define smith_lookup_fd          files_lookup_fd_rcu
#else
#define smith_lookup_fd          fcheck_files
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 5, 0)
static int __init files_struct_symbols_init(void)
{
	void *ptr;

	ptr = (void *)put_files_struct;
	if (!ptr)
		return -ENODEV;
	put_files_struct_sym = ptr;

	return 0;
}
#else
static int __init files_struct_symbols_init(void)
{
    void *ptr;

    ptr = (void *)smith_kallsyms_lookup_name("put_files_struct");
    if (!ptr)
        return -ENODEV;
    put_files_struct_sym = ptr;

    return 0;
}
#endif

//get task tree first AF_INET/AF_INET6 socket info
void get_process_socket(__be32 * sip4, struct in6_addr *sip6, int *sport,
                        __be32 * dip4, struct in6_addr *dip6, int *dport,
                        char **socket_pname, char **socket_pname_buf,
                        pid_t * socket_pid, int *sa_family)
{
    int i;
    int fd_max;
    int limit_index = 0, socket_check = 0;

    char fd_buff[24];
    const char *d_name;

    void *tmp_socket = NULL;
    struct task_struct *task;
    struct sock *sk;
    struct inet_sock *inet;
    struct socket *socket;

    task = current;
    get_task_struct(task);

    while (task && task->pid != 1) {
        struct files_struct *files;

        limit_index = limit_index + 1;
        if (limit_index > EXECVE_GET_SOCK_PID_LIMIT)
            break;

        files = smith_get_files_struct(task);
        if (!files)
            goto next_task;

        rcu_read_lock();
        fd_max = files_fdtable(files)->max_fds;
        rcu_read_unlock();

        for (i = 0; i < fd_max; i++) {
            struct file *file;
            if (i > EXECVE_GET_SOCK_FD_LIMIT)
                break;

            rcu_read_lock();
            file = smith_lookup_fd(files, i);
            if (!file || !get_file_rcu(file)) {
                rcu_read_unlock();
                continue;
            }
            rcu_read_unlock();

            d_name = smith_d_path(&file->f_path, fd_buff, 24);
            if (strlen(d_name) < 8)
                goto next_file;

            //find socket fd
            if (strncmp("socket:[", d_name, 8) == 0) {
                if (IS_ERR_OR_NULL(file->private_data))
                    goto next_file;

                tmp_socket = file->private_data;

                socket = (struct socket *)tmp_socket;
                if (socket) {
                    sk = socket->sk;
                    if (!socket->sk)
                        goto next_file;

                    inet = (struct inet_sock *)sk;
                    switch (sk->sk_family) {
                        case AF_INET:
#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 32)
                            *dip4 = inet->inet_daddr;
		            *sip4 = inet->inet_saddr;
			    *sport = ntohs(inet->inet_sport);
		            *dport = ntohs(inet->inet_dport);
#else
                            *dip4 = inet->daddr;
                            *sip4 = inet->saddr;
                            *sport = ntohs(inet->sport);
                            *dport = ntohs(inet->dport);
#endif
                            socket_check = 1;
                            *sa_family = sk->sk_family;
                            break;
#if IS_ENABLED(CONFIG_IPV6)
                            case AF_INET6:
#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 32)
						    memcpy(dip6, &(sk->sk_v6_daddr), sizeof(sk->sk_v6_daddr));
						    memcpy(sip6, &(sk->sk_v6_rcv_saddr), sizeof(sk->sk_v6_rcv_saddr));
						    *sport = ntohs(inet->inet_sport);
						    *dport = ntohs(inet->inet_dport);
#else
						    memcpy(dip6, &(inet->pinet6->daddr), sizeof(inet->pinet6->daddr));
						    memcpy(sip6, &(inet->pinet6->daddr), sizeof(inet->pinet6->daddr));
						    *sport = ntohs(inet->sport);
						    *dport = ntohs(inet->dport);
#endif
						    socket_check = 1;
						    *sa_family = sk->sk_family;
						    break;
#endif
                    }
                }
            }
next_file:
            fput(file);
        }
        smith_put_files_struct(files);

        if (socket_check) {
            *socket_pid = task->pid;
            *socket_pname = "-1";
            put_task_struct(task);
            return;
        } else {
            struct task_struct *old_task;

next_task:
            old_task = task;
            rcu_read_lock();
            task = rcu_dereference(task->real_parent);
            if (task)
                get_task_struct(task);
            rcu_read_unlock();
            put_task_struct(old_task);
        }
    }

    if (task)
        put_task_struct(task);

    return;
}

struct connect_data {
    struct sock *sk;
    int sa_family;
    int type;
};

struct connect_syscall_data {
    int fd;
    struct sockaddr *dirp;
};

struct accept_data {
    int type;
    void __user *accept_dirp;
    union {
        struct sockaddr    sa;
        struct sockaddr_in si4;
        struct sockaddr_in6 si6;
        struct __kernel_sockaddr_storage kss; /* to avoid overflow access of kernel_getsockname */
    };
};

struct udp_recvmsg_data {
    int sport;
    int dport;
    int sa_family;

    __be32 dip4;
    __be32 sip4;

    struct in6_addr *dip6;
    struct in6_addr *sip6;
    struct msghdr *msg;

    void __user *iov_base;
    __kernel_size_t iov_len;
};

struct bind_data {
    int fd;
    union {
        struct sockaddr dirp;
        struct sockaddr_in sin;
#if IS_ENABLED(CONFIG_IPV6)
        struct sockaddr_in6 sin6;
#endif
    };
};

struct execve_data {
    char *argv;
    char *ssh_connection;
    char *ld_preload;
    char *ld_library_path;

    int free_argv;
    int free_ssh_connection;
    int free_ld_preload;
    int free_ld_library_path;
};

struct update_cred_data {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 5, 0)
    uid_t old_uid;
#else
    int old_uid;
#endif
};

int bind_entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct bind_data *data = (struct bind_data *)ri->data;
    struct sockaddr_storage address;
    struct sockaddr *uaddr;
    int ulen = p_get_arg3(regs);

    if (ulen <= 0 || ulen > sizeof(struct sockaddr_storage))
        return -EINVAL;

    if (smith_copy_from_user(&address, (void __user *)p_get_arg2(regs), ulen))
    return -EFAULT;

    uaddr = (struct sockaddr *)&address;
    if (uaddr->sa_family == AF_INET && ulen >= sizeof(data->sin))
        memcpy(&data->sin, (void *)&address, sizeof(data->sin));
#if IS_ENABLED(CONFIG_IPV6)
        else if (uaddr->sa_family == AF_INET6 && ulen >= sizeof(data->sin6))
		memcpy(&data->sin6, (void *)&address, sizeof(data->sin6));
#endif
    else
        return -EINVAL;

    return 0;
}

int bind_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    int retval, sa_family, sport;

    char *exe_path = DEFAULT_RET_STR;
    char *buffer = NULL;

    struct sockaddr *uaddr;
    struct sockaddr_in *sin;
    struct sockaddr_in6 *sin6;
    struct in_addr *in_addr = NULL;
    struct in6_addr *in6_addr = NULL;

    uaddr = &((struct bind_data *)ri->data)->dirp;
    retval = regs_return_value(regs);
    /*
     * If the return value is not zero, the data passed by the user
     * is untrusted. Access to untrusted data may be problematic.
     */
    if (retval)
        return 0;

    sa_family = uaddr->sa_family;
    //only get AF_INET/AF_INET6 bind info
    switch (sa_family) {
        case AF_INET:
            sin = (struct sockaddr_in *)uaddr;
            in_addr = &sin->sin_addr;
            sport = ntohs(sin->sin_port);
            break;
#if IS_ENABLED(CONFIG_IPV6)
        case AF_INET6:
		    sin6 = (struct sockaddr_in6 *)uaddr;
		    in6_addr = &sin6->sin6_addr;
		    sport = ntohs(sin6->sin6_port);
		    break;
#endif
        default:
            return 0;
    }

    buffer = kzalloc(PATH_MAX, GFP_ATOMIC);
    exe_path = smith_get_exe_file(buffer, PATH_MAX);

    if (sa_family == AF_INET)
        bind_print(exe_path, in_addr, sport, retval);
#if IS_ENABLED(CONFIG_IPV6)
    else if (sa_family == AF_INET6)
		bind6_print(exe_path, in6_addr, sport, retval);
#endif

    if (buffer)
        kfree(buffer);

    return 0;
}

int connect_syscall_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    int flag = 0;
    int err, fd, copy_res;
    int dport, sport, retval, sa_family;

    __be32 dip4 = 0;
    __be32 sip4 = 0;

    char *exe_path = DEFAULT_RET_STR;
    char *buffer = NULL;

    struct socket *socket;
    struct sock *sk;
    struct sockaddr tmp_dirp;
    struct connect_syscall_data *data;
    struct inet_sock *inet;
    struct in6_addr *dip6 = NULL;
    struct in6_addr *sip6 = NULL;

    retval = regs_return_value(regs);

    data = (struct connect_syscall_data *)ri->data;
    fd = data->fd;

    if (!fd || IS_ERR_OR_NULL(data->dirp))
        return 0;

    socket = sockfd_lookup(fd, &err);
    if (socket) {
        copy_res = smith_copy_from_user(&tmp_dirp, data->dirp, 16);

        if (copy_res) {
            sockfd_put(socket);
            return 0;
        }

        switch (tmp_dirp.sa_family) {
            case AF_INET:
                sk = socket->sk;
                inet = (struct inet_sock *)sk;
#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 32)
            if (inet->inet_daddr) {
                    dip4 = inet->inet_daddr;
				    //dip4 = ((struct sockaddr_in *)&tmp_dirp)->sin_addr.s_addr;
				    sip4 = inet->inet_saddr;
				    sport = ntohs(inet->inet_sport);
				    dport = ntohs(((struct sockaddr_in *)&tmp_dirp)->sin_port);
				    if(dport == 0)
				        dport = ntohs(inet->inet_dport);
				    flag = 1;
			    }
#else
                if (inet->daddr) {
                    dip4 = inet->daddr;
                    //dip4 = ((struct sockaddr_in *)&tmp_dirp)->sin_addr.s_addr;
                    sip4 = inet->saddr;
                    sport = ntohs(inet->sport);
                    dport = ntohs(((struct sockaddr_in *)&tmp_dirp)->sin_port);
                    if(dport == 0)
                        dport = ntohs(inet->dport);
                    flag = 1;
                }
#endif
                sa_family = AF_INET;
                break;
#if IS_ENABLED(CONFIG_IPV6)
            case AF_INET6:
			    sk = socket->sk;
			    inet = (struct inet_sock *)sk;
#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 32)
			    if (inet->inet_dport) {
				    //dip6 = &((struct sockaddr_in6 *)&tmp_dirp)->sin6_addr;
				    dip6 = &(sk->sk_v6_daddr);
				    sip6 = &(sk->sk_v6_rcv_saddr);
				    sport = ntohs(inet->inet_sport);
				    dport = ntohs(((struct sockaddr_in6 *)&tmp_dirp)->sin6_port);
				    if(dport == 0)
				        dport = ntohs(inet->inet_dport);
				    flag = 1;
			    }
#else
			    if (inet->dport) {
				    //dip6 = &((struct sockaddr_in6 *)&tmp_dirp)->sin6_addr;
				    dip6 = &(inet->pinet6->daddr);
				    sip6 = &(inet->pinet6->saddr);
				    sport = ntohs(inet->sport);
				    dport = ntohs(((struct sockaddr_in6 *)&tmp_dirp)->sin6_port);
				    if(dport)
				        dport = ntohs(inet->dport);
				    flag = 1;
			    }
#endif
			sa_family = AF_INET6;
			break;
#endif
            default:
                break;
        }
        sockfd_put(socket);
    }

    if (flag) {
        buffer = kzalloc(PATH_MAX, GFP_ATOMIC);
        exe_path = smith_get_exe_file(buffer, PATH_MAX);

        if (sa_family == AF_INET)
            connect4_print(-1, dport, dip4, exe_path, sip4, sport, retval);
#if IS_ENABLED(CONFIG_IPV6)
        else
			connect6_print(-1, dport, dip6, exe_path, sip6, sport, retval);
#endif

        if (buffer)
            kfree(buffer);
    }

    return 0;
}

int connect_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    int flag = 0;
    int retval, dport, sport;

    __be32 dip4;
    __be32 sip4;

    char *exe_path = DEFAULT_RET_STR;
    char *buffer = NULL;

    struct sock *sk;
    struct connect_data *data;
    struct inet_sock *inet;
    struct in6_addr *dip6;
    struct in6_addr *sip6;

    retval = regs_return_value(regs);
    data = (struct connect_data *)ri->data;

    sk = data->sk;
    if (IS_ERR_OR_NULL(sk))
        return 0;

    buffer = kzalloc(PATH_MAX, GFP_ATOMIC);
    exe_path = smith_get_exe_file(buffer, PATH_MAX);

    //exe filter check
    if (execve_exe_check(exe_path)) {
        if (buffer)
            kfree(buffer);
        return 0;
    }
    //only get AF_INET/AF_INET6 connect info
    inet = (struct inet_sock *)sk;
    switch (data->sa_family) {
        case AF_INET:
#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 32)
            if (inet->inet_daddr) {
			dip4 = inet->inet_daddr;
			sip4 = inet->inet_saddr;
			sport = ntohs(inet->inet_sport);
			dport = ntohs(inet->inet_dport);
			flag = 1;
		}
#else
            if (inet->daddr) {
                dip4 = inet->daddr;
                sip4 = inet->saddr;
                sport = ntohs(inet->sport);
                dport = ntohs(inet->dport);
                flag = 1;
            }
#endif
            break;
#if IS_ENABLED(CONFIG_IPV6)
        case AF_INET6:
#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 32)
		    if (inet->inet_dport) {
			    dip6 = &(sk->sk_v6_daddr);
			    sip6 = &(sk->sk_v6_rcv_saddr);
			    sport = ntohs(inet->inet_sport);
			    dport = ntohs(inet->inet_dport);
			    flag = 1;
		    }
#else
		    if (inet->dport) {
			    dip6 = &(inet->pinet6->daddr);
			    sip6 = &(inet->pinet6->saddr);
			    sport = ntohs(inet->sport);
			    dport = ntohs(inet->dport);
			    flag = 1;
		    }
#endif
		break;
#endif
        default:
            break;
    }

    if (flag) {
        if (data->sa_family == AF_INET)
            connect4_print(data->type, dport, dip4, exe_path, sip4,
                           sport, retval);
#if IS_ENABLED(CONFIG_IPV6)
        else
			connect6_print(data->type, dport, dip6, exe_path, sip6,
				       sport, retval);
#endif
    }

    if (buffer)
        kfree(buffer);

    return 0;
}

int accept_entry_handler(struct kretprobe_instance *ri,
                         struct pt_regs *regs)
{
    struct accept_data *data;
    struct sockaddr *dirp;

    data = (struct accept_data *)ri->data;
    data->type = 2;

    dirp = (void __user *)p_get_arg2(regs);
    if(IS_ERR_OR_NULL(dirp))
        return -EINVAL;
    data->accept_dirp = dirp;
    return 0;
}

int accept4_entry_handler(struct kretprobe_instance *ri,
                          struct pt_regs *regs)
{
    struct accept_data *data;
    struct sockaddr *dirp;

    data = (struct accept_data *)ri->data;
    data->type = 1;

    dirp = (void __user *)p_get_arg2(regs);
    if(IS_ERR_OR_NULL(dirp))
        return -EINVAL;
    data->accept_dirp = dirp;
    return 0;
}

static int smith_sock_getname(struct socket *s, struct sockaddr *sa, int *l, int peer)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 17, 0)
    if (peer)
        return kernel_getpeername(s, sa);
    else
        return kernel_getsockname(s, sa);
#else
    if (peer)
        return kernel_getpeername(s, sa, l);
    else
        return kernel_getsockname(s, sa, l);
#endif
}

int accept_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct accept_data *data;
    struct socket *sock = NULL;

    int sport = 0;
    int dport = 0;
    int retval, addrlen = 0, err = 0;

    char *exe_path = DEFAULT_RET_STR;
    char *buffer = NULL;

    data = (struct accept_data *)ri->data;
    retval = regs_return_value(regs);
    sock = sockfd_lookup(retval, &err);
    if(IS_ERR_OR_NULL(sock))
        goto out;

    buffer = kzalloc(PATH_MAX, GFP_ATOMIC);
    exe_path = smith_get_exe_file(buffer, PATH_MAX);

    if (smith_sock_getname(sock, &data->sa, &addrlen, 0) < 0)
        goto out;

    //only get AF_INET/AF_INET6 accept info
    if (data->si4.sin_family == AF_INET) {
        __be32 sip4 = 0;
        __be32 dip4 = data->si4.sin_addr.s_addr;
        dport = ntohs(data->si4.sin_port);

        if (smith_sock_getname(sock, &data->sa, &addrlen, 1) < 0)
            goto out;
        sip4 = (data->si4.sin_addr.s_addr);
        sport = ntohs(data->si4.sin_port);
        accept_print(dport, dip4, exe_path, sip4, sport, retval);
    }
#if IS_ENABLED(CONFIG_IPV6)
    else if (data->si4.sin_family == AF_INET6) {
        struct in6_addr *sip6;
        struct in6_addr dip6 = data->si6.sin6_addr;
        dport = ntohs(data->si6.sin6_port);

        if (smith_sock_getname(sock, &data->sa, &addrlen, 1) < 0)
            goto out;
        sport = ntohs(data->si6.sin6_port);
        sip6 = &(data->si6.sin6_addr);
        accept6_print(dport, &dip6, exe_path, sip6, sport, retval);
    }
#endif

out:
    if (sock)
        sockfd_put(sock);
    if (buffer)
        kfree(buffer);
    return 0;
}

int execve_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    int sa_family = -1;
    int dport = 0, sport = 0;

    __be32 dip4;
    __be32 sip4;
    pid_t socket_pid = -1;

    char *pname = DEFAULT_RET_STR;
    char *tmp_stdin = DEFAULT_RET_STR;
    char *tmp_stdout = DEFAULT_RET_STR;
    char *buffer = NULL;
    char *pname_buf = NULL;
    char *pid_tree = NULL;
    char *socket_pname = "-1";
    char *socket_pname_buf = NULL;
    char *tty_name = "-1";
    char *exe_path = DEFAULT_RET_STR;
    char *pgid_exe_path = "-1";
    char *stdin_buf = NULL;
    char *stdout_buf = NULL;

    struct in6_addr dip6;
    struct in6_addr sip6;
    struct file *file;
    struct execve_data *data;
    struct tty_struct *tty;

    data = (struct execve_data *)ri->data;
    buffer = kzalloc(PATH_MAX, GFP_ATOMIC);
    exe_path = smith_get_exe_file(buffer, PATH_MAX);

    tty = get_current_tty();
    if(tty && strlen(tty->name) > 0)
        tty_name = tty->name;

    //exe filter check and argv filter check
    if (execve_exe_check(exe_path) || execve_argv_check(data->argv))
        goto out;

    get_process_socket(&sip4, &sip6, &sport, &dip4, &dip6, &dport,
                       &socket_pname, &socket_pname_buf, &socket_pid,
                       &sa_family);

    //if socket exist,get pid tree
    if (sa_family == AF_INET6 || sa_family == AF_INET)
        pid_tree = smith_get_pid_tree(PID_TREE_LIMIT);
    else
        pid_tree = smith_get_pid_tree(PID_TREE_LIMIT_LOW);

    // get stdin
    file = fget_raw(0);
    if (file) {
        stdin_buf = kzalloc(256, GFP_ATOMIC);
        tmp_stdin = smith_d_path(&(file->f_path), stdin_buf, 256);
        fput(file);
    }

    //get stdout
    file = fget_raw(1);
    if (file) {
        stdout_buf = kzalloc(256, GFP_ATOMIC);
        tmp_stdout = smith_d_path(&(file->f_path), stdout_buf, 256);
        fput(file);
    }

    pname_buf = kzalloc(PATH_MAX, GFP_ATOMIC);
    pname = smith_d_path(&current->fs->pwd, pname_buf, PATH_MAX);

    if (sa_family == AF_INET) {
        execve_print(pname,
                     exe_path, pgid_exe_path, data->argv,
                     tmp_stdin, tmp_stdout,
                     dip4, dport, sip4, sport,
                     pid_tree, tty_name, socket_pid, socket_pname,
                     data->ssh_connection, data->ld_preload, data->ld_library_path,
                     regs_return_value(regs));
    }
#if IS_ENABLED(CONFIG_IPV6)
        else if (sa_family == AF_INET6) {
		execve6_print(pname,
			      exe_path, pgid_exe_path, data->argv,
			      tmp_stdin, tmp_stdout,
			      &dip6, dport, &sip6, sport,
			      pid_tree, tty_name, socket_pid, socket_pname,
			      data->ssh_connection, data->ld_preload, data->ld_library_path,
			      regs_return_value(regs));
	}
#endif
    else {
        execve_nosocket_print(pname,
                              exe_path, pgid_exe_path, data->argv,
                              tmp_stdin, tmp_stdout,
                              pid_tree, tty_name,
                              data->ssh_connection, data->ld_preload, data->ld_library_path,
                              regs_return_value(regs));
    }

out:
    if (pname_buf)
        kfree(pname_buf);

    if (stdin_buf)
        kfree(stdin_buf);

    if (stdout_buf)
        kfree(stdout_buf);

    if (buffer)
        kfree(buffer);

    if (data->free_argv)
        kfree(data->argv);

    if (pid_tree)
        kfree(pid_tree);

    if (data->free_ld_preload)
        kfree(data->ld_preload);

    if (data->free_ssh_connection)
        kfree(data->ssh_connection);

    if (data->free_ld_library_path)
        kfree(data->ld_library_path);

    if(tty)
        tty_kref_put(tty);

    return 0;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 0, 0)
//get execve syscall argv/LD_PRELOAD && SSH_CONNECTION && LD_LIBRARY_PATH env info
void get_execve_data(struct user_arg_ptr argv_ptr, struct user_arg_ptr env_ptr,
		     struct execve_data *data)
{
	int argv_len = 0, argv_res_len = 0, i = 0, len = 0, offset = 0;
	int env_len = 0, free_argv = 0, res = 0;
	int ssh_connection_flag = 0, ld_preload_flag = 0, ld_library_path_flag = 0;
	int free_ld_preload = 1, free_ssh_connection = 1, free_ld_library_path = 1;

	char *argv_res = NULL;
	char *ssh_connection = NULL;
	char *ld_preload = NULL;
    char *ld_library_path = NULL;
	const char __user *native;

	env_len = count(env_ptr, MAX_ARG_STRINGS);
	argv_len = count(argv_ptr, SMITH_MAX_ARG_STRINGS);
	argv_res_len = 256 * argv_len;

	if (argv_len > 0) {
		argv_res = kmalloc(argv_res_len + 1, GFP_ATOMIC);
		if (!argv_res) {
			argv_res = "-1";
		} else {
			free_argv = 1;
			for (i = 0; i < argv_len; i++) {
				native = get_user_arg_ptr(argv_ptr, i);
				if (IS_ERR(native))
					break;

				len = smith_strnlen_user(native, MAX_ARG_STRLEN);
				if (!len || len > MAX_ARG_STRLEN)
					break;

				if (offset + len > argv_res_len) {
				    res = argv_res_len - offset;
				    offset += res - smith_copy_from_user(argv_res + offset, native, res);
				    break;
				}

				if (smith_copy_from_user(argv_res + offset, native, len))
				    break;

				offset += len;
                *(argv_res + offset - 1) = ' ';
			}
			*(argv_res + offset) = '\0';
		}
	}

	ssh_connection = kmalloc(255, GFP_ATOMIC);
	ld_preload = kmalloc(255, GFP_ATOMIC);
    ld_library_path = kmalloc(255, GFP_ATOMIC);

	if (!ssh_connection)
		free_ssh_connection = 0;

	if (!ld_preload)
		free_ld_preload = 0;

    if (!ld_library_path)
        free_ld_library_path = 0;

	//get SSH_CONNECTION and LD_PRELOAD and LD_LIBRARY_PATH env info
	if (env_len > 0) {
		char buf[256];
		for (i = 0; i < env_len; i++) {
			if (ld_preload_flag == 1 && ssh_connection_flag == 1 && ld_library_path_flag == 1)
				break;

			native = get_user_arg_ptr(env_ptr, i);
			if (IS_ERR(native))
				continue;

			len = smith_strnlen_user(native, MAX_ARG_STRLEN);
			if (len > 11) {
				if (len > 255)
					len = 255; 
				memset(buf, 0, 256);
				if (smith_copy_from_user(buf, native, len))
					break;
				else {
					if (strncmp("SSH_CONNECTION=", buf, 15) == 0) {
						ssh_connection_flag = 1;
						if (free_ssh_connection == 1) {
							strcpy(ssh_connection, buf + 15);
						} else {
							ssh_connection = "-1";
						}
					} else if (strncmp("LD_PRELOAD=", buf, 11) == 0) {
						ld_preload_flag = 1;
						if (free_ld_preload == 1) {
							strcpy(ld_preload, buf + 11);
						} else {
							ld_preload = "-1";
						}
					} else if (strncmp("LD_LIBRARY_PATH=", buf, 16) == 0) {
                    	ld_library_path_flag = 1;
                        if (free_ld_library_path == 1) {
                        	strcpy(ld_library_path, buf + 16);
                        } else {
                        	ld_library_path = "-1";
                    	}
                    }
				}
			}
		}
	}

	if (ssh_connection_flag == 0) {
		if (free_ssh_connection == 0)
			ssh_connection = "-1";
		else
			strcpy(ssh_connection, "-1");
	}
	data->ssh_connection = ssh_connection;
	data->free_ssh_connection = free_ssh_connection;

	if (ld_preload_flag == 0) {
		if (free_ld_preload == 0)
			ld_preload = "-1";
		else
			strcpy(ld_preload, "-1");
	}
	data->ld_preload = ld_preload;
	data->free_ld_preload = free_ld_preload;

    if (ld_library_path_flag == 0) {
        if (free_ld_library_path == 0)
            ld_library_path = "-1";
        else
            strcpy(ld_library_path, "-1");
    }
    data->ld_library_path = ld_library_path;
    data->free_ld_library_path = free_ld_library_path;

	data->argv = argv_res;
	data->free_argv = free_argv;
}

#ifdef CONFIG_COMPAT
int compat_execve_entry_handler(struct kretprobe_instance *ri,
			      struct pt_regs *regs)
{
	struct user_arg_ptr argv_ptr;
	struct user_arg_ptr env_ptr;
	struct execve_data *data;
	data = (struct execve_data *)ri->data;

	argv_ptr.is_compat = true;
	argv_ptr.ptr.compat = (const compat_uptr_t __user *)p_get_arg2(regs);

	env_ptr.is_compat = true;
	env_ptr.ptr.compat = (const compat_uptr_t __user *)p_get_arg3(regs);

	get_execve_data(argv_ptr, env_ptr, data);
	return 0;
}

int compat_execveat_entry_handler(struct kretprobe_instance *ri,
				struct pt_regs *regs)
{
	struct user_arg_ptr argv_ptr;
	struct user_arg_ptr env_ptr;
	struct execve_data *data;
	data = (struct execve_data *)ri->data;

	argv_ptr.is_compat = true;
	argv_ptr.ptr.compat = (const compat_uptr_t __user *)p_get_arg3(regs);

	env_ptr.is_compat = true;
	env_ptr.ptr.compat = (const compat_uptr_t __user *)p_get_arg4(regs);

	get_execve_data(argv_ptr, env_ptr, data);
	return 0;
}
#endif

int execveat_entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct user_arg_ptr argv_ptr;
	struct user_arg_ptr env_ptr;
	struct execve_data *data;
	data = (struct execve_data *)ri->data;

	argv_ptr.ptr.native = (const char *const *)p_get_arg3(regs);
	env_ptr.ptr.native = (const char *const *)p_get_arg4(regs);

	get_execve_data(argv_ptr, env_ptr, data);
	return 0;
}

int execve_entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct user_arg_ptr argv_ptr;
	struct user_arg_ptr env_ptr;
	struct execve_data *data;
	data = (struct execve_data *)ri->data;

	argv_ptr.ptr.native = (const char *const *)p_get_arg2(regs);
	env_ptr.ptr.native = (const char *const *)p_get_arg3(regs);

	get_execve_data(argv_ptr, env_ptr, data);
	return 0;
}

#else


//get execve syscall argv/LD_PRELOAD && SSH_CONNECTION env info
void get_execve_data(char **argv, char **env, struct execve_data *data)
{
    int argv_len = 0, argv_res_len = 0, i = 0, len = 0, offset = 0, res = 0;
    int env_len = 0, free_argv = 0, ssh_connection_flag = 0, ld_preload_flag = 0, ld_library_path_flag = 0;
    int free_ssh_connection = 1, free_ld_preload = 1; free_ld_library_path = 1;

    char *argv_res = NULL;
    char *ssh_connection = NULL;
    char *ld_preload = NULL;
    char *ld_library_path = NULL;
    const char __user * native;

    env_len = execve_count(env, MAX_ARG_STRINGS);
    argv_res_len = 256 * argv_len;
    argv_len = execve_count(argv, SMITH_MAX_ARG_STRINGS);

    //get execve args data
    if (argv_len > 0) {
        argv_res = kmalloc(argv_res_len + 1, GFP_ATOMIC);
        if (!argv_res) {
            argv_res = "-1";
        } else {
            free_argv = 1;
            for (i = 0; i < argv_len; i++) {
                if (smith_get_user(native, argv + i))
                    break;

                len = smith_strnlen_user(native, MAX_ARG_STRLEN);
                if (!len || len > MAX_ARG_STRLEN)
                    break;

                if (offset + len > argv_res_len) {
                    res = argv_res_len - offset;
                    offset += res - smith_copy_from_user(argv_res + offset, native, res);
                    break;
                }

                if (smith_copy_from_user(argv_res + offset, native, len))
                    break;

                offset += len;
                *(argv_res + offset - 1) = ' ';
            }
            *(argv_res + offset) = '\0';
        }
    }

    ssh_connection = kmalloc(255, GFP_ATOMIC);
    ld_preload = kmalloc(255, GFP_ATOMIC);
    ld_library_path = kmalloc(255, GFP_ATOMIC);

    if (!ssh_connection)
        free_ssh_connection = 0;

    if (!ld_preload)
        free_ld_preload = 0;

    if (!ld_library_path)
        free_ld_library_path = 0;

    //get SSH_CONNECTION and LD_PRELOAD and LD_LIBRARY_PATH env info
    if (env_len > 0) {
        char buf[256];
        for (i = 0; i < argv_len; i++) {
            if (ld_preload_flag == 1 && ssh_connection_flag == 1 && ld_library_path_flag == 1)
                break;

            if (smith_get_user(native, env + i))
                break;

            len = smith_strnlen_user(native, MAX_ARG_STRLEN);
            if (!len || len > MAX_ARG_STRLEN)
                break;
            else if (len > 10 && len < 256) {
                memset(buf, 0, 256);
                if (smith_copy_from_user(buf, native, len))
                    break;
                else {
                    if (strncmp("SSH_CONNECTION=", buf, 11) == 0) {
                        ssh_connection_flag = 1;
                        if (free_ssh_connection == 1) {
                            strcpy(ssh_connection, buf + 15);
                        } else {
                            ssh_connection = "-1";
                        }
                    } else if (strncmp("LD_PRELOAD=", buf, 11) == 0) {
                        ld_preload_flag = 1;
                        if (free_ld_preload == 1) {
                            strcpy(ld_preload, buf + 11);
                        } else {
                            ld_preload = "-1";
                        }
                    } else if (strncmp("LD_LIBRARY_PATH=", buf, 11) == 0) {
                        ld_library_path_flag = 1;
                        if (free_ld_library_path == 1) {
                            strcpy(ld_library_path, buf + 16);
                        } else {
                            ld_library_path = "-1";
                    }
                }
            }
        }
    }

    if (ssh_connection_flag == 0) {
        if (free_ssh_connection == 0)
            ssh_connection = "-1";
        else
            strcpy(ssh_connection, "-1");
    }
    data->ssh_connection = ssh_connection;
    data->free_ssh_connection = free_ssh_connection;

    if (ld_preload_flag == 0) {
        if (free_ld_preload == 0)
            ld_preload = "-1";
        else
            strcpy(ld_preload, "-1");
    }
    data->ld_preload = ld_preload;
    data->free_ld_preload = free_ld_preload;

    if (ld_library_path_flag == 0) {
        if (free_ld_library_path == 0)
            ld_library_path = "-1";
        else
            strcpy(ld_library_path, "-1");
    }
    data->ld_library_path = ld_library_path;
    data->free_ld_library_path = free_ld_library_path;

    data->argv = argv_res;
    data->free_argv = free_argv;
}

int compat_execve_entry_handler(struct kretprobe_instance *ri,
                                struct pt_regs *regs)
{
    struct execve_data *data;
    char **argv = (char **)p_get_arg2(regs);
    char **env = (char **)p_get_arg3(regs);

    data = (struct execve_data *)ri->data;
    get_execve_data(argv, env, data);
    return 0;
}

int execve_entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct execve_data *data;
    char **argv = (char **)p_get_arg2(regs);
    char **env = (char **)p_get_arg3(regs);
    data = (struct execve_data *)ri->data;
    get_execve_data(argv, env, data);
    return 0;
}

#endif

//get create file info
int security_inode_create_pre_handler(struct kprobe *p, struct pt_regs *regs)
{
    int sa_family = -1;
    int dport = 0, sport = 0;

    __be32 dip4;
    __be32 sip4;
    pid_t socket_pid = -1;

    void *tmp;
    char *pname_buf = NULL;
    char *buffer = NULL;
    char *pathstr = DEFAULT_RET_STR;
    char *exe_path = DEFAULT_RET_STR;
    char *socket_pname = "-1";
    char *socket_pname_buf = NULL;

    struct in6_addr dip6;
    struct in6_addr sip6;

    if (IS_PRIVATE((struct inode *)p_regs_get_arg1(regs)))
        return 0;

    buffer = kzalloc(PATH_MAX, GFP_ATOMIC);
    exe_path = smith_get_exe_file(buffer, PATH_MAX);

    //exe filter check
    if (execve_exe_check(exe_path))
        goto out;

    pname_buf = kzalloc(PATH_MAX, GFP_ATOMIC);
    if (pname_buf) {
        tmp = (void *)p_regs_get_arg2(regs);
        if (IS_ERR_OR_NULL(tmp)) {
            kfree(pname_buf);
            goto out;
        }
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 38)
        pathstr = dentry_path_raw((struct dentry *)tmp, pname_buf, PATH_MAX);
#else
        pathstr = __dentry_path((struct dentry *)tmp, pname_buf, PATH_MAX);
#endif

        if(IS_ERR(pathstr))
            pathstr = NAME_TOO_LONG;
    }

    get_process_socket(&sip4, &sip6, &sport, &dip4, &dip6, &dport,
                       &socket_pname, &socket_pname_buf, &socket_pid,
                       &sa_family);

    if (sa_family == AF_INET) {
        security_inode4_create_print(exe_path, pathstr,
                                     dip4, dport, sip4, sport,
                                     socket_pid);
    }
#if IS_ENABLED(CONFIG_IPV6)
        else if (sa_family == AF_INET6) {
		security_inode6_create_print(exe_path, pathstr, &dip6,
                                     dport, &sip6, sport,
			                         socket_pid);
	}
#endif
    else {
        security_inode_create_nosocket_print(exe_path, pathstr);
    }

    if (pname_buf)
        kfree(pname_buf);

out:
    if (buffer)
        kfree(buffer);

    return 0;
}

int ptrace_pre_handler(struct kprobe *p, struct pt_regs *regs)
{
    long request;
    request = (long)p_get_arg1(regs);

    //only get PTRACE_POKETEXT/PTRACE_POKEDATA ptrace
    //Read a word at the address addr in the tracee's memory,
    //returning the word as the result of the ptrace() call.  Linux
    //does not have separate text and data address spaces, so these
    //two requests are currently equivalent.  (data is ignored; but
    //see NOTES.)

    if (request == PTRACE_POKETEXT || request == PTRACE_POKEDATA) {
        long pid;
        void *addr;
        char *exe_path = DEFAULT_RET_STR;
        char *buffer = NULL;
        char *pid_tree = NULL;

        pid = (long)p_get_arg2(regs);
        addr = (void *)p_get_arg3(regs);

        if (IS_ERR_OR_NULL(addr))
            return 0;

        buffer = kzalloc(PATH_MAX, GFP_ATOMIC);
        exe_path = smith_get_exe_file(buffer, PATH_MAX);

        pid_tree = smith_get_pid_tree(PID_TREE_LIMIT);
        ptrace_print(request, pid, addr, "-1", exe_path, pid_tree);

        if(buffer)
            kfree(buffer);

        if(pid_tree)
            kfree(pid_tree);
    }

    return 0;
}

void dns_data_transport(char *query, __be32 dip, __be32 sip, int dport,
                        int sport, int qr, int opcode, int rcode)
{
    char *exe_path = DEFAULT_RET_STR;
    char *buffer = NULL;

    buffer = kzalloc(PATH_MAX, GFP_ATOMIC);
    exe_path = smith_get_exe_file(buffer, PATH_MAX);

    //exe filter check
    if (execve_exe_check(exe_path))
        goto out;

    dns_print(dport, dip, exe_path, sip, sport, qr, opcode, rcode, query);

out:
    if (buffer)
        kfree(buffer);
}

#if IS_ENABLED(CONFIG_IPV6)
void dns6_data_transport(char *query, struct in6_addr *dip,
			 struct in6_addr *sip, int dport, int sport, int qr,
			 int opcode, int rcode)
{
	char *exe_path = DEFAULT_RET_STR;
	char *buffer = NULL;

	buffer = kzalloc(PATH_MAX, GFP_ATOMIC);
	exe_path = smith_get_exe_file(buffer, PATH_MAX);

	//exe filter check
	if (execve_exe_check(exe_path))
		goto out;

	dns6_print(dport, dip, exe_path, sip, sport, qr, opcode, rcode, query);

out:
	if (buffer)
		kfree(buffer);
}
#endif

void udp_msg_parser(struct msghdr *msg, struct udp_recvmsg_data *data) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 19, 0)
    if (msg->msg_iter.iov) {
            if (msg->msg_iter.iov->iov_len > 0) {
                data->iov_len = msg->msg_iter.iov->iov_len;
                data->iov_base = msg->msg_iter.iov->iov_base;
            }
        } else if (msg->msg_iter.kvec) {
            if (msg->msg_iter.kvec->iov_len > 0) {
                data->iov_len = msg->msg_iter.kvec->iov_len;
                data->iov_base = msg->msg_iter.kvec->iov_base;
            }
        }
#else
    if (msg->msg_iov->iov_len > 0) {
        data->iov_base = msg->msg_iov->iov_base;
        data->iov_len = msg->msg_iov->iov_len;
    }
#endif
    return;
}

int udp_recvmsg_entry_handler(struct kretprobe_instance *ri,
                              struct pt_regs *regs) {
    int flags;

    void *tmp_msg;
    void *tmp_sk;

    struct sock *sk;
    struct inet_sock *inet;
    struct msghdr *msg;
    struct udp_recvmsg_data *data;

    data = (struct udp_recvmsg_data *) ri->data;

#if LINUX_VERSION_CODE > KERNEL_VERSION(4, 0, 9)
    flags = (int)p_regs_get_arg5(regs);
#else
    flags = (int)p_regs_get_arg6(regs);
#endif
    if (flags & MSG_ERRQUEUE)
        return -EINVAL;

#if LINUX_VERSION_CODE > KERNEL_VERSION(4, 0, 9)
    tmp_sk = (void *)p_regs_get_arg1(regs);
#else
    tmp_sk = (void *)p_regs_get_arg2(regs);
#endif
    if (IS_ERR_OR_NULL(tmp_sk))
        return -EINVAL;

#if LINUX_VERSION_CODE > KERNEL_VERSION(4, 0, 9)
    tmp_msg = (void *)p_regs_get_arg2(regs);
#else
    tmp_msg = (void *)p_regs_get_arg3(regs);
#endif
    if (IS_ERR_OR_NULL(tmp_msg))
        return -EINVAL;

    msg = (struct msghdr *) tmp_msg;

    sk = (struct sock *) tmp_sk;
    inet = (struct inet_sock *) sk;

    data->sa_family = AF_INET;

    //only port == 53 or 5353 UDP data
#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 32)
    if (inet->inet_dport == 13568 || inet->inet_dport == 59668)
#else
    if (inet->dport == 13568 || inet->dport == 59668)
#endif
    {
#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 32)
        if (inet->inet_daddr) {
            data->dip4 = inet->inet_daddr;
            data->sip4 = inet->inet_saddr;
            data->sport = ntohs(inet->inet_sport);
            data->dport = ntohs(inet->inet_dport);
        }
#else
        if (inet->daddr) {
            data->dip4 = inet->daddr;
            data->sip4 = inet->saddr;
            data->sport = ntohs(inet->sport);
            data->dport = ntohs(inet->dport);
        }
#endif

        udp_msg_parser(msg, data);
        if (data->iov_len > 0)
            return 0;
#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 32)
        } else if (inet->inet_dport == 0) {
        data->msg = msg;
        data->dport = 0;
        data->sip4 = inet->inet_saddr;
        data->sport = ntohs(inet->inet_sport);
        return 0;
    }
#else
    } else if (inet->dport == 0) {
        data->msg = msg;
        data->dport = 0;
        data->sip4 = inet->saddr;
        data->sport = ntohs(inet->sport);
        return 0;
    }
#endif

    return -EINVAL;
}

#if IS_ENABLED(CONFIG_IPV6)
int udpv6_recvmsg_entry_handler(struct kretprobe_instance *ri,
				struct pt_regs *regs)
{
	struct sock *sk;
	struct inet_sock *inet;
	struct msghdr *msg;
	struct udp_recvmsg_data *data;
	void *tmp_msg;
	void *tmp_sk;
	int flags;

	data = (struct udp_recvmsg_data *)ri->data;

#if LINUX_VERSION_CODE > KERNEL_VERSION(4, 0, 9)
	flags = (int)p_regs_get_arg5(regs);
#else
	flags = (int)p_regs_get_arg6(regs);
#endif
	if (flags & MSG_ERRQUEUE)
		return -EINVAL;

#if LINUX_VERSION_CODE > KERNEL_VERSION(4, 0, 9)
	tmp_sk = (void *)p_regs_get_arg1(regs);
#else
	tmp_sk = (void *)p_regs_get_arg2(regs);
#endif

	if (IS_ERR_OR_NULL(tmp_sk))
		return -EINVAL;

#if LINUX_VERSION_CODE > KERNEL_VERSION(4, 0, 9)
    tmp_msg = (void *)p_regs_get_arg2(regs);
#else
    tmp_msg = (void *)p_regs_get_arg3(regs);
#endif
    if (IS_ERR_OR_NULL(tmp_msg))
        return -EINVAL;

    msg = (struct msghdr *)tmp_msg;
    sk = (struct sock *)tmp_sk;
	if (IS_ERR_OR_NULL(sk))
		return -EINVAL;

	inet = (struct inet_sock *)sk;
	if (IS_ERR_OR_NULL(inet))
		return -EINVAL;

	sk = (struct sock *)tmp_sk;
	inet = (struct inet_sock *)sk;

	data->sa_family = AF_INET6;
	//only get port == 53 or 5353 UDP data
#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 32)
	if (inet->inet_dport == 13568 || inet->inet_dport == 59668)
#else
	if (inet->dport == 13568 || inet->dport == 59668)
#endif
	{
#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 32)
		if (inet->inet_dport) {
			data->dip6 = &(sk->sk_v6_daddr);
			data->sip6 = &(sk->sk_v6_rcv_saddr);
			data->sport = ntohs(inet->inet_sport);
			data->dport = ntohs(inet->inet_dport);
		}
#else
		if (inet->dport) {
			data->dip6 = &(inet->pinet6->daddr);
			data->sip6 = &(inet->pinet6->saddr);
			data->sport = ntohs(inet->sport);
			data->dport = ntohs(inet->dport);
		}
#endif
        udp_msg_parser(msg, data);
		if (data->iov_len > 0)
			return 0;
#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 32)
	} else if (inet->inet_dport == 0) {
        data->msg = msg;
	    data->dport = 0;
		data->sip6 = &(sk->sk_v6_rcv_saddr);
		data->sport = ntohs(inet->inet_sport);
	    return 0;
	}
#else
	} else if (inet->dport == 0) {
        data->msg = msg;
        data->dport = 0;
    	data->sip6 = &(inet->pinet6->saddr);
		data->sport = ntohs(inet->sport);
        return 0;
    }
#endif

	return -EINVAL;
}
#endif

int udp_recvmsg_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    int qr;
    int opcode = 0, rcode = 0;
    int query_len = 0, iov_len = 512;

    char *query;
    unsigned char *recv_data = NULL;

    struct udp_recvmsg_data *data;
    struct sockaddr_in *sin;
    struct sockaddr_in6 *sin6;

    data = (struct udp_recvmsg_data *)ri->data;

    if (data->dport == 0) {
        if (IS_ERR_OR_NULL(data->msg) || IS_ERR_OR_NULL(data->msg->msg_name))
            return 0;

        if (data->sa_family == AF_INET) {
            sin = (struct sockaddr_in *) data->msg->msg_name;
            if (sin->sin_port == 13568 || sin->sin_port == 59668) {
                data->dport = sin->sin_port;
                data->dip4 = sin->sin_addr.s_addr;
                udp_msg_parser(data->msg, data);
            } else {
                return 0;
            }
#if IS_ENABLED(CONFIG_IPV6)
            } else {
            sin6 = (struct sockaddr_in6 *)data->msg->msg_name;
            if (sin6->sin6_port == 13568 || sin6->sin6_port == 59668) {
                data->dport = sin6->sin6_port;
                data->dip6 = &(sin6->sin6_addr);
                udp_msg_parser(data->msg, data);
            } else {
                return 0;
            }
        }
#else
        }
#endif
    }

    if (data->iov_len < 20)
        return 0;

    if (data->iov_len < 512)
        iov_len = data->iov_len;

    recv_data = kmalloc((iov_len + 1) * sizeof(char), GFP_ATOMIC);

    if (!recv_data)
        return 0;

    if (smith_copy_from_user(recv_data, data->iov_base, iov_len)) {
        kfree(recv_data);
        return 0;
    }
    recv_data[iov_len] = '\0';

    if (sizeof(recv_data) >= 8) {
        qr = (recv_data[2] & 0x80) ? 1 : 0;
        if (qr == 1) {
            opcode = (recv_data[2] >> 3) & 0x0f;
            rcode = recv_data[3] & 0x0f;

            query_len = strlen(recv_data + 12);

            if (query_len == 0 || query_len > 253) {
                kfree(recv_data);
                return 0;
            }

            //parser DNS protocol and get DNS query info
            query = kzalloc(query_len, GFP_ATOMIC);
            if (!query) {
                kfree(recv_data);
                return 0;
            }

            __get_dns_query(recv_data, 12, query);
            if (data->sa_family == AF_INET)
                dns_data_transport(query, data->dip4,
                                   data->sip4, data->dport,
                                   data->sport, qr, opcode,
                                   rcode);
#if IS_ENABLED(CONFIG_IPV6)
            else
				dns6_data_transport(query, data->dip6,
						            data->sip6, data->dport,
						            data->sport, qr, opcode,
						            rcode);
#endif
            kfree(query);
        }
    }

    kfree(recv_data);
    return 0;
}

int mprotect_pre_handler(struct kprobe *p, struct pt_regs *regs)
{
    int target_pid = -1;
    unsigned long prot;

    char *file_path = "-1";
    char *file_buf = NULL;
    char *vm_file_path = "-1";
    char *vm_file_buff = NULL;
    char *exe_path = "-1";
    char *abs_buf = NULL;
    char *pid_tree = NULL;

    struct vm_area_struct *vma;

    //only get PROT_EXEC mprotect info
    //The memory can be used to store instructions which can then be executed. On most architectures,
    //this flag implies that the memory can be read (as if PROT_READ had been specified).
    prot = (unsigned long)p_regs_get_arg2(regs);
    if (prot & PROT_EXEC) {
        abs_buf = kzalloc(PATH_MAX, GFP_ATOMIC);
        exe_path = smith_get_exe_file(abs_buf, PATH_MAX);

        vma = (struct vm_area_struct *)p_regs_get_arg1(regs);
        if (IS_ERR_OR_NULL(vma)) {
            mprotect_print(exe_path, prot, "-1", -1, "-1", "-1");
        } else {
            rcu_read_lock();
            if (!IS_ERR_OR_NULL(vma->vm_mm)) {
                if (!IS_ERR_OR_NULL(&vma->vm_mm->exe_file)) {
                    if (get_file_rcu(vma->vm_mm->exe_file)) {
                        file_buf = kzalloc(PATH_MAX, GFP_ATOMIC);
                        file_path = smith_d_path(&vma->vm_mm->exe_file->f_path, file_buf, PATH_MAX);
                        fput(vma->vm_mm->exe_file);
                    }
                }
#ifdef CONFIG_MEMCG
                target_pid = vma->vm_mm->owner->pid;
#endif
            }

            if (!IS_ERR_OR_NULL(vma->vm_file)) {
                if (get_file_rcu(vma->vm_file)) {
                    vm_file_buff =
                            kzalloc(PATH_MAX, GFP_ATOMIC);
                    vm_file_path = smith_d_path(&vma->vm_file->f_path, vm_file_buff, PATH_MAX);
                    fput(vma->vm_file);
                }
            }
            rcu_read_unlock();

            pid_tree = smith_get_pid_tree(PID_TREE_LIMIT);
            mprotect_print(exe_path, prot, file_path, target_pid, vm_file_path, pid_tree);
        }

        if (pid_tree)
            kfree(pid_tree);

        if (file_buf)
            kfree(file_buf);

        if (abs_buf)
            kfree(abs_buf);

        if (vm_file_buff)
            kfree(vm_file_buff);
    }
    return 0;
}

int call_usermodehelper_exec_pre_handler(struct kprobe *p, struct pt_regs *regs)
{
    int wait = 0, argv_res_len = 0, argv_len = 0, i = 0;
    int offset = 0, res = 0, free_argv = 0, len = 0;
    void *si_tmp;
    const char *path;
    char **argv;
    char *argv_res = NULL;
    char * native;
    struct subprocess_info *si;

    si_tmp = (void *)p_regs_get_arg1(regs);
    if (IS_ERR_OR_NULL(si_tmp))
        return 0;

    si = (struct subprocess_info *)si_tmp;
    wait = (int)p_regs_get_arg2(regs);

    path = si->path;
    argv = si->argv;

    if (IS_ERR_OR_NULL(path))
        return 0;

    argv_len = execve_count(argv, SMITH_MAX_ARG_STRINGS);
    argv_res_len = 256 * argv_len;

    //get execve args data
    if (argv_len > 0) {
        argv_res = kmalloc(argv_res_len + 1, GFP_ATOMIC);
        if (!argv_res) {
            argv_res = "-1";
        } else {
            free_argv = 1;
            for (i = 0; i < argv_len; i++) {
                if (smith_get_user(native, argv + i))
                    break;

                len = smith_strnlen_user(native, MAX_ARG_STRLEN);
                if (!len || len > MAX_ARG_STRLEN)
                    break;

                if (offset + len > argv_res_len) {
                    res = argv_res_len - offset;
                    offset += res - smith_copy_from_user(argv_res + offset, native, res);
                    break;
                }

                if (smith_copy_from_user(argv_res + offset, native, len))
                    break;

                offset += len;
                *(argv_res + offset - 1) = ' ';
            }
            *(argv_res + offset) = '\0';
        }
    }

    call_usermodehelper_exec_print(path, argv_res, wait);

    if(free_argv)
        kfree(argv_res);

    return 0;
}

void rename_and_link_hander(int type, const char __user * oldori, const char __user * newori)
{
    int old_len = 0;
    int new_len = 0;

    char *buffer = NULL;
    char *pname = DEFAULT_RET_STR;
    char *pname_buf = NULL;
    char *exe_path = DEFAULT_RET_STR;
    char *oldname = NULL;
    char *newname = NULL;

    if (IS_ERR_OR_NULL(oldori) || IS_ERR_OR_NULL(newori))
        return;

    new_len = smith_strnlen_user(newori, PATH_MAX);
    if (!new_len || new_len > PATH_MAX)
        return;

    old_len = smith_strnlen_user(oldori, PATH_MAX);
    if (!old_len || old_len > PATH_MAX)
        return;

    oldname = kmalloc((old_len + 1) * sizeof(char), GFP_ATOMIC);
    newname = kmalloc((new_len + 1) * sizeof(char), GFP_ATOMIC);

    if(!oldname || !newname)
        goto out_free;

    if(smith_copy_from_user(oldname, oldori, old_len) || smith_copy_from_user(newname, newori, new_len))
        goto out_free;

    oldname[old_len] = '\0';
    newname[new_len] = '\0';

    pname_buf = kzalloc(PATH_MAX, GFP_ATOMIC);
    pname = smith_d_path(&current->fs->pwd, pname_buf, PATH_MAX);

    buffer = kzalloc(PATH_MAX, GFP_ATOMIC);
    exe_path = smith_get_exe_file(buffer, PATH_MAX);

    if (execve_exe_check(exe_path))
        goto out_free;

    if (type)
        rename_print(exe_path, pname, oldname, newname);
    else
        link_print(exe_path, pname, oldname, newname);

out_free:
    if (pname_buf)
        kfree(pname_buf);

    if (buffer)
        kfree(buffer);

    if (oldname)
        kfree(oldname);

    if (newname)
        kfree(newname);
}

int rename_pre_handler(struct kprobe *p, struct pt_regs *regs)
{
    void *oldname = NULL;
    void *newname = NULL;

    oldname = (void *)p_get_arg1(regs);
    newname = (void *)p_get_arg2(regs);

    if (IS_ERR_OR_NULL(oldname) || IS_ERR_OR_NULL(newname))
        return 0;

    rename_and_link_hander(1, (const char __user *)oldname,
    (const char __user *)newname);
    return 0;
}

int renameat_pre_handler(struct kprobe *p, struct pt_regs *regs)
{
    void *oldname = NULL;
    void *newname = NULL;

    oldname = (void *)p_get_arg2(regs);
    newname = (void *)p_get_arg4(regs);

    if (IS_ERR_OR_NULL(oldname) || IS_ERR_OR_NULL(newname))
        return 0;

    rename_and_link_hander(1, (const char __user *)oldname,
    (const char __user *)newname);
    return 0;
}

int link_pre_handler(struct kprobe *p, struct pt_regs *regs)
{
    void *oldname = NULL;
    void *newname = NULL;

    oldname = (void *)p_get_arg1(regs);
    newname = (void *)p_get_arg2(regs);

    if (IS_ERR_OR_NULL(oldname) || IS_ERR_OR_NULL(newname))
        return 0;

    rename_and_link_hander(0, (const char __user *)oldname,
    (const char __user *)newname);
    return 0;
}

int linkat_pre_handler(struct kprobe *p, struct pt_regs *regs)
{
    void *oldname = NULL;
    void *newname = NULL;

    oldname = (void *)p_get_arg2(regs);
    newname = (void *)p_get_arg4(regs);

    if (IS_ERR_OR_NULL(oldname) || IS_ERR_OR_NULL(newname))
        return 0;

    rename_and_link_hander(0, (const char __user *)oldname,
    (const char __user *)newname);
    return 0;
}

int setsid_pre_handler(struct kprobe *p, struct pt_regs *regs)
{
    char *exe_path = DEFAULT_RET_STR;
    char *buffer = NULL;

    buffer = kzalloc(PATH_MAX, GFP_ATOMIC);
    exe_path = smith_get_exe_file(buffer, PATH_MAX);

    if (execve_exe_check(exe_path))
        goto out;

    setsid_print(exe_path);

out:
    if (buffer)
        kfree(buffer);

    return 0;
}

int prctl_pre_handler(struct kprobe *p, struct pt_regs *regs)
{
    char *exe_path = DEFAULT_RET_STR;
    char *buffer = NULL;
    int newname_len = 0;
    char __user *newname_ori;
    char *newname = NULL;


    //only get PS_SET_NAME data
    //PR_SET_NAME (since Linux 2.6.9)
    //Set the name of the calling thread, using the value in the lo‐
    //cation pointed to by (char *) arg2.  The name can be up to 16
    //bytes long, including the terminating null byte.  (If the
    //length of the string, including the terminating null byte, ex‐
    //ceeds 16 bytes, the string is silently truncated.)
    if (PR_SET_NAME != (int)p_get_arg1(regs))
        return 0;

    newname_ori = (void *)p_get_arg2(regs);
    if (IS_ERR_OR_NULL(newname_ori))
        return 0;

    newname_len = smith_strnlen_user((char __user *)newname_ori, PATH_MAX);
    if (!newname_len || newname_len > PATH_MAX)
        return 0;

    newname = kmalloc((newname_len + 1) * sizeof(char), GFP_ATOMIC);
    if(!newname)
        return 0;

    if(smith_copy_from_user(newname, (char __user *)newname_ori, newname_len)) {
        kfree(newname);
        return 0;
    }
    newname[newname_len] = '\0';

    buffer = kzalloc(PATH_MAX, GFP_ATOMIC);
    exe_path = smith_get_exe_file(buffer, PATH_MAX);

    if (execve_exe_check(exe_path))
        goto out;

    prctl_print(exe_path, PR_SET_NAME, newname);

out:
    if (buffer)
        kfree(buffer);

    kfree(newname);

    return 0;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 17, 0)
int memfd_create_kprobe_pre_handler(struct kprobe *p, struct pt_regs *regs)
{
    int len;
    unsigned long flags;

    char *fdname = NULL;
    char __user *fdname_ori;
    char *exe_path = DEFAULT_RET_STR;
    char *exe_buffer = NULL;

    exe_buffer = kzalloc(PATH_MAX, GFP_ATOMIC);
    exe_path = smith_get_exe_file(exe_buffer, PATH_MAX);

    fdname_ori = (void *)p_get_arg1(regs);
    if (IS_ERR_OR_NULL(fdname_ori))
        goto out;

    len = smith_strnlen_user((char __user *)fdname_ori, PATH_MAX);
    if (!len || len > PATH_MAX)
        goto out;

    fdname = kmalloc((len + 1) * sizeof(char), GFP_ATOMIC);
    if(!fdname)
        goto out;

    if(smith_copy_from_user(fdname, (char __user *)fdname_ori, len))
        goto out;

    fdname[len] = '\0';

    flags = (unsigned long)p_get_arg2(regs);
    memfd_create_print(exe_path, fdname, flags);

out:
    if (exe_buffer)
        kfree(exe_buffer);

    if (fdname)
        kfree(fdname);

    return 0;
}
#endif

int open_pre_handler(struct kprobe *p, struct pt_regs *regs)
{
    int filename_len = 0;

    char *exe_path = DEFAULT_RET_STR;
    char *buffer = NULL;
    char *filename = NULL;
    char __user *filename_ori;

    filename_ori = (void *)p_get_arg1(regs);
    if (IS_ERR_OR_NULL(filename_ori))
        return 0;

    filename_len = smith_strnlen_user((char __user *)filename_ori, PATH_MAX);
    if (!filename_len || filename_len > PATH_MAX)
        return 0;

    filename = kmalloc((filename_len + 1) * sizeof(char), GFP_ATOMIC);
    if(!filename)
        return 0;

    if(smith_copy_from_user(filename, (char __user *)filename_ori, filename_len))
    goto out;

    filename[filename_len] = '\0';

    buffer = kzalloc(PATH_MAX, GFP_ATOMIC);
    exe_path = smith_get_exe_file(buffer, PATH_MAX);

    open_print(exe_path, filename, (int)p_get_arg2(regs),
               (umode_t)p_get_arg3(regs));

out:
    if (buffer)
        kfree(buffer);

    kfree(filename);

    return 0;
}

int nanosleep_pre_handler(struct kprobe *p, struct pt_regs *regs)
{
    char *exe_path = DEFAULT_RET_STR;
    char *buffer = NULL;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 18, 0)
    struct __kernel_timespec *ts;
    struct timespec64 tu = {0, 0};
#else
    struct timespec tu = {0, 0};
#endif
    void *tmp;

    tmp = (void *)p_get_arg1(regs);
    if (IS_ERR_OR_NULL(tmp))
        return 0;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 18, 0)
    ts = (struct __kernel_timespec __user *)tmp;
    if (get_timespec64(&tu, ts))
        return 0;

    if (!timespec64_valid(&tu))
        return 0;
#else
    if (smith_copy_from_user(&tu, (void __user *)tmp, sizeof(tu)))
        return 0;
    if (!timespec_valid(&tu))
        return 0;
#endif

     buffer = kzalloc(PATH_MAX, GFP_ATOMIC);
     exe_path = smith_get_exe_file(buffer, PATH_MAX);

     /* Year-2038 issue: signed-32bit will overflow */
     nanosleep_print(exe_path, (long long)tu.tv_sec, tu.tv_nsec);

     if (buffer)
        kfree(buffer);

     return 0;
}

void kill_and_tkill_handler(int type, pid_t pid, int sig)
{
    char *exe_path = DEFAULT_RET_STR;
    char *buffer = NULL;

    buffer = kzalloc(PATH_MAX, GFP_ATOMIC);
    exe_path = smith_get_exe_file(buffer, PATH_MAX);

    if (type)
        kill_print(exe_path, pid, sig);
    else
        tkill_print(exe_path, pid, sig);

    if (buffer)
        kfree(buffer);
    return;
}

int kill_pre_handler(struct kprobe *p, struct pt_regs *regs)
{
    pid_t pid = (pid_t)p_get_arg1(regs);
    int sig = (int)p_get_arg2(regs);
    kill_and_tkill_handler(0, pid, sig);
    return 0;
}

int tkill_pre_handler(struct kprobe *p, struct pt_regs *regs)
{
    pid_t pid = (pid_t)p_get_arg1(regs);
    int sig = (int)p_get_arg2(regs);
    kill_and_tkill_handler(1, pid, sig);
    return 0;
}

void delete_file_handler(int type, char *path)
{
    char *buffer = NULL;
    char *exe_path = DEFAULT_RET_STR;

    buffer = kzalloc(PATH_MAX, GFP_ATOMIC);
    exe_path = smith_get_exe_file(buffer, PATH_MAX);

    if (type)
        security_path_rmdir_print(exe_path, path);
    else
        security_path_unlink_print(exe_path, path);

    if (buffer)
        kfree(buffer);
}

int security_path_rmdir_pre_handler(struct kprobe *p, struct pt_regs *regs)
{
    void *tmp;
    char *pname_buf = NULL;
    char *pathstr = DEFAULT_RET_STR;

    if (IS_PRIVATE((struct inode *)p_regs_get_arg1(regs)))
        return 0;

    pname_buf = kzalloc(PATH_MAX, GFP_ATOMIC);
    if (pname_buf) {
        tmp = (void *)p_regs_get_arg2(regs);
        if (IS_ERR_OR_NULL(tmp)) {
            kfree(pname_buf);
            return 0;
        }
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 38)
        pathstr = dentry_path_raw((struct dentry *)tmp, pname_buf, PATH_MAX);
#else
        pathstr = __dentry_path((struct dentry *)tmp, pname_buf, PATH_MAX);
#endif

        if (IS_ERR(pathstr))
            pathstr = "-2";
    }

    delete_file_handler(1, pathstr);

    if (pname_buf)
        kfree(pname_buf);

    return 0;
}

int security_path_unlink_pre_handler(struct kprobe *p, struct pt_regs *regs)
{
    void *tmp;
    char *pname_buf = NULL;
    char *pathstr = DEFAULT_RET_STR;

    if (IS_PRIVATE((struct inode *)p_regs_get_arg1(regs)))
        return 0;

    pname_buf = kzalloc(PATH_MAX, GFP_ATOMIC);
    if (pname_buf) {
        tmp = (void *)p_regs_get_arg2(regs);
        if (IS_ERR_OR_NULL(tmp)) {
            kfree(pname_buf);
            return 0;
        }
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 38)
        pathstr = dentry_path_raw((struct dentry *)tmp, pname_buf, PATH_MAX);
#else
        pathstr = __dentry_path((struct dentry *)tmp, pname_buf, PATH_MAX);
#endif
        if (IS_ERR(pathstr))
            pathstr = "-2";
    }

    delete_file_handler(0, pathstr);

    if (pname_buf)
        kfree(pname_buf);

    return 0;
}

void exit_handler(int type)
{
    char *exe_path = DEFAULT_RET_STR;
    char *buffer = NULL;

    buffer = kzalloc(PATH_MAX, GFP_ATOMIC);
    exe_path = smith_get_exe_file(buffer, PATH_MAX);

    if (type)
        exit_print(exe_path);
    else
        exit_group_print(exe_path);

    if (buffer)
        kfree(buffer);
    return;
}

int exit_pre_handler(struct kprobe *p, struct pt_regs *regs)
{
    exit_handler(0);
    return 0;
}

int exit_group_pre_handler(struct kprobe *p, struct pt_regs *regs)
{
    exit_handler(1);
    return 0;
}

int do_init_module_pre_handler(struct kprobe *p, struct pt_regs *regs)
{
    char *pid_tree = NULL;
    char *buffer = NULL;
    char *exe_path = DEFAULT_RET_STR;
    char *pname_buf = NULL;
    char *pname = NULL;
    void *tmp_mod;
    struct module *mod;

    tmp_mod = (void *) p_regs_get_arg1(regs);
    if (IS_ERR_OR_NULL(tmp_mod))
        return 0;

    mod = (struct module *)tmp_mod;

    buffer = kzalloc(PATH_MAX, GFP_ATOMIC);
    exe_path = smith_get_exe_file(buffer, PATH_MAX);

    pname_buf = kzalloc(PATH_MAX, GFP_ATOMIC);
    pname = smith_d_path(&current->fs->pwd, pname_buf, PATH_MAX);

    pid_tree = smith_get_pid_tree(PID_TREE_LIMIT);
    do_init_module_print(exe_path, mod->name, pid_tree, pname);

    if (buffer)
        kfree(buffer);

    if (pid_tree)
        kfree(pid_tree);

    if (pname_buf)
        kfree(pname_buf);

    return 0;
}

int update_cred_entry_handler(struct kretprobe_instance *ri,
                              struct pt_regs *regs)
{
    struct update_cred_data *data;
    data = (struct update_cred_data *)ri->data;
    data->old_uid = __get_current_uid();
    return 0;
}

int update_cred_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    int now_uid;
    int retval;
    char *exe_path = NULL;
    char *buffer = NULL;
    char *pid_tree = NULL;
    struct update_cred_data *data;

    now_uid = __get_current_uid();
    retval = regs_return_value(regs);

    //only get old uid ≠0 && new uid == 0
    if (now_uid != 0)
        return 0;

    data = (struct update_cred_data *)ri->data;
    if (data->old_uid != 0) {
        buffer = kzalloc(PATH_MAX, GFP_ATOMIC);
        exe_path = smith_get_exe_file(buffer, PATH_MAX);

        pid_tree = smith_get_pid_tree(PID_TREE_LIMIT);
        update_cred_print(exe_path, pid_tree, data->old_uid, retval);

        if (buffer)
            kfree(buffer);

        if (pid_tree)
            kfree(pid_tree);
    }
    return 0;
}

int connect_syscall_entry_handler(struct kretprobe_instance *ri,
                                  struct pt_regs *regs)
{
    struct connect_syscall_data *data;
    data = (struct connect_syscall_data *)ri->data;
    data->fd = p_get_arg1(regs);
    data->dirp = (struct sockaddr *)p_get_arg2(regs);
    return 0;
}

int tcp_v4_connect_entry_handler(struct kretprobe_instance *ri,
                                 struct pt_regs *regs)
{
    struct connect_data *data;
    data = (struct connect_data *)ri->data;
    data->sa_family = AF_INET;
    // type 1 for TCPv4
    data->type = 1;
    data->sk = (struct sock *)p_regs_get_arg1(regs);
    return 0;
}

#if IS_ENABLED(CONFIG_IPV6)
int tcp_v6_connect_entry_handler(struct kretprobe_instance *ri,
				 struct pt_regs *regs)
{
	struct connect_data *data;
	data = (struct connect_data *)ri->data;
	data->sa_family = AF_INET6;
	// type 2 for TCPv6
	data->type = 2;
	data->sk = (struct sock *)p_regs_get_arg1(regs);
	return 0;
}
#endif

int ip4_datagram_connect_entry_handler(struct kretprobe_instance *ri,
                                       struct pt_regs *regs)
{
    struct connect_data *data;
    data = (struct connect_data *)ri->data;
    data->sa_family = AF_INET;
    // type 3 for UDPv4
    data->type = 3;
    data->sk = (struct sock *)p_regs_get_arg1(regs);
    return 0;
}

#if IS_ENABLED(CONFIG_IPV6)
int ip6_datagram_connect_entry_handler(struct kretprobe_instance *ri,
				       struct pt_regs *regs)
{
	struct connect_data *data;
	data = (struct connect_data *)ri->data;
	data->sa_family = AF_INET6;
	// type 4 for UDPv6
	data->type = 4;
	data->sk = (struct sock *)p_regs_get_arg1(regs);
	return 0;
}
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 19, 0)
struct kretprobe execveat_kretprobe = {
	    .kp.symbol_name = P_GET_SYSCALL_NAME(execveat),
	    .entry_handler = execveat_entry_handler,
	    .data_size = sizeof(struct execve_data),
	    .handler = execve_handler,
};
#endif

struct kretprobe execve_kretprobe = {
        .kp.symbol_name = P_GET_SYSCALL_NAME(execve),
        .entry_handler = execve_entry_handler,
        .data_size = sizeof(struct execve_data),
        .handler = execve_handler,
};

#ifdef CONFIG_COMPAT
struct kretprobe compat_execve_kretprobe = {
	    .kp.symbol_name = P_GET_COMPAT_SYSCALL_NAME(execve),
	    .entry_handler = compat_execve_entry_handler,
	    .data_size = sizeof(struct execve_data),
	    .handler = execve_handler,
};

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,19,0)
struct kretprobe compat_execveat_kretprobe = {
	    .kp.symbol_name = P_GET_SYSCALL_NAME(execveat),
	    .entry_handler = compat_execveat_entry_handler,
	    .data_size = sizeof(struct execve_data),
	    .handler = execve_handler,
};
#endif
#endif

struct kprobe call_usermodehelper_exec_kprobe = {
        .symbol_name = "call_usermodehelper_exec",
        .pre_handler = call_usermodehelper_exec_pre_handler,
};

struct kprobe rename_kprobe = {
        .symbol_name = P_GET_SYSCALL_NAME(rename),
        .pre_handler = rename_pre_handler,
};

struct kprobe renameat_kprobe = {
        .symbol_name = P_GET_SYSCALL_NAME(renameat),
        .pre_handler = renameat_pre_handler,
};

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,15,0)
struct kprobe renameat2_kprobe = {
	    .symbol_name = P_GET_SYSCALL_NAME(renameat2),
	    .pre_handler = renameat_pre_handler,
};
#endif

struct kprobe link_kprobe = {
        .symbol_name = P_GET_SYSCALL_NAME(link),
        .pre_handler = link_pre_handler,
};

struct kprobe linkat_kprobe = {
        .symbol_name = P_GET_SYSCALL_NAME(linkat),
        .pre_handler = linkat_pre_handler,
};

struct kprobe ptrace_kprobe = {
        .symbol_name = P_GET_SYSCALL_NAME(ptrace),
        .pre_handler = ptrace_pre_handler,
};

struct kretprobe udp_recvmsg_kretprobe = {
        .kp.symbol_name = "udp_recvmsg",
        .data_size = sizeof(struct udp_recvmsg_data),
        .handler = udp_recvmsg_handler,
        .entry_handler = udp_recvmsg_entry_handler,
};

#if IS_ENABLED(CONFIG_IPV6)
struct kretprobe udpv6_recvmsg_kretprobe = {
	    .kp.symbol_name = "udpv6_recvmsg",
	    .data_size = sizeof(struct udp_recvmsg_data),
	    .handler = udp_recvmsg_handler,
	    .entry_handler = udpv6_recvmsg_entry_handler,
};

struct kretprobe ip6_datagram_connect_kretprobe = {
	    .kp.symbol_name = "ip6_datagram_connect",
	    .data_size = sizeof(struct connect_data),
	    .handler = connect_handler,
	    .entry_handler = ip6_datagram_connect_entry_handler,
};

struct kretprobe tcp_v6_connect_kretprobe = {
	    .kp.symbol_name = "tcp_v6_connect",
	    .data_size = sizeof(struct connect_data),
	    .handler = connect_handler,
	    .entry_handler = tcp_v6_connect_entry_handler,
};
#endif

struct kretprobe ip4_datagram_connect_kretprobe = {
        .kp.symbol_name = "ip4_datagram_connect",
        .data_size = sizeof(struct connect_data),
        .handler = connect_handler,
        .entry_handler = ip4_datagram_connect_entry_handler,
};

struct kretprobe tcp_v4_connect_kretprobe = {
        .kp.symbol_name = "tcp_v4_connect",
        .data_size = sizeof(struct connect_data),
        .handler = connect_handler,
        .entry_handler = tcp_v4_connect_entry_handler,
};

struct kretprobe connect_syscall_kretprobe = {
        .kp.symbol_name = P_GET_SYSCALL_NAME(connect),
        .data_size = sizeof(struct connect_syscall_data),
        .handler = connect_syscall_handler,
        .entry_handler = connect_syscall_entry_handler,
};

struct kretprobe accept_kretprobe = {
        .kp.symbol_name = P_GET_SYSCALL_NAME(accept),
        .data_size = sizeof(struct accept_data),
        .handler = accept_handler,
        .entry_handler = accept_entry_handler,
};

struct kretprobe accept4_kretprobe = {
        .kp.symbol_name = P_GET_SYSCALL_NAME(accept4),
        .data_size = sizeof(struct accept_data),
        .handler = accept_handler,
        .entry_handler = accept4_entry_handler,
};

struct kprobe do_init_module_kprobe = {
        .symbol_name = "do_init_module",
        .pre_handler = do_init_module_pre_handler,
};

struct kretprobe update_cred_kretprobe = {
        .kp.symbol_name = "commit_creds",
        .data_size = sizeof(struct update_cred_data),
        .handler = update_cred_handler,
        .entry_handler = update_cred_entry_handler,
};

struct kprobe security_inode_create_kprobe = {
        .symbol_name = "security_inode_create",
        .pre_handler = security_inode_create_pre_handler,
};

struct kretprobe bind_kretprobe = {
        .kp.symbol_name = P_GET_SYSCALL_NAME(bind),
        .data_size = sizeof(struct bind_data),
        .handler = bind_handler,
        .entry_handler = bind_entry_handler,
};

struct kprobe mprotect_kprobe = {
        .symbol_name = "security_file_mprotect",
        .pre_handler = mprotect_pre_handler,
};

struct kprobe setsid_kprobe = {
        .symbol_name = P_GET_SYSCALL_NAME(setsid),
        .pre_handler = setsid_pre_handler,
};

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 17, 0)
struct kprobe memfd_create_kprobe = {
        .symbol_name = P_GET_SYSCALL_NAME(memfd_create),
        .pre_handler = memfd_create_kprobe_pre_handler,
};
#endif

struct kprobe prctl_kprobe = {
        .symbol_name = P_GET_SYSCALL_NAME(prctl),
        .pre_handler = prctl_pre_handler,
};

struct kprobe open_kprobe = {
        .symbol_name = P_GET_SYSCALL_NAME(open),
        .pre_handler = open_pre_handler,
};

struct kprobe kill_kprobe = {
        .symbol_name = P_GET_SYSCALL_NAME(kill),
        .pre_handler = kill_pre_handler,
};

struct kprobe tkill_kprobe = {
        .symbol_name = P_GET_SYSCALL_NAME(tkill),
        .pre_handler = tkill_pre_handler,
};

struct kprobe nanosleep_kprobe = {
        .symbol_name = P_GET_SYSCALL_NAME(nanosleep),
        .pre_handler = nanosleep_pre_handler,
};

struct kprobe exit_kprobe = {
        .symbol_name = P_GET_SYSCALL_NAME(exit),
        .pre_handler = exit_pre_handler,
};

struct kprobe exit_group_kprobe = {
        .symbol_name = P_GET_SYSCALL_NAME(exit_group),
        .pre_handler = exit_group_pre_handler,
};

struct kprobe security_path_rmdir_kprobe = {
        .symbol_name = "security_path_rmdir",
        .pre_handler = security_path_rmdir_pre_handler,
};

struct kprobe security_path_unlink_kprobe = {
        .symbol_name = "security_path_unlink",
        .pre_handler = security_path_unlink_pre_handler,
};

int register_bind_kprobe(void)
{
    int ret;
    ret = register_kretprobe(&bind_kretprobe);

    if (ret == 0)
        bind_kprobe_state = 0x1;

    return ret;
}

void unregister_bind_kprobe(void)
{
    unregister_kretprobe(&bind_kretprobe);
}

int register_call_usermodehelper_exec_kprobe(void)
{
    int ret;
    ret = register_kprobe(&call_usermodehelper_exec_kprobe);

    if (ret == 0)
        call_usermodehelper_exec_kprobe_state = 0x1;

    return ret;
}

void unregister_call_usermodehelper_exec_kprobe(void)
{
    unregister_kprobe(&call_usermodehelper_exec_kprobe);
}

int register_rename_kprobe(void)
{
    int ret;
    ret = register_kprobe(&rename_kprobe);

    if (ret == 0)
        rename_kprobe_state = 0x1;

    return ret;
}

void unregister_rename_kprobe(void)
{
    unregister_kprobe(&rename_kprobe);
}

int register_renameat_kprobe(void)
{
    int ret;
    ret = register_kprobe(&renameat_kprobe);

    if (ret == 0)
        renameat_kprobe_state = 0x1;

    return ret;
}

void unregister_renameat_kprobe(void)
{
    unregister_kprobe(&renameat_kprobe);
}

int register_exit_kprobe(void)
{
    int ret;
    ret = register_kprobe(&exit_kprobe);

    if (ret == 0)
        exit_kprobe_state = 0x1;

    return ret;
}

void unregister_exit_kprobe(void)
{
    unregister_kprobe(&exit_kprobe);
}

int register_exit_group_kprobe(void)
{
    int ret;
    ret = register_kprobe(&exit_group_kprobe);

    if (ret == 0)
        exit_group_kprobe_state = 0x1;

    return ret;
}

void unregister_exit_group_kprobe(void)
{
    unregister_kprobe(&exit_group_kprobe);
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,15,0)
int register_renameat2_kprobe(void)
{
	int ret;
	ret = register_kprobe(&renameat2_kprobe);

	if (ret == 0)
		renameat2_kprobe_state = 0x1;

	return ret;
}

void unregister_renameat2_kprobe(void)
{
	unregister_kprobe(&renameat2_kprobe);
}
#endif

int register_link_kprobe(void)
{
    int ret;
    ret = register_kprobe(&link_kprobe);

    if (ret == 0)
        link_kprobe_state = 0x1;

    return ret;
}

void unregister_link_kprobe(void)
{
    unregister_kprobe(&link_kprobe);
}

int register_linkat_kprobe(void)
{
    int ret;
    ret = register_kprobe(&linkat_kprobe);

    if (ret == 0)
        linkat_kprobe_state = 0x1;

    return ret;
}

void unregister_linkat_kprobe(void)
{
    unregister_kprobe(&linkat_kprobe);
}

int register_execve_kprobe(void)
{
    int ret;
    ret = register_kretprobe(&execve_kretprobe);
    if (ret == 0)
        execve_kretprobe_state = 0x1;

    return ret;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 19, 0)
int register_execveat_kprobe(void)
{
	int ret;
	ret = register_kretprobe(&execveat_kretprobe);
	if (ret == 0)
		execveat_kretprobe_state = 0x1;

	return ret;
}
#endif

#ifdef CONFIG_COMPAT
int register_compat_execve_kprobe(void)
{
	int ret;
	ret = register_kretprobe(&compat_execve_kretprobe);
	if (ret == 0)
		compat_execve_kretprobe_state = 0x1;

	return ret;
}

void unregister_compat_execve_kprobe(void)
{
	unregister_kretprobe(&compat_execve_kretprobe);
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 19, 0)
int register_compat_execveat_kprobe(void)
{
	int ret;
	ret = register_kretprobe(&compat_execveat_kretprobe);
	if (ret == 0)
		compat_execveat_kretprobe_state = 0x1;

	return ret;
}

void unregister_compat_execveat_kprobe(void)
{
	unregister_kretprobe(&compat_execveat_kretprobe);
}
#endif
#endif

void unregister_execve_kprobe(void)
{
    unregister_kretprobe(&execve_kretprobe);
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 19, 0)
void unregister_execveat_kprobe(void)
{
	unregister_kretprobe(&execveat_kretprobe);
}
#endif

int register_ptrace_kprobe(void)
{
    int ret;
    ret = register_kprobe(&ptrace_kprobe);

    if (ret == 0)
        ptrace_kprobe_state = 0x1;

    return ret;
}

void unregister_ptrace_kprobe(void)
{
    unregister_kprobe(&ptrace_kprobe);
}

int register_udp_recvmsg_kprobe(void)
{
    int ret;
    ret = register_kretprobe(&udp_recvmsg_kretprobe);

    if (ret == 0)
        udp_recvmsg_kprobe_state = 0x1;

    return ret;
}

void unregister_udp_recvmsg_kprobe(void)
{
    unregister_kretprobe(&udp_recvmsg_kretprobe);
}

#if IS_ENABLED(CONFIG_IPV6)
int register_udpv6_recvmsg_kprobe(void)
{
	int ret;
	ret = register_kretprobe(&udpv6_recvmsg_kretprobe);

	if (ret == 0)
		udpv6_recvmsg_kprobe_state = 0x1;

	return ret;
}

void unregister_udpv6_recvmsg_kprobe(void)
{
	unregister_kretprobe(&udpv6_recvmsg_kretprobe);
}

int register_ip6_datagram_connect_kprobe(void)
{
	int ret;
	ret = register_kretprobe(&ip6_datagram_connect_kretprobe);

	if (ret == 0)
		ip6_datagram_connect_kprobe_state = 0x1;

	return ret;
}

void unregister_ip6_datagram_connect_kprobe(void)
{
	unregister_kretprobe(&ip6_datagram_connect_kretprobe);
}

int register_tcp_v6_connect_kprobe(void)
{
	int ret;
	ret = register_kretprobe(&tcp_v6_connect_kretprobe);

	if (ret == 0)
		tcp_v6_connect_kprobe_state = 0x1;

	return ret;
}

void unregister_tcp_v6_connect_kprobe(void)
{
	unregister_kretprobe(&tcp_v6_connect_kretprobe);
}
#endif

int register_ip4_datagram_connect_kprobe(void)
{
    int ret;
    ret = register_kretprobe(&ip4_datagram_connect_kretprobe);

    if (ret == 0)
        ip4_datagram_connect_kprobe_state = 0x1;

    return ret;
}

void unregister_ip4_datagram_connect_kprobe(void)
{
    unregister_kretprobe(&ip4_datagram_connect_kretprobe);
}

int register_tcp_v4_connect_kprobe(void)
{
    int ret;
    ret = register_kretprobe(&tcp_v4_connect_kretprobe);

    if (ret == 0)
        tcp_v4_connect_kprobe_state = 0x1;

    return ret;
}

void unregister_tcp_v4_connect_kprobe(void)
{
    unregister_kretprobe(&tcp_v4_connect_kretprobe);
}

int register_connect_syscall_kprobe(void)
{
    int ret;
    ret = register_kretprobe(&connect_syscall_kretprobe);

    if (ret == 0)
        connect_syscall_kprobe_state = 0x1;

    return ret;
}

void unregister_connect_syscall_kprobe(void)
{
    unregister_kretprobe(&connect_syscall_kretprobe);
}

int register_accept_kprobe(void)
{
    int ret;
    ret = register_kretprobe(&accept_kretprobe);

    if (ret == 0)
        accept_kretprobe_state = 0x1;

    return ret;
}

void unregister_accept_kprobe(void)
{
    unregister_kretprobe(&accept_kretprobe);
}

int register_accept4_kprobe(void)
{
    int ret;
    ret = register_kretprobe(&accept4_kretprobe);

    if (ret == 0)
        accept4_kretprobe_state = 0x1;

    return ret;
}

void unregister_accept4_kprobe(void)
{
    unregister_kretprobe(&accept4_kretprobe);
}

int register_create_file_kprobe(void)
{
    int ret;
    ret = register_kprobe(&security_inode_create_kprobe);
    if (ret == 0)
        create_file_kprobe_state = 0x1;

    return ret;
}

void unregister_create_file_kprobe(void)
{
    unregister_kprobe(&security_inode_create_kprobe);
}

int register_do_init_module_kprobe(void)
{
    int ret;
    ret = register_kprobe(&do_init_module_kprobe);

    if (ret == 0)
        do_init_module_kprobe_state = 0x1;

    return ret;
}

void unregister_do_init_module_kprobe(void)
{
    unregister_kprobe(&do_init_module_kprobe);
}

int register_setsid_kprobe(void)
{
    int ret;
    ret = register_kprobe(&setsid_kprobe);

    if (ret == 0)
        setsid_kprobe_state = 0x1;

    return ret;
}

void unregister_setsid_kprobe(void)
{
    unregister_kprobe(&setsid_kprobe);
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 17, 0)
int register_memfd_create_kprobe(void)
{
    int ret;
    ret = register_kprobe(&memfd_create_kprobe);

    if (ret == 0)
        memfd_create_kprobe_state = 0x1;

    return ret;
}

void unregister_memfd_create_kprobe(void)
{
    unregister_kprobe(&memfd_create_kprobe);
}
#endif

int register_prctl_kprobe(void)
{
    int ret;
    ret = register_kprobe(&prctl_kprobe);

    if (ret == 0)
        prctl_kprobe_state = 0x1;

    return ret;
}

void unregister_prctl_kprobe(void)
{
    unregister_kprobe(&prctl_kprobe);
}

int register_update_cred_kprobe(void)
{
    int ret;
    ret = register_kretprobe(&update_cred_kretprobe);
    if (ret == 0)
        update_cred_kprobe_state = 0x1;

    return ret;
}

void unregister_update_cred_kprobe(void)
{
    unregister_kretprobe(&update_cred_kretprobe);
}

int register_mprotect_kprobe(void)
{
    int ret;
    ret = register_kprobe(&mprotect_kprobe);
    if (ret == 0)
        mprotect_kprobe_state = 0x1;

    return ret;
}

void unregister_mprotect_kprobe(void)
{
    unregister_kprobe(&mprotect_kprobe);
}

int register_open_kprobe(void)
{
    int ret;
    ret = register_kprobe(&open_kprobe);
    if (ret == 0)
        open_kprobe_state = 0x1;

    return ret;
}

void unregister_open_kprobe(void)
{
    unregister_kprobe(&open_kprobe);
}

int register_nanosleep_kprobe(void)
{
    int ret;
    ret = register_kprobe(&nanosleep_kprobe);
    if (ret == 0)
        nanosleep_kprobe_state = 0x1;

    return ret;
}

void unregister_nanosleep_kprobe(void)
{
    unregister_kprobe(&nanosleep_kprobe);
}

int register_security_path_rmdir_kprobe(void)
{
    int ret;
    ret = register_kprobe(&security_path_rmdir_kprobe);
    if (ret == 0)
        security_path_rmdir_kprobe_state = 0x1;

    return ret;
}

void unregister_security_path_rmdir_kprobe(void)
{
    unregister_kprobe(&security_path_rmdir_kprobe);
}

int register_security_path_unlink_kprobe(void)
{
    int ret;
    ret = register_kprobe(&security_path_unlink_kprobe);
    if (ret == 0)
        security_path_unlink_kprobe_state = 0x1;

    return ret;
}

void unregister_security_path_unlink_kprobe(void)
{
    unregister_kprobe(&security_path_unlink_kprobe);
}

int register_kill_kprobe(void)
{
    int ret;
    ret = register_kprobe(&kill_kprobe);
    if (ret == 0)
        kill_kprobe_state = 0x1;

    return ret;
}

void unregister_kill_kprobe(void)
{
    unregister_kprobe(&kill_kprobe);
}

int register_tkill_kprobe(void)
{
    int ret;
    ret = register_kprobe(&tkill_kprobe);
    if (ret == 0)
        tkill_kprobe_state = 0x1;

    return ret;
}

void unregister_tkill_kprobe(void)
{
    unregister_kprobe(&tkill_kprobe);
}

void uninstall_kprobe(void)
{
    if (bind_kprobe_state == 0x1)
        unregister_bind_kprobe();

    if (connect_syscall_kprobe_state == 0x1)
        unregister_connect_syscall_kprobe();

    if (call_usermodehelper_exec_kprobe_state == 0x1)
        unregister_call_usermodehelper_exec_kprobe();

    if (mprotect_kprobe_state == 0x1)
        unregister_mprotect_kprobe();

    if (execve_kretprobe_state == 0x1)
        unregister_execve_kprobe();

    if (ptrace_kprobe_state == 0x1)
        unregister_ptrace_kprobe();

    if (create_file_kprobe_state == 0x1)
        unregister_create_file_kprobe();

    if (udp_recvmsg_kprobe_state == 0x1)
        unregister_udp_recvmsg_kprobe();

    if (udpv6_recvmsg_kprobe_state == 0x1)
        unregister_udpv6_recvmsg_kprobe();

    if (do_init_module_kprobe_state == 0x1)
        unregister_do_init_module_kprobe();

    if (update_cred_kprobe_state == 0x1)
        unregister_update_cred_kprobe();

    if (setsid_kprobe_state == 0x1)
        unregister_setsid_kprobe();

    if (tcp_v4_connect_kprobe_state == 0x1)
        unregister_tcp_v4_connect_kprobe();

    if (tcp_v6_connect_kprobe_state == 0x1)
        unregister_tcp_v6_connect_kprobe();

    if (ip4_datagram_connect_kprobe_state == 0x1)
        unregister_ip4_datagram_connect_kprobe();

    if (ip6_datagram_connect_kprobe_state == 0x1)
        unregister_ip6_datagram_connect_kprobe();

    if (rename_kprobe_state == 0x1)
        unregister_rename_kprobe();

    if (renameat_kprobe_state == 0x1)
        unregister_renameat_kprobe();

    if (prctl_kprobe_state == 0x1)
        unregister_prctl_kprobe();

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 17, 0)
    if (memfd_create_kprobe_state == 0x1)
        unregister_memfd_create_kprobe();
#endif

    if (accept_kretprobe_state == 0x1)
        unregister_accept_kprobe();

    if (accept4_kretprobe_state == 0x1)
        unregister_accept4_kprobe();

    if (open_kprobe_state == 0x1)
        unregister_open_kprobe();

    if (nanosleep_kprobe_state == 0x1)
        unregister_nanosleep_kprobe();

    if (kill_kprobe_state == 0x1)
        unregister_kill_kprobe();

    if (tkill_kprobe_state == 0x1)
        unregister_tkill_kprobe();

    if (exit_kprobe_state == 0x1)
        unregister_exit_kprobe();

    if (exit_group_kprobe_state == 0x1)
        unregister_exit_group_kprobe();

    if (security_path_rmdir_kprobe_state == 0x1)
        unregister_security_path_rmdir_kprobe();

    if (security_path_unlink_kprobe_state == 0x1)
        unregister_security_path_unlink_kprobe();

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 15, 0)
    if (renameat2_kprobe_state == 0x1)
		unregister_renameat2_kprobe();
#endif

    if (link_kprobe_state == 0x1)
        unregister_link_kprobe();

    if (linkat_kprobe_state == 0x1)
        unregister_linkat_kprobe();

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 19, 0)
    if (execveat_kretprobe_state == 0x1)
		unregister_execveat_kprobe();
#endif

#ifdef CONFIG_COMPAT
    if (compat_execve_kretprobe_state == 0x1)
        unregister_compat_execve_kprobe();
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 19, 0)
    if (compat_execveat_kretprobe_state == 0x1)
	    unregister_compat_execveat_kprobe();
#endif
#endif

}

void install_kprobe(void)
{
    int ret;

    if (SANDBOX == 1) {
        DNS_HOOK = 1;
        CALL_USERMODEHELPER = 1;
        //MPROTECT_HOOK = 1;
        ACCEPT_HOOK = 1;
        OPEN_HOOK = 1;
        MPROTECT_HOOK = 1;
        //NANOSLEEP_HOOK = 1;
        KILL_HOOK = 1;
        RM_HOOK = 1;
        EXIT_HOOK = 1;

        FAKE_SLEEP = 0;
        FAKE_RM = 0;

        PID_TREE_LIMIT = 100;
        PID_TREE_LIMIT_LOW = 100;
        EXECVE_GET_SOCK_PID_LIMIT = 100;
        EXECVE_GET_SOCK_FD_LIMIT = 100;

        FAKE_SLEEP = 1;
        FAKE_RM = 1;
    }

    if (RM_HOOK == 1) {
        ret = register_security_path_rmdir_kprobe();
        if (ret < 0)
            printk(KERN_INFO "[ELKEID] security_path_rmdir register_kprobe failed, returned %d\n", ret);

        ret = register_security_path_unlink_kprobe();
        if (ret < 0)
            printk(KERN_INFO "[ELKEID] security_path_unlink register_kprobe failed, returned %d\n", ret);
    }

    if (ACCEPT_HOOK == 1) {
        ret = register_accept_kprobe();
        if (ret < 0)
            printk(KERN_INFO "[ELKEID] open accept_kprobe failed, returned %d\n", ret);

        ret = register_accept4_kprobe();
        if (ret < 0)
            printk(KERN_INFO "[ELKEID] open accept4_kprobe failed, returned %d\n", ret);
    }

    if (OPEN_HOOK == 1) {
        ret = register_open_kprobe();
        if (ret < 0)
            printk(KERN_INFO "[ELKEID] open register_kprobe failed, returned %d\n", ret);
    }

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 17, 0)
    if (MEMFD_CREATE_HOOK == 1) {
        ret = register_memfd_create_kprobe();
        if (ret < 0)
            printk(KERN_INFO "[ELKEID] memfd_create register_kprobe failed, returned %d\n", ret);
    }
#endif

    if (KILL_HOOK == 1) {
        ret = register_kill_kprobe();
        if (ret < 0)
            printk(KERN_INFO "[ELKEID] open kill_kprobe failed, returned %d\n", ret);

        ret = register_tkill_kprobe();
        if (ret < 0)
            printk(KERN_INFO "[ELKEID] open tkill_kprobe failed, returned %d\n", ret);
    }

    if (EXIT_HOOK == 1) {
        ret = register_exit_kprobe();
        if (ret < 0)
            printk(KERN_INFO "[ELKEID] open exit_kprobe failed, returned %d\n", ret);

        ret = register_exit_group_kprobe();
        if (ret < 0)
            printk(KERN_INFO "[ELKEID] open exit_group_kprobe failed, returned %d\n", ret);
    }

    if (NANOSLEEP_HOOK == 1) {
        ret = register_nanosleep_kprobe();
        if (ret < 0)
            printk(KERN_INFO "[ELKEID] nanosleep register_kprobe failed, returned %d\n", ret);
    }

    if (CONNECT_HOOK == 1) {
        ret = register_connect_syscall_kprobe();
        if (ret < 0)
            printk(KERN_INFO "[ELKEID] connect register_kprobe failed, returned %d\n", ret);

//            ret = register_tcp_v4_connect_kprobe();
//            if (ret < 0)
//                printk(KERN_INFO "[ELKEID] connect register_kprobe failed, returned %d\n", ret);
//
//            ret = register_ip4_datagram_connect_kprobe();
//            if (ret < 0) {
//                printk(KERN_INFO "[ELKEID] ip4_datagram_connect register_kprobe failed, returned %d\n", ret);
//
//    #if IS_ENABLED(CONFIG_IPV6)
//            ret = register_tcp_v6_connect_kprobe();
//            if (ret < 0) {
//                printk(KERN_INFO "[ELKEID] tcp_v6_connect register_kprobe failed, returned %d\n", ret);
//
//            ret = register_ip6_datagram_connect_kprobe();
//            if (ret < 0) {
//                printk(KERN_INFO "[ELKEID] ip6_datagram_connect register_kprobe failed, returned %d\n", ret);
//    #endif
    }

    if (MPROTECT_HOOK == 1) {
        ret = register_mprotect_kprobe();
        if (ret < 0)
            printk(KERN_INFO "[ELKEID] mprotect register_kprobe failed, returned %d\n", ret);
    }

    if (PRCTL_HOOK == 1) {
        ret = register_prctl_kprobe();
        if (ret < 0)
            printk(KERN_INFO "[ELKEID] prctl register_kprobe failed, returned %d\n", ret);
    }

    if (SETSID_HOOK == 1) {
        ret = register_setsid_kprobe();
        if (ret < 0)
            printk(KERN_INFO "[ELKEID] setsid register_kprobe failed, returned %d\n", ret);
    }

    if (BIND_HOOK == 1) {
        ret = register_bind_kprobe();
        if (ret < 0)
            printk(KERN_INFO "[ELKEID] bind register_kprobe failed, returned %d\n", ret);
    }

    if (RENAME_HOOK == 1) {
        ret = register_rename_kprobe();
        if (ret < 0)
            printk(KERN_INFO "[ELKEID] renameat register_kprobe failed, returned %d\n", ret);

        ret = register_renameat_kprobe();
        if (ret < 0)
            printk(KERN_INFO "[ELKEID] rename2 register_kprobe failed, returned %d\n", ret);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,15,0)
        ret = register_renameat2_kprobe();
		if (ret < 0)
			printk(KERN_INFO "[ELKEID] mprotect register_kprobe failed, returned %d\n", ret);
#endif
    }

    if (LINK_HOOK == 1) {
        ret = register_link_kprobe();
        if (ret < 0)
            printk(KERN_INFO "[ELKEID] link register_kprobe failed, returned %d\n", ret);

        ret = register_linkat_kprobe();
        if (ret < 0)
            printk(KERN_INFO "[ELKEID] linkat register_kprobe failed, returned %d\n", ret);
    }

    if (CREATE_FILE_HOOK == 1) {
        ret = register_create_file_kprobe();
        if (ret < 0)
            printk(KERN_INFO "[ELKEID] create_file register_kprobe failed, returned %d\n", ret);
    }

    if (EXECVE_HOOK == 1) {
        ret = register_execve_kprobe();
        if (ret < 0)
            printk(KERN_INFO "[ELKEID] execve register_kprobe failed, returned %d\n", ret);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 19, 0)
        ret = register_execveat_kprobe();
		if (ret < 0)
			printk(KERN_INFO "[ELKEID] execveat register_kprobe failed, returned %d\n", ret);
#endif

#ifdef CONFIG_COMPAT
        ret = register_compat_execve_kprobe();
		if (ret < 0)
			printk(KERN_INFO "[ELKEID] compat_sys_execve register_kprobe failed, returned %d\n", ret);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 19, 0)
		ret = register_compat_execveat_kprobe();
		if (ret < 0)
			printk(KERN_INFO "[ELKEID] compat_sys_execveat register_kprobe failed, returned %d\n", ret);
#endif
#endif
    }

    if (CALL_USERMODEHELPER == 1) {
        ret = register_call_usermodehelper_exec_kprobe();
        if (ret < 0)
            printk(KERN_INFO "[ELKEID] call_usermodehelper_exec register_kprobe failed, returned %d\n", ret);
    }

    if (PTRACE_HOOK == 1) {
        ret = register_ptrace_kprobe();
        if (ret < 0)
            printk(KERN_INFO "[ELKEID] ptrace register_kprobe failed, returned %d\n", ret);
    }
#ifdef CONFIG_X86
    if (DNS_HOOK == 1) {
		ret = register_udp_recvmsg_kprobe();
		if (ret < 0)
			printk(KERN_INFO "[ELKEID] udp_recvmsg register_kprobe failed, returned %d\n", ret);
#if IS_ENABLED(CONFIG_IPV6)
		ret = register_udpv6_recvmsg_kprobe();
		if (ret < 0)
			printk(KERN_INFO "[ELKEID] udpv6_recvmsg register_kprobe failed, returned %d\n", ret);
#endif
	}
#endif

    if (DO_INIT_MODULE_HOOK == 1) {
        ret = register_do_init_module_kprobe();
        if (ret < 0)
            printk(KERN_INFO "[ELKEID] do_init_module register_kprobe failed, returned %d\n", ret);
    }

    if (UPDATE_CRED_HOOK == 1) {
        ret = register_update_cred_kprobe();
        if (ret < 0)
            printk(KERN_INFO "[ELKEID] update_cred register_kprobe failed, returned %d\n", ret);
    }
}

static int __init smith_init(void)
{
    int ret;

    ret = files_struct_symbols_init();
    if (ret)
        return ret;

    ret = filter_init();
    if (ret)
        return ret;

    printk(KERN_INFO "[ELKEID] Filter Init Success \n");

#if (EXIT_PROTECT == 1)
    exit_protect_action();
#endif

    __init_root_pid_ns_inum();

    install_kprobe();

    printk(KERN_INFO "[ELKEID] SANDBOX: %d\n", SANDBOX);

    printk(KERN_INFO
    "[ELKEID] register_kprobe success: connect_hook: %d,load_module_hook:"
    " %d,execve_hook: %d,call_usermodehekoer_hook: %d,bind_hook: %d,create_file_hook: %d,ptrace_hook: %d, update_cred_hook:"
    " %d, dns_hook: %d, accept_hook:%d, mprotect_hook: %d,link_hook: %d, memfd_create: %d, rename_hook: %d,"
    "setsid_hook:%d, prctl_hook:%d, open_hook:%d, nanosleep_hook:%d, kill_hook: %d, rm_hook: %d, "
    " EXIT_HOOK: %d, EXIT_PROTECT: %d\n",
            CONNECT_HOOK, DO_INIT_MODULE_HOOK, EXECVE_HOOK, CALL_USERMODEHELPER, BIND_HOOK,
            CREATE_FILE_HOOK, PTRACE_HOOK, UPDATE_CRED_HOOK, DNS_HOOK,
            ACCEPT_HOOK, MPROTECT_HOOK, LINK_HOOK, MEMFD_CREATE_HOOK, RENAME_HOOK, SETSID_HOOK,
            PRCTL_HOOK, OPEN_HOOK, NANOSLEEP_HOOK, KILL_HOOK, RM_HOOK, EXIT_HOOK,
            EXIT_PROTECT);

    return 0;
}

static void smith_exit(void)
{
    uninstall_kprobe();
    filter_cleanup();
    printk(KERN_INFO "[ELKEID] uninstall_kprobe success\n");
}

KPROBE_INITCALL(smith_init, smith_exit);

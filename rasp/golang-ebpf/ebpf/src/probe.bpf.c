#include "trace.h"
#include "stringify.h"
#include "config.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

SEC("uprobe/os_exec_command")
int os_exec_command(struct pt_regs *ctx) {
    pid_t pid = (pid_t) (bpf_get_current_pid_tgid() >> 32);
    probe_config *c = bpf_map_lookup_elem(&config_map, &pid);

    if (!c || c->stop[0][0])
        return 0;

    string path;
    slice args;

    if (c->register_based) {
        path.data = (const char *) GO_REGS_PARM1(ctx);
        path.length = (size_t) GO_REGS_PARM2(ctx);

        args.data = (void *) GO_REGS_PARM3(ctx);
        args.count = (go_int) GO_REGS_PARM4(ctx);
        args.capacity = (go_int) GO_REGS_PARM5(ctx);
    } else {
        if (bpf_probe_read_user(&path, sizeof(string), (void *) (PT_REGS_SP(ctx) + sizeof(uintptr_t))) < 0)
            return 0;

        if (bpf_probe_read_user(&args, sizeof(slice), (void *) (PT_REGS_SP(ctx) + sizeof(uintptr_t) + sizeof(string))) < 0)
            return 0;
    }

    probe_event *event = new_event(pid, 0, 0, 2);

    if (!event)
        return 0;

    if (stringify_string(&path, event->args[0], ARG_LENGTH) < 0) {
        free_event(event);
        return 0;
    }

    if (stringify_string_slice(&args, event->args[1], ARG_LENGTH) < 0) {
        free_event(event);
        return 0;
    }

    submit_event(ctx, c, event);

    return 0;
}

SEC("uprobe/os_exec_cmd_start")
int os_exec_cmd_start(struct pt_regs *ctx) {
    pid_t pid = (pid_t) (bpf_get_current_pid_tgid() >> 32);
    probe_config *c = bpf_map_lookup_elem(&config_map, &pid);

    if (!c || c->stop[0][1])
        return 0;

    os_exec_cmd *receiver;

    if (c->register_based) {
        receiver = (os_exec_cmd *) GO_REGS_PARM1(ctx);
    } else {
        if (bpf_probe_read_user(&receiver, sizeof(os_exec_cmd *), (void *) (PT_REGS_SP(ctx) + sizeof(uintptr_t))) < 0)
            return 0;
    }

    os_exec_cmd cmd;

    if (bpf_probe_read_user(&cmd, sizeof(os_exec_cmd), receiver) < 0)
        return 0;

    probe_event *event = new_event(pid, 0, 1, 1);

    if (!event)
        return 0;

    int n = stringify_string(&cmd.path, event->args[0], ARG_LENGTH);

    if (n < 0) {
        free_event(event);
        return 0;
    }

    if (n == ARG_LENGTH - 1) {
        submit_event(ctx, c, event);
        return 0;
    }

    event->args[0][BOUND(n , ARG_LENGTH)] = ' ';

    if (stringify_string_slice(&cmd.args, event->args[0] + BOUND(n + 1, ARG_LENGTH), ARG_LENGTH - BOUND(n + 1, ARG_LENGTH)) < 0) {
        free_event(event);
        return 0;
    }

    submit_event(ctx, c, event);

    return 0;
}

SEC("uprobe/os_openfile")
int os_openfile(struct pt_regs *ctx) {
    pid_t pid = (pid_t) (bpf_get_current_pid_tgid() >> 32);
    probe_config *c = bpf_map_lookup_elem(&config_map, &pid);

    if (!c || c->stop[1][0])
        return 0;

    string path;
    go_int flag;
    go_uint32 mode;

    if (c->register_based) {
        path.data = (const char *) GO_REGS_PARM1(ctx);
        path.length = (size_t) GO_REGS_PARM2(ctx);

        flag = (go_int) GO_REGS_PARM3(ctx);
        mode = (go_uint32) GO_REGS_PARM4(ctx);
    } else {
        if (bpf_probe_read_user(&path, sizeof(string), (void *) (PT_REGS_SP(ctx) + sizeof(uintptr_t))) < 0)
            return 0;

        if (bpf_probe_read_user(&flag, sizeof(go_int), (void *) (PT_REGS_SP(ctx) + sizeof(uintptr_t) + sizeof(string))) < 0)
            return 0;

        if (bpf_probe_read_user(&mode, sizeof(go_uint32), (void *) (PT_REGS_SP(ctx) + sizeof(uintptr_t) + sizeof(string) + sizeof(go_int))) < 0)
            return 0;
    }

    probe_event *event = new_event(pid, 1, 0, 3);

    if (!event)
        return 0;

    if (stringify_string(&path, event->args[0], ARG_LENGTH) < 0) {
        free_event(event);
        return 0;
    }

    if (stringify_go_int64(flag, event->args[1], ARG_LENGTH) < 0) {
        free_event(event);
        return 0;
    }

    if (stringify_go_uint64(mode, event->args[2], ARG_LENGTH) < 0) {
        free_event(event);
        return 0;
    }

    submit_event(ctx, c, event);

    return 0;
}

SEC("uprobe/os_remove")
int os_remove(struct pt_regs *ctx) {
    pid_t pid = (pid_t) (bpf_get_current_pid_tgid() >> 32);
    probe_config *c = bpf_map_lookup_elem(&config_map, &pid);

    if (!c || c->stop[1][1])
        return 0;

    string path;

    if (c->register_based) {
        path.data = (const char *) GO_REGS_PARM1(ctx);
        path.length = (size_t) GO_REGS_PARM2(ctx);
    } else {
        if (bpf_probe_read_user(&path, sizeof(string), (void *) (PT_REGS_SP(ctx) + sizeof(uintptr_t))) < 0)
            return 0;
    }

    probe_event *event = new_event(pid, 1, 1, 1);

    if (!event)
        return 0;

    if (stringify_string(&path, event->args[0], ARG_LENGTH) < 0) {
        free_event(event);
        return 0;
    }

    submit_event(ctx, c, event);

    return 0;
}

SEC("uprobe/os_remove_all")
int os_remove_all(struct pt_regs *ctx) {
    pid_t pid = (pid_t) (bpf_get_current_pid_tgid() >> 32);
    probe_config *c = bpf_map_lookup_elem(&config_map, &pid);

    if (!c || c->stop[1][2])
        return 0;

    string path;

    if (c->register_based) {
        path.data = (const char *) GO_REGS_PARM1(ctx);
        path.length = (size_t) GO_REGS_PARM2(ctx);
    } else {
        if (bpf_probe_read_user(&path, sizeof(string), (void *) (PT_REGS_SP(ctx) + sizeof(uintptr_t))) < 0)
            return 0;
    }

    probe_event *event = new_event(pid, 1, 2, 1);

    if (!event)
        return 0;

    if (stringify_string(&path, event->args[0], ARG_LENGTH) < 0) {
        free_event(event);
        return 0;
    }

    submit_event(ctx, c, event);

    return 0;
}

SEC("uprobe/os_rename")
int os_rename(struct pt_regs *ctx) {
    pid_t pid = (pid_t) (bpf_get_current_pid_tgid() >> 32);
    probe_config *c = bpf_map_lookup_elem(&config_map, &pid);

    if (!c || c->stop[1][3])
        return 0;

    string src;
    string dst;

    if (c->register_based) {
        src.data = (const char *) GO_REGS_PARM1(ctx);
        src.length = (size_t) GO_REGS_PARM2(ctx);

        dst.data = (const char *) GO_REGS_PARM3(ctx);
        dst.length = (size_t) GO_REGS_PARM4(ctx);
    } else {
        if (bpf_probe_read_user(&src, sizeof(string), (void *) (PT_REGS_SP(ctx) + sizeof(uintptr_t))) < 0)
            return 0;

        if (bpf_probe_read_user(&dst, sizeof(string), (void *) (PT_REGS_SP(ctx) + sizeof(uintptr_t) + sizeof(string))) < 0)
            return 0;
    }

    probe_event *event = new_event(pid, 1, 3, 2);

    if (!event)
        return 0;

    if (stringify_string(&src, event->args[0], ARG_LENGTH) < 0) {
        free_event(event);
        return 0;
    }

    if (stringify_string(&dst, event->args[1], ARG_LENGTH) < 0) {
        free_event(event);
        return 0;
    }

    submit_event(ctx, c, event);

    return 0;
}

SEC("uprobe/io_ioutil_readdir")
int io_ioutil_readdir(struct pt_regs *ctx) {
    pid_t pid = (pid_t) (bpf_get_current_pid_tgid() >> 32);
    probe_config *c = bpf_map_lookup_elem(&config_map, &pid);

    if (!c || c->stop[1][4])
        return 0;

    string path;

    if (c->register_based) {
        path.data = (const char *) GO_REGS_PARM1(ctx);
        path.length = (size_t) GO_REGS_PARM2(ctx);
    } else {
        if (bpf_probe_read_user(&path, sizeof(string), (void *) (PT_REGS_SP(ctx) + sizeof(uintptr_t))) < 0)
            return 0;
    }

    probe_event *event = new_event(pid, 1, 4, 1);

    if (!event)
        return 0;

    if (stringify_string(&path, event->args[0], ARG_LENGTH) < 0) {
        free_event(event);
        return 0;
    }

    submit_event(ctx, c, event);

    return 0;
}

SEC("uprobe/net_dial")
int net_dial(struct pt_regs *ctx) {
    pid_t pid = (pid_t) (bpf_get_current_pid_tgid() >> 32);
    probe_config *c = bpf_map_lookup_elem(&config_map, &pid);

    if (!c || c->stop[2][0])
        return 0;

    string network;
    string address;

    if (c->register_based) {
        network.data = (const char *) GO_REGS_PARM1(ctx);
        network.length = (size_t) GO_REGS_PARM2(ctx);

        address.data = (const char *) GO_REGS_PARM3(ctx);
        address.length = (size_t) GO_REGS_PARM4(ctx);
    } else {
        if (bpf_probe_read_user(&network, sizeof(string), (void *) (PT_REGS_SP(ctx) + sizeof(uintptr_t))) < 0)
            return 0;

        if (bpf_probe_read_user(&address, sizeof(string), (void *) (PT_REGS_SP(ctx) + sizeof(uintptr_t) + sizeof(string))) < 0)
            return 0;
    }

    probe_event *event = new_event(pid, 2, 0, 2);

    if (!event)
        return 0;

    if (stringify_string(&network, event->args[0], ARG_LENGTH) < 0) {
        free_event(event);
        return 0;
    }

    if (stringify_string(&address, event->args[1], ARG_LENGTH) < 0) {
        free_event(event);
        return 0;
    }

    submit_event(ctx, c, event);

    return 0;
}

SEC("uprobe/net_dial_tcp")
int net_dial_tcp(struct pt_regs *ctx) {
    pid_t pid = (pid_t) (bpf_get_current_pid_tgid() >> 32);
    probe_config *c = bpf_map_lookup_elem(&config_map, &pid);

    if (!c || c->stop[2][1])
        return 0;

    string network;
    tcp_address *remote;

    if (c->register_based) {
        network.data = (const char *) GO_REGS_PARM1(ctx);
        network.length = (size_t) GO_REGS_PARM2(ctx);

        remote = (tcp_address *) GO_REGS_PARM4(ctx);
    } else {
        if (bpf_probe_read_user(&network, sizeof(string), (void *) (PT_REGS_SP(ctx) + sizeof(uintptr_t))) < 0)
            return 0;

        if (bpf_probe_read_user(&remote, sizeof(tcp_address *), (void *) (PT_REGS_SP(ctx) + sizeof(uintptr_t) + sizeof(string) + sizeof(uintptr_t))) < 0)
            return 0;
    }

    probe_event *event = new_event(pid, 2, 1, 3);

    if (!event)
        return 0;

    if (stringify_string(&network, event->args[0], ARG_LENGTH) < 0) {
        free_event(event);
        return 0;
    }

    if (!remote) {
        free_event(event);
        return 0;
    }

    tcp_address address;

    if (bpf_probe_read_user(&address, sizeof(tcp_address), remote) < 0) {
        free_event(event);
        return 0;
    }

    if (stringify_tcp_address(&address, event->args[2], ARG_LENGTH) < 0) {
        free_event(event);
        return 0;
    }

    submit_event(ctx, c, event);

    return 0;
}

SEC("uprobe/net_dial_ip")
int net_dial_ip(struct pt_regs *ctx) {
    pid_t pid = (pid_t) (bpf_get_current_pid_tgid() >> 32);
    probe_config *c = bpf_map_lookup_elem(&config_map, &pid);

    if (!c || c->stop[2][2])
        return 0;

    string network;
    ip_address *remote;

    if (c->register_based) {
        network.data = (const char *) GO_REGS_PARM1(ctx);
        network.length = (size_t) GO_REGS_PARM2(ctx);

        remote = (ip_address *) GO_REGS_PARM4(ctx);
    } else {
        if (bpf_probe_read_user(&network, sizeof(string), (void *) (PT_REGS_SP(ctx) + sizeof(uintptr_t))) < 0)
            return 0;

        if (bpf_probe_read_user(&remote, sizeof(ip_address *), (void *) (PT_REGS_SP(ctx) + sizeof(uintptr_t) + sizeof(string) + sizeof(uintptr_t))) < 0)
            return 0;
    }

    probe_event *event = new_event(pid, 2, 2, 3);

    if (!event)
        return 0;

    if (stringify_string(&network, event->args[0], ARG_LENGTH) < 0) {
        free_event(event);
        return 0;
    }

    if (!remote) {
        free_event(event);
        return 0;
    }

    ip_address address;

    if (bpf_probe_read_user(&address, sizeof(ip_address), remote) < 0) {
        free_event(event);
        return 0;
    }

    if (stringify_ip_address(&address, event->args[2], ARG_LENGTH) < 0) {
        free_event(event);
        return 0;
    }

    submit_event(ctx, c, event);

    return 0;
}

SEC("uprobe/net_dial_udp")
int net_dial_udp(struct pt_regs *ctx) {
    pid_t pid = (pid_t) (bpf_get_current_pid_tgid() >> 32);
    probe_config *c = bpf_map_lookup_elem(&config_map, &pid);

    if (!c || c->stop[2][3])
        return 0;

    string network;
    udp_address *remote;

    if (c->register_based) {
        network.data = (const char *) GO_REGS_PARM1(ctx);
        network.length = (size_t) GO_REGS_PARM2(ctx);

        remote = (udp_address *) GO_REGS_PARM4(ctx);
    } else {
        if (bpf_probe_read_user(&network, sizeof(string), (void *) (PT_REGS_SP(ctx) + sizeof(uintptr_t))) < 0)
            return 0;

        if (bpf_probe_read_user(&remote, sizeof(udp_address *), (void *) (PT_REGS_SP(ctx) + sizeof(uintptr_t) + sizeof(string) + sizeof(uintptr_t))) < 0)
            return 0;
    }

    probe_event *event = new_event(pid, 2, 3, 3);

    if (!event)
        return 0;

    if (stringify_string(&network, event->args[0], ARG_LENGTH) < 0) {
        free_event(event);
        return 0;
    }

    if (!remote) {
        free_event(event);
        return 0;
    }

    udp_address address;

    if (bpf_probe_read_user(&address, sizeof(udp_address), remote) < 0) {
        free_event(event);
        return 0;
    }

    if (stringify_udp_address(&address, event->args[2], ARG_LENGTH) < 0) {
        free_event(event);
        return 0;
    }

    submit_event(ctx, c, event);

    return 0;
}

SEC("uprobe/net_dial_unix")
int net_dial_unix(struct pt_regs *ctx) {
    pid_t pid = (pid_t) (bpf_get_current_pid_tgid() >> 32);
    probe_config *c = bpf_map_lookup_elem(&config_map, &pid);

    if (!c || c->stop[2][4])
        return 0;

    string network;
    unix_address *remote;

    if (c->register_based) {
        network.data = (const char *) GO_REGS_PARM1(ctx);
        network.length = (size_t) GO_REGS_PARM2(ctx);

        remote = (unix_address *) GO_REGS_PARM4(ctx);
    } else {
        if (bpf_probe_read_user(&network, sizeof(string), (void *) (PT_REGS_SP(ctx) + sizeof(uintptr_t))) < 0)
            return 0;

        if (bpf_probe_read_user(&remote, sizeof(unix_address *), (void *) (PT_REGS_SP(ctx) + sizeof(uintptr_t) + sizeof(string) + sizeof(uintptr_t))) < 0)
            return 0;
    }

    probe_event *event = new_event(pid, 2, 4, 3);

    if (!event)
        return 0;

    if (stringify_string(&network, event->args[0], ARG_LENGTH) < 0) {
        free_event(event);
        return 0;
    }

    if (!remote) {
        free_event(event);
        return 0;
    }

    unix_address address;

    if (bpf_probe_read_user(&address, sizeof(unix_address), remote) < 0) {
        free_event(event);
        return 0;
    }

    if (stringify_unix_address(&address, event->args[2], ARG_LENGTH) < 0) {
        free_event(event);
        return 0;
    }

    submit_event(ctx, c, event);

    return 0;
}

SEC("uprobe/net_dialer_dial_context")
int net_dialer_dial_context(struct pt_regs *ctx) {
    pid_t pid = (pid_t) (bpf_get_current_pid_tgid() >> 32);
    probe_config *c = bpf_map_lookup_elem(&config_map, &pid);

    if (!c || c->stop[2][5])
        return 0;

    string network;
    string address;

    if (c->register_based) {
        network.data = (const char *) GO_REGS_PARM4(ctx);
        network.length = (size_t) GO_REGS_PARM5(ctx);

        address.data = (const char *) GO_REGS_PARM6(ctx);
        address.length = (size_t) GO_REGS_PARM7(ctx);
    } else {
        if (bpf_probe_read_user(&network, sizeof(string), (void *) (PT_REGS_SP(ctx) + 2 * sizeof(uintptr_t) + sizeof(interface))) < 0)
            return 0;

        if (bpf_probe_read_user(&address, sizeof(string), (void *) (PT_REGS_SP(ctx) + 2 * sizeof(uintptr_t) + sizeof(interface) + sizeof(string))) < 0)
            return 0;
    }

    probe_event *event = new_event(pid, 2, 5, 4);

    if (!event)
        return 0;

    if (stringify_string(&network, event->args[2], ARG_LENGTH) < 0) {
        free_event(event);
        return 0;
    }

    if (stringify_string(&address, event->args[3], ARG_LENGTH) < 0) {
        free_event(event);
        return 0;
    }

    submit_event(ctx, c, event);

    return 0;
}

SEC("uprobe/net_resolve_tcp_address")
int net_resolve_tcp_address(struct pt_regs *ctx) {
    pid_t pid = (pid_t) (bpf_get_current_pid_tgid() >> 32);
    probe_config *c = bpf_map_lookup_elem(&config_map, &pid);

    if (!c || c->stop[3][0])
        return 0;

    string network;
    string address;

    if (c->register_based) {
        network.data = (const char *) GO_REGS_PARM1(ctx);
        network.length = (size_t) GO_REGS_PARM2(ctx);

        address.data = (const char *) GO_REGS_PARM3(ctx);
        address.length = (size_t) GO_REGS_PARM4(ctx);
    } else {
        if (bpf_probe_read_user(&network, sizeof(string), (void *) (PT_REGS_SP(ctx) + sizeof(uintptr_t))) < 0)
            return 0;

        if (bpf_probe_read_user(&address, sizeof(string), (void *) (PT_REGS_SP(ctx) + sizeof(uintptr_t) + sizeof(string))) < 0)
            return 0;
    }

    probe_event *event = new_event(pid, 3, 0, 2);

    if (!event)
        return 0;

    if (stringify_string(&network, event->args[0], ARG_LENGTH) < 0) {
        free_event(event);
        return 0;
    }

    if (stringify_string(&address, event->args[1], ARG_LENGTH) < 0) {
        free_event(event);
        return 0;
    }

    submit_event(ctx, c, event);

    return 0;
}

SEC("uprobe/net_resolve_ip_address")
int net_resolve_ip_address(struct pt_regs *ctx) {
    pid_t pid = (pid_t) (bpf_get_current_pid_tgid() >> 32);
    probe_config *c = bpf_map_lookup_elem(&config_map, &pid);

    if (!c || c->stop[3][1])
        return 0;

    string network;
    string address;

    if (c->register_based) {
        network.data = (const char *) GO_REGS_PARM1(ctx);
        network.length = (size_t) GO_REGS_PARM2(ctx);

        address.data = (const char *) GO_REGS_PARM3(ctx);
        address.length = (size_t) GO_REGS_PARM4(ctx);
    } else {
        if (bpf_probe_read_user(&network, sizeof(string), (void *) (PT_REGS_SP(ctx) + sizeof(uintptr_t))) < 0)
            return 0;

        if (bpf_probe_read_user(&address, sizeof(string), (void *) (PT_REGS_SP(ctx) + sizeof(uintptr_t) + sizeof(string))) < 0)
            return 0;
    }

    probe_event *event = new_event(pid, 3, 1, 2);

    if (!event)
        return 0;

    if (stringify_string(&network, event->args[0], ARG_LENGTH) < 0) {
        free_event(event);
        return 0;
    }

    if (stringify_string(&address, event->args[1], ARG_LENGTH) < 0) {
        free_event(event);
        return 0;
    }

    submit_event(ctx, c, event);

    return 0;
}

SEC("uprobe/net_resolve_udp_address")
int net_resolve_udp_address(struct pt_regs *ctx) {
    pid_t pid = (pid_t) (bpf_get_current_pid_tgid() >> 32);
    probe_config *c = bpf_map_lookup_elem(&config_map, &pid);

    if (!c || c->stop[3][2])
        return 0;

    string network;
    string address;

    if (c->register_based) {
        network.data = (const char *) GO_REGS_PARM1(ctx);
        network.length = (size_t) GO_REGS_PARM2(ctx);

        address.data = (const char *) GO_REGS_PARM3(ctx);
        address.length = (size_t) GO_REGS_PARM4(ctx);
    } else {
        if (bpf_probe_read_user(&network, sizeof(string), (void *) (PT_REGS_SP(ctx) + sizeof(uintptr_t))) < 0)
            return 0;

        if (bpf_probe_read_user(&address, sizeof(string), (void *) (PT_REGS_SP(ctx) + sizeof(uintptr_t) + sizeof(string))) < 0)
            return 0;
    }

    probe_event *event = new_event(pid, 3, 2, 2);

    if (!event)
        return 0;

    if (stringify_string(&network, event->args[0], ARG_LENGTH) < 0) {
        free_event(event);
        return 0;
    }

    if (stringify_string(&address, event->args[1], ARG_LENGTH) < 0) {
        free_event(event);
        return 0;
    }

    submit_event(ctx, c, event);

    return 0;
}

SEC("uprobe/net_resolve_unix_address")
int net_resolve_unix_address(struct pt_regs *ctx) {
    pid_t pid = (pid_t) (bpf_get_current_pid_tgid() >> 32);
    probe_config *c = bpf_map_lookup_elem(&config_map, &pid);

    if (!c || c->stop[3][3])
        return 0;

    string network;
    string address;

    if (c->register_based) {
        network.data = (const char *) GO_REGS_PARM1(ctx);
        network.length = (size_t) GO_REGS_PARM2(ctx);

        address.data = (const char *) GO_REGS_PARM3(ctx);
        address.length = (size_t) GO_REGS_PARM4(ctx);
    } else {
        if (bpf_probe_read_user(&network, sizeof(string), (void *) (PT_REGS_SP(ctx) + sizeof(uintptr_t))) < 0)
            return 0;

        if (bpf_probe_read_user(&address, sizeof(string), (void *) (PT_REGS_SP(ctx) + sizeof(uintptr_t) + sizeof(string))) < 0)
            return 0;
    }

    probe_event *event = new_event(pid, 3, 3, 2);

    if (!event)
        return 0;

    if (stringify_string(&network, event->args[0], ARG_LENGTH) < 0) {
        free_event(event);
        return 0;
    }

    if (stringify_string(&address, event->args[1], ARG_LENGTH) < 0) {
        free_event(event);
        return 0;
    }

    submit_event(ctx, c, event);

    return 0;
}

SEC("uprobe/net_lookup_address")
int net_lookup_address(struct pt_regs *ctx) {
    pid_t pid = (pid_t) (bpf_get_current_pid_tgid() >> 32);
    probe_config *c = bpf_map_lookup_elem(&config_map, &pid);

    if (!c || c->stop[4][0])
        return 0;

    string address;

    if (c->register_based) {
        address.data = (const char *) GO_REGS_PARM1(ctx);
        address.length = (size_t) GO_REGS_PARM2(ctx);
    } else {
        if (bpf_probe_read_user(&address, sizeof(string), (void *) (PT_REGS_SP(ctx) + sizeof(uintptr_t))) < 0)
            return 0;
    }

    probe_event *event = new_event(pid, 4, 0, 1);

    if (!event)
        return 0;

    if (stringify_string(&address, event->args[0], ARG_LENGTH) < 0) {
        free_event(event);
        return 0;
    }

    submit_event(ctx, c, event);

    return 0;
}

SEC("uprobe/net_lookup_cname")
int net_lookup_cname(struct pt_regs *ctx) {
    pid_t pid = (pid_t) (bpf_get_current_pid_tgid() >> 32);
    probe_config *c = bpf_map_lookup_elem(&config_map, &pid);

    if (!c || c->stop[4][1])
        return 0;

    string host;

    if (c->register_based) {
        host.data = (const char *) GO_REGS_PARM1(ctx);
        host.length = (size_t) GO_REGS_PARM2(ctx);
    } else {
        if (bpf_probe_read_user(&host, sizeof(string), (void *) (PT_REGS_SP(ctx) + sizeof(uintptr_t))) < 0)
            return 0;
    }

    probe_event *event = new_event(pid, 4, 1, 1);

    if (!event)
        return 0;

    if (stringify_string(&host, event->args[0], ARG_LENGTH) < 0) {
        free_event(event);
        return 0;
    }

    submit_event(ctx, c, event);

    return 0;
}

SEC("uprobe/net_lookup_host")
int net_lookup_host(struct pt_regs *ctx) {
    pid_t pid = (pid_t) (bpf_get_current_pid_tgid() >> 32);
    probe_config *c = bpf_map_lookup_elem(&config_map, &pid);

    if (!c || c->stop[4][2])
        return 0;

    string host;

    if (c->register_based) {
        host.data = (const char *) GO_REGS_PARM1(ctx);
        host.length = (size_t) GO_REGS_PARM2(ctx);
    } else {
        if (bpf_probe_read_user(&host, sizeof(string), (void *) (PT_REGS_SP(ctx) + sizeof(uintptr_t))) < 0)
            return 0;
    }

    probe_event *event = new_event(pid, 4, 2, 1);

    if (!event)
        return 0;

    if (stringify_string(&host, event->args[0], ARG_LENGTH) < 0) {
        free_event(event);
        return 0;
    }

    submit_event(ctx, c, event);

    return 0;
}

SEC("uprobe/net_lookup_port")
int net_lookup_port(struct pt_regs *ctx) {
    pid_t pid = (pid_t) (bpf_get_current_pid_tgid() >> 32);
    probe_config *c = bpf_map_lookup_elem(&config_map, &pid);

    if (!c || c->stop[4][3])
        return 0;

    string network;
    string service;

    if (c->register_based) {
        network.data = (const char *) GO_REGS_PARM1(ctx);
        network.length = (size_t) GO_REGS_PARM2(ctx);

        service.data = (const char *) GO_REGS_PARM3(ctx);
        service.length = (size_t) GO_REGS_PARM4(ctx);
    } else {
        if (bpf_probe_read_user(&network, sizeof(string), (void *) (PT_REGS_SP(ctx) + sizeof(uintptr_t))) < 0)
            return 0;

        if (bpf_probe_read_user(&service, sizeof(string), (void *) (PT_REGS_SP(ctx) + sizeof(uintptr_t) + sizeof(string))) < 0)
            return 0;
    }

    probe_event *event = new_event(pid, 4, 3, 2);

    if (!event)
        return 0;

    if (stringify_string(&network, event->args[0], ARG_LENGTH) < 0) {
        free_event(event);
        return 0;
    }

    if (stringify_string(&service, event->args[1], ARG_LENGTH) < 0) {
        free_event(event);
        return 0;
    }

    submit_event(ctx, c, event);

    return 0;
}

SEC("uprobe/net_lookup_txt")
int net_lookup_txt(struct pt_regs *ctx) {
    pid_t pid = (pid_t) (bpf_get_current_pid_tgid() >> 32);
    probe_config *c = bpf_map_lookup_elem(&config_map, &pid);

    if (!c || c->stop[4][4])
        return 0;

    string name;

    if (c->register_based) {
        name.data = (const char *) GO_REGS_PARM1(ctx);
        name.length = (size_t) GO_REGS_PARM2(ctx);
    } else {
        if (bpf_probe_read_user(&name, sizeof(string), (void *) (PT_REGS_SP(ctx) + sizeof(uintptr_t))) < 0)
            return 0;
    }

    probe_event *event = new_event(pid, 4, 4, 1);

    if (!event)
        return 0;

    if (stringify_string(&name, event->args[0], ARG_LENGTH) < 0) {
        free_event(event);
        return 0;
    }

    submit_event(ctx, c, event);

    return 0;
}

SEC("uprobe/net_lookup_ip")
int net_lookup_ip(struct pt_regs *ctx) {
    pid_t pid = (pid_t) (bpf_get_current_pid_tgid() >> 32);
    probe_config *c = bpf_map_lookup_elem(&config_map, &pid);

    if (!c || c->stop[4][5])
        return 0;

    string host;

    if (c->register_based) {
        host.data = (const char *) GO_REGS_PARM1(ctx);
        host.length = (size_t) GO_REGS_PARM2(ctx);
    } else {
        if (bpf_probe_read_user(&host, sizeof(string), (void *) (PT_REGS_SP(ctx) + sizeof(uintptr_t))) < 0)
            return 0;
    }

    probe_event *event = new_event(pid, 4, 5, 1);

    if (!event)
        return 0;

    if (stringify_string(&host, event->args[0], ARG_LENGTH) < 0) {
        free_event(event);
        return 0;
    }

    submit_event(ctx, c, event);

    return 0;
}

SEC("uprobe/net_lookup_mx")
int net_lookup_mx(struct pt_regs *ctx) {
    pid_t pid = (pid_t) (bpf_get_current_pid_tgid() >> 32);
    probe_config *c = bpf_map_lookup_elem(&config_map, &pid);

    if (!c || c->stop[4][6])
        return 0;

    string name;

    if (c->register_based) {
        name.data = (const char *) GO_REGS_PARM1(ctx);
        name.length = (size_t) GO_REGS_PARM2(ctx);
    } else {
        if (bpf_probe_read_user(&name, sizeof(string), (void *) (PT_REGS_SP(ctx) + sizeof(uintptr_t))) < 0)
            return 0;
    }

    probe_event *event = new_event(pid, 4, 6, 1);

    if (!event)
        return 0;

    if (stringify_string(&name, event->args[0], ARG_LENGTH) < 0) {
        free_event(event);
        return 0;
    }

    submit_event(ctx, c, event);

    return 0;
}

SEC("uprobe/net_lookup_ns")
int net_lookup_ns(struct pt_regs *ctx) {
    pid_t pid = (pid_t) (bpf_get_current_pid_tgid() >> 32);
    probe_config *c = bpf_map_lookup_elem(&config_map, &pid);

    if (!c || c->stop[4][7])
        return 0;

    string name;

    if (c->register_based) {
        name.data = (const char *) GO_REGS_PARM1(ctx);
        name.length = (size_t) GO_REGS_PARM2(ctx);
    } else {
        if (bpf_probe_read_user(&name, sizeof(string), (void *) (PT_REGS_SP(ctx) + sizeof(uintptr_t))) < 0)
            return 0;
    }

    probe_event *event = new_event(pid, 4, 7, 1);

    if (!event)
        return 0;

    if (stringify_string(&name, event->args[0], ARG_LENGTH) < 0) {
        free_event(event);
        return 0;
    }

    submit_event(ctx, c, event);

    return 0;
}

SEC("uprobe/net_resolver_lookup_address")
int net_resolver_lookup_address(struct pt_regs *ctx) {
    pid_t pid = (pid_t) (bpf_get_current_pid_tgid() >> 32);
    probe_config *c = bpf_map_lookup_elem(&config_map, &pid);

    if (!c || c->stop[4][8])
        return 0;

    string address;

    if (c->register_based) {
        address.data = (const char *) GO_REGS_PARM4(ctx);
        address.length = (size_t) GO_REGS_PARM5(ctx);
    } else {
        if (bpf_probe_read_user(&address, sizeof(string), (void *) (PT_REGS_SP(ctx) + 2 * sizeof(uintptr_t) + sizeof(interface))) < 0)
            return 0;
    }

    probe_event *event = new_event(pid, 4, 8, 3);

    if (!event)
        return 0;

    if (stringify_string(&address, event->args[2], ARG_LENGTH) < 0) {
        free_event(event);
        return 0;
    }

    submit_event(ctx, c, event);

    return 0;
}

SEC("uprobe/net_resolver_lookup_cname")
int net_resolver_lookup_cname(struct pt_regs *ctx) {
    pid_t pid = (pid_t) (bpf_get_current_pid_tgid() >> 32);
    probe_config *c = bpf_map_lookup_elem(&config_map, &pid);

    if (!c || c->stop[4][9])
        return 0;

    string host;

    if (c->register_based) {
        host.data = (const char *) GO_REGS_PARM4(ctx);
        host.length = (size_t) GO_REGS_PARM5(ctx);
    } else {
        if (bpf_probe_read_user(&host, sizeof(string), (void *) (PT_REGS_SP(ctx) + 2 * sizeof(uintptr_t) + sizeof(interface))) < 0)
            return 0;
    }

    probe_event *event = new_event(pid, 4, 9, 3);

    if (!event)
        return 0;

    if (stringify_string(&host, event->args[2], ARG_LENGTH) < 0) {
        free_event(event);
        return 0;
    }

    submit_event(ctx, c, event);

    return 0;
}

SEC("uprobe/net_resolver_lookup_host")
int net_resolver_lookup_host(struct pt_regs *ctx) {
    pid_t pid = (pid_t) (bpf_get_current_pid_tgid() >> 32);
    probe_config *c = bpf_map_lookup_elem(&config_map, &pid);

    if (!c || c->stop[4][10])
        return 0;

    string host;

    if (c->register_based) {
        host.data = (const char *) GO_REGS_PARM4(ctx);
        host.length = (size_t) GO_REGS_PARM5(ctx);
    } else {
        if (bpf_probe_read_user(&host, sizeof(string), (void *) (PT_REGS_SP(ctx) + 2 * sizeof(uintptr_t) + sizeof(interface))) < 0)
            return 0;
    }

    probe_event *event = new_event(pid, 4, 10, 3);

    if (!event)
        return 0;

    if (stringify_string(&host, event->args[2], ARG_LENGTH) < 0) {
        free_event(event);
        return 0;
    }

    submit_event(ctx, c, event);

    return 0;
}

SEC("uprobe/net_resolver_lookup_port")
int net_resolver_lookup_port(struct pt_regs *ctx) {
    pid_t pid = (pid_t) (bpf_get_current_pid_tgid() >> 32);
    probe_config *c = bpf_map_lookup_elem(&config_map, &pid);

    if (!c || c->stop[4][11])
        return 0;

    string network;
    string service;

    if (c->register_based) {
        network.data = (const char *) GO_REGS_PARM4(ctx);
        network.length = (size_t) GO_REGS_PARM5(ctx);

        service.data = (const char *) GO_REGS_PARM6(ctx);
        service.length = (size_t) GO_REGS_PARM7(ctx);
    } else {
        if (bpf_probe_read_user(&network, sizeof(string), (void *) (PT_REGS_SP(ctx) + 2 * sizeof(uintptr_t) + sizeof(interface))) < 0)
            return 0;

        if (bpf_probe_read_user(&service, sizeof(string), (void *) (PT_REGS_SP(ctx) + 2 * sizeof(uintptr_t) + sizeof(interface) + sizeof(string))) < 0)
            return 0;
    }

    probe_event *event = new_event(pid, 4, 11, 4);

    if (!event)
        return 0;

    if (stringify_string(&network, event->args[2], ARG_LENGTH) < 0) {
        free_event(event);
        return 0;
    }

    if (stringify_string(&service, event->args[3], ARG_LENGTH) < 0) {
        free_event(event);
        return 0;
    }

    submit_event(ctx, c, event);

    return 0;
}

SEC("uprobe/net_resolver_lookup_txt")
int net_resolver_lookup_txt(struct pt_regs *ctx) {
    pid_t pid = (pid_t) (bpf_get_current_pid_tgid() >> 32);
    probe_config *c = bpf_map_lookup_elem(&config_map, &pid);

    if (!c || c->stop[4][12])
        return 0;

    string name;

    if (c->register_based) {
        name.data = (const char *) GO_REGS_PARM4(ctx);
        name.length = (size_t) GO_REGS_PARM5(ctx);
    } else {
        if (bpf_probe_read_user(&name, sizeof(string), (void *) (PT_REGS_SP(ctx) + 2 * sizeof(uintptr_t) + sizeof(interface))) < 0)
            return 0;
    }

    probe_event *event = new_event(pid, 4, 12, 3);

    if (!event)
        return 0;

    if (stringify_string(&name, event->args[2], ARG_LENGTH) < 0) {
        free_event(event);
        return 0;
    }

    submit_event(ctx, c, event);

    return 0;
}

SEC("uprobe/net_resolver_lookup_ip_address")
int net_resolver_lookup_ip_address(struct pt_regs *ctx) {
    pid_t pid = (pid_t) (bpf_get_current_pid_tgid() >> 32);
    probe_config *c = bpf_map_lookup_elem(&config_map, &pid);

    if (!c || c->stop[4][13])
        return 0;

    string host;

    if (c->register_based) {
        host.data = (const char *) GO_REGS_PARM4(ctx);
        host.length = (size_t) GO_REGS_PARM5(ctx);
    } else {
        if (bpf_probe_read_user(&host, sizeof(string), (void *) (PT_REGS_SP(ctx) + 2 * sizeof(uintptr_t) + sizeof(interface))) < 0)
            return 0;
    }

    probe_event *event = new_event(pid, 4, 13, 3);

    if (!event)
        return 0;

    if (stringify_string(&host, event->args[2], ARG_LENGTH) < 0) {
        free_event(event);
        return 0;
    }

    submit_event(ctx, c, event);

    return 0;
}

SEC("uprobe/net_resolver_lookup_mx")
int net_resolver_lookup_mx(struct pt_regs *ctx) {
    pid_t pid = (pid_t) (bpf_get_current_pid_tgid() >> 32);
    probe_config *c = bpf_map_lookup_elem(&config_map, &pid);

    if (!c || c->stop[4][14])
        return 0;

    string name;

    if (c->register_based) {
        name.data = (const char *) GO_REGS_PARM4(ctx);
        name.length = (size_t) GO_REGS_PARM5(ctx);
    } else {
        if (bpf_probe_read_user(&name, sizeof(string), (void *) (PT_REGS_SP(ctx) + 2 * sizeof(uintptr_t) + sizeof(interface))) < 0)
            return 0;
    }

    probe_event *event = new_event(pid, 4, 14, 3);

    if (!event)
        return 0;

    if (stringify_string(&name, event->args[2], ARG_LENGTH) < 0) {
        free_event(event);
        return 0;
    }

    submit_event(ctx, c, event);

    return 0;
}

SEC("uprobe/net_resolver_lookup_ns")
int net_resolver_lookup_ns(struct pt_regs *ctx) {
    pid_t pid = (pid_t) (bpf_get_current_pid_tgid() >> 32);
    probe_config *c = bpf_map_lookup_elem(&config_map, &pid);

    if (!c || c->stop[4][15])
        return 0;

    string name;

    if (c->register_based) {
        name.data = (const char *) GO_REGS_PARM4(ctx);
        name.length = (size_t) GO_REGS_PARM5(ctx);
    } else {
        if (bpf_probe_read_user(&name, sizeof(string), (void *) (PT_REGS_SP(ctx) + 2 * sizeof(uintptr_t) + sizeof(interface))) < 0)
            return 0;
    }

    probe_event *event = new_event(pid, 4, 15, 3);

    if (!event)
        return 0;

    if (stringify_string(&name, event->args[2], ARG_LENGTH) < 0) {
        free_event(event);
        return 0;
    }

    submit_event(ctx, c, event);

    return 0;
}

SEC("uprobe/net_listen")
int net_listen(struct pt_regs *ctx) {
    pid_t pid = (pid_t) (bpf_get_current_pid_tgid() >> 32);
    probe_config *c = bpf_map_lookup_elem(&config_map, &pid);

    if (!c || c->stop[5][0])
        return 0;

    string network;
    string address;

    if (c->register_based) {
        network.data = (const char *) GO_REGS_PARM1(ctx);
        network.length = (size_t) GO_REGS_PARM2(ctx);

        address.data = (const char *) GO_REGS_PARM3(ctx);
        address.length = (size_t) GO_REGS_PARM4(ctx);
    } else {
        if (bpf_probe_read_user(&network, sizeof(string), (void *) (PT_REGS_SP(ctx) + sizeof(uintptr_t))) < 0)
            return 0;

        if (bpf_probe_read_user(&address, sizeof(string), (void *) (PT_REGS_SP(ctx) + sizeof(uintptr_t) + sizeof(string))) < 0)
            return 0;
    }

    probe_event *event = new_event(pid, 5, 0, 2);

    if (!event)
        return 0;

    if (stringify_string(&network, event->args[0], ARG_LENGTH) < 0) {
        free_event(event);
        return 0;
    }

    if (stringify_string(&address, event->args[1], ARG_LENGTH) < 0) {
        free_event(event);
        return 0;
    }

    submit_event(ctx, c, event);

    return 0;
}

SEC("uprobe/net_listen_tcp")
int net_listen_tcp(struct pt_regs *ctx) {
    pid_t pid = (pid_t) (bpf_get_current_pid_tgid() >> 32);
    probe_config *c = bpf_map_lookup_elem(&config_map, &pid);

    if (!c || c->stop[5][1])
        return 0;

    string network;
    tcp_address *local;

    if (c->register_based) {
        network.data = (const char *) GO_REGS_PARM1(ctx);
        network.length = (size_t) GO_REGS_PARM2(ctx);

        local = (tcp_address *) GO_REGS_PARM3(ctx);
    } else {
        if (bpf_probe_read_user(&network, sizeof(string), (void *) (PT_REGS_SP(ctx) + sizeof(uintptr_t))) < 0)
            return 0;

        if (bpf_probe_read_user(&local, sizeof(tcp_address *), (void *) (PT_REGS_SP(ctx) + sizeof(uintptr_t) + sizeof(string))) < 0)
            return 0;
    }

    probe_event *event = new_event(pid, 5, 1, 2);

    if (!event)
        return 0;

    if (stringify_string(&network, event->args[0], ARG_LENGTH) < 0) {
        free_event(event);
        return 0;
    }

    if (!local) {
        free_event(event);
        return 0;
    }

    tcp_address address;

    if (bpf_probe_read_user(&address, sizeof(tcp_address), local) < 0) {
        free_event(event);
        return 0;
    }

    if (stringify_tcp_address(&address, event->args[1], ARG_LENGTH) < 0) {
        free_event(event);
        return 0;
    }

    submit_event(ctx, c, event);

    return 0;
}

SEC("uprobe/net_listen_ip")
int net_listen_ip(struct pt_regs *ctx) {
    pid_t pid = (pid_t) (bpf_get_current_pid_tgid() >> 32);
    probe_config *c = bpf_map_lookup_elem(&config_map, &pid);

    if (!c || c->stop[5][2])
        return 0;

    string network;
    ip_address *local;

    if (c->register_based) {
        network.data = (const char *) GO_REGS_PARM1(ctx);
        network.length = (size_t) GO_REGS_PARM2(ctx);

        local = (ip_address *) GO_REGS_PARM3(ctx);
    } else {
        if (bpf_probe_read_user(&network, sizeof(string), (void *) (PT_REGS_SP(ctx) + sizeof(uintptr_t))) < 0)
            return 0;

        if (bpf_probe_read_user(&local, sizeof(ip_address *), (void *) (PT_REGS_SP(ctx) + sizeof(uintptr_t) + sizeof(string))) < 0)
            return 0;
    }

    probe_event *event = new_event(pid, 5, 2, 2);

    if (!event)
        return 0;

    if (stringify_string(&network, event->args[0], ARG_LENGTH) < 0) {
        free_event(event);
        return 0;
    }

    if (!local) {
        free_event(event);
        return 0;
    }

    ip_address address;

    if (bpf_probe_read_user(&address, sizeof(ip_address), local) < 0) {
        free_event(event);
        return 0;
    }

    if (stringify_ip_address(&address, event->args[1], ARG_LENGTH) < 0) {
        free_event(event);
        return 0;
    }

    submit_event(ctx, c, event);

    return 0;
}

SEC("uprobe/net_listen_udp")
int net_listen_udp(struct pt_regs *ctx) {
    pid_t pid = (pid_t) (bpf_get_current_pid_tgid() >> 32);
    probe_config *c = bpf_map_lookup_elem(&config_map, &pid);

    if (!c || c->stop[5][3])
        return 0;

    string network;
    udp_address *local;

    if (c->register_based) {
        network.data = (const char *) GO_REGS_PARM1(ctx);
        network.length = (size_t) GO_REGS_PARM2(ctx);

        local = (udp_address *) GO_REGS_PARM3(ctx);
    } else {
        if (bpf_probe_read_user(&network, sizeof(string), (void *) (PT_REGS_SP(ctx) + sizeof(uintptr_t))) < 0)
            return 0;

        if (bpf_probe_read_user(&local, sizeof(udp_address *), (void *) (PT_REGS_SP(ctx) + sizeof(uintptr_t) + sizeof(string))) < 0)
            return 0;
    }

    probe_event *event = new_event(pid, 5, 3, 2);

    if (!event)
        return 0;

    if (stringify_string(&network, event->args[0], ARG_LENGTH) < 0) {
        free_event(event);
        return 0;
    }

    if (!local) {
        free_event(event);
        return 0;
    }

    udp_address address;

    if (bpf_probe_read_user(&address, sizeof(udp_address), local) < 0) {
        free_event(event);
        return 0;
    }

    if (stringify_udp_address(&address, event->args[1], ARG_LENGTH) < 0) {
        free_event(event);
        return 0;
    }

    submit_event(ctx, c, event);

    return 0;
}

SEC("uprobe/net_listen_unix")
int net_listen_unix(struct pt_regs *ctx) {
    pid_t pid = (pid_t) (bpf_get_current_pid_tgid() >> 32);
    probe_config *c = bpf_map_lookup_elem(&config_map, &pid);

    if (!c || c->stop[5][4])
        return 0;

    string network;
    unix_address *local;

    if (c->register_based) {
        network.data = (const char *) GO_REGS_PARM1(ctx);
        network.length = (size_t) GO_REGS_PARM2(ctx);

        local = (unix_address *) GO_REGS_PARM3(ctx);
    } else {
        if (bpf_probe_read_user(&network, sizeof(string), (void *) (PT_REGS_SP(ctx) + sizeof(uintptr_t))) < 0)
            return 0;

        if (bpf_probe_read_user(&local, sizeof(unix_address *), (void *) (PT_REGS_SP(ctx) + sizeof(uintptr_t) + sizeof(string))) < 0)
            return 0;
    }

    probe_event *event = new_event(pid, 5, 4, 2);

    if (!event)
        return 0;

    if (stringify_string(&network, event->args[0], ARG_LENGTH) < 0) {
        free_event(event);
        return 0;
    }

    if (!local) {
        free_event(event);
        return 0;
    }

    unix_address address;

    if (bpf_probe_read_user(&address, sizeof(unix_address), local) < 0) {
        free_event(event);
        return 0;
    }

    if (stringify_unix_address(&address, event->args[1], ARG_LENGTH) < 0) {
        free_event(event);
        return 0;
    }

    submit_event(ctx, c, event);

    return 0;
}

SEC("uprobe/net_http_new_request")
int net_http_new_request(struct pt_regs *ctx) {
    pid_t pid = (pid_t) (bpf_get_current_pid_tgid() >> 32);
    probe_config *c = bpf_map_lookup_elem(&config_map, &pid);

    if (!c || c->stop[6][0])
        return 0;

    string method;
    string url;

    if (c->register_based) {
        method.data = (const char *) GO_REGS_PARM1(ctx);
        method.length = (size_t) GO_REGS_PARM2(ctx);

        url.data = (const char *) GO_REGS_PARM3(ctx);
        url.length = (size_t) GO_REGS_PARM4(ctx);
    } else {
        if (bpf_probe_read_user(&method, sizeof(string), (void *) (PT_REGS_SP(ctx) + sizeof(uintptr_t))) < 0)
            return 0;

        if (bpf_probe_read_user(&url, sizeof(string), (void *) (PT_REGS_SP(ctx) + sizeof(uintptr_t) + sizeof(string))) < 0)
            return 0;
    }

    probe_event *event = new_event(pid, 6, 0, 2);

    if (!event)
        return 0;

    if (stringify_string(&method, event->args[0], ARG_LENGTH) < 0) {
        free_event(event);
        return 0;
    }

    if (stringify_string(&url, event->args[1], ARG_LENGTH) < 0) {
        free_event(event);
        return 0;
    }

    submit_event(ctx, c, event);

    return 0;
}

SEC("uprobe/net_http_new_request_with_context")
int net_http_new_request_with_context(struct pt_regs *ctx) {
    pid_t pid = (pid_t) (bpf_get_current_pid_tgid() >> 32);
    probe_config *c = bpf_map_lookup_elem(&config_map, &pid);

    if (!c || c->stop[6][1])
        return 0;

    string method;
    string url;

    if (c->register_based) {
        method.data = (const char *) GO_REGS_PARM3(ctx);
        method.length = (size_t) GO_REGS_PARM4(ctx);

        url.data = (const char *) GO_REGS_PARM5(ctx);
        url.length = (size_t) GO_REGS_PARM6(ctx);
    } else {
        if (bpf_probe_read_user(&method, sizeof(string), (void *) (PT_REGS_SP(ctx) + sizeof(uintptr_t) + sizeof(interface))) < 0)
            return 0;

        if (bpf_probe_read_user(&url, sizeof(string), (void *) (PT_REGS_SP(ctx) + sizeof(uintptr_t) + sizeof(interface) + sizeof(string))) < 0)
            return 0;
    }

    probe_event *event = new_event(pid, 6, 1, 4);

    if (!event)
        return 0;

    if (stringify_string(&method, event->args[1], ARG_LENGTH) < 0) {
        free_event(event);
        return 0;
    }

    if (stringify_string(&url, event->args[2], ARG_LENGTH) < 0) {
        free_event(event);
        return 0;
    }

    submit_event(ctx, c, event);

    return 0;
}

SEC("uprobe/plugin_open")
int plugin_open(struct pt_regs *ctx) {
    pid_t pid = (pid_t) (bpf_get_current_pid_tgid() >> 32);
    probe_config *c = bpf_map_lookup_elem(&config_map, &pid);

    if (!c || c->stop[7][0])
        return 0;

    string path;

    if (c->register_based) {
        path.data = (const char *) GO_REGS_PARM1(ctx);
        path.length = (size_t) GO_REGS_PARM2(ctx);
    } else {
        if (bpf_probe_read_user(&path, sizeof(string), (void *) (PT_REGS_SP(ctx) + sizeof(uintptr_t))) < 0)
            return 0;
    }

    probe_event *event = new_event(pid, 7, 0, 1);

    if (!event)
        return 0;

    if (stringify_string(&path, event->args[0], ARG_LENGTH) < 0) {
        free_event(event);
        return 0;
    }

    submit_event(ctx, c, event);

    return 0;
}

#ifdef ENABLE_HTTP
SEC("uprobe/on_request")
int on_request(struct pt_regs *ctx) {
    pid_t pid = (pid_t) (bpf_get_current_pid_tgid() >> 32);
    probe_config *c = bpf_map_lookup_elem(&config_map, &pid);

    if (!c)
        return 0;

    http_request *ptr;

    if (c->register_based) {
        ptr = (http_request *) GO_REGS_PARM4(ctx);
    } else {
        if (bpf_probe_read_user(&ptr, sizeof(http_request *), (void *) (PT_REGS_SP(ctx) + sizeof(uintptr_t) * 2 + sizeof(interface))) < 0)
            return 0;
    }

    probe_request *request = get_cache();

    if (!request)
        return 0;

    string str;

    if (bpf_probe_read_user(&str, sizeof(string), &ptr->method) < 0)
        return 0;

    if (stringify_string(&str, request->method, SHORT_ARG_LENGTH) < 0)
        return 0;

    if (bpf_probe_read_user(&str, sizeof(string), &ptr->request_uri) < 0)
        return 0;

    if (stringify_string(&str, request->uri, ARG_LENGTH) < 0)
        return 0;

    if (bpf_probe_read_user(&str, sizeof(string), &ptr->host) < 0)
        return 0;

    if (stringify_string(&str, request->host, SHORT_ARG_LENGTH) < 0)
        return 0;

    if (bpf_probe_read_user(&str, sizeof(string), &ptr->remote_address) < 0)
        return 0;

    if (stringify_string(&str, request->remote, SHORT_ARG_LENGTH) < 0)
        return 0;

    goroutine g = {0, 0};

    g.pid = pid;
    g.g = get_g(ctx, c, pid);

#ifndef DISABLE_HTTP_HEADER
    map *m;

    if (bpf_probe_read_user(&m, sizeof(map *), &ptr->header) < 0)
        return 0;

    map header;

    if (bpf_probe_read_user(&header, sizeof(map), m) < 0)
        return 0;

    if (header.flags & MAP_WRITING_FLAG || header.old_buckets) {
        bpf_map_update_elem(&request_map, &g, request, BPF_ANY);
        return 0;
    }

    volatile size_t count = 0;

    UNROLL_LOOP
    for (int i = 0; i < MAP_MAX_COUNT; i++) {
        if (i >= (2 ^ header.B) || count >= header.count || count >= HEADER_COUNT)
            break;

        char b[sizeof(bucket) + 8 * sizeof(string) + 8 * sizeof(slice)];

        if (bpf_probe_read_user(
                b,
                sizeof(b),
                (char *) header.buckets + i * (sizeof(bucket) + 8 * sizeof(string) + 8 * sizeof(slice))
        ) < 0)
            break;

        UNROLL_LOOP
        for (int j = 0; j < MAP_BUCKET_MAX_COUNT; j++) {
            if (!((bucket *) b)->top_bits[j])
                break;

            if (((bucket *) b)->top_bits[j] < MAP_MIN_TOP_HASH)
                continue;

            if (stringify_string(
                    (string *) (((bucket *) b)->keys + j * sizeof(string)),
                    request->headers[BOUND(count, HEADER_COUNT)][0],
                    SHORT_ARG_LENGTH
            ) < 0)
                break;

            if (stringify_string_slice(
                    (slice *) (((bucket *) b)->keys + 8 * sizeof(string) + j * sizeof(slice)),
                    request->headers[BOUND(count, HEADER_COUNT)][1],
                    SHORT_ARG_LENGTH
            ) < 0)
                break;

            count++;
        }
    }

    if (count < HEADER_COUNT)
        request->headers[BOUND(count, HEADER_COUNT)][0][0] = 0;
#endif

    bpf_map_update_elem(&request_map, &g, request, BPF_ANY);

    return 0;
}

SEC("uprobe/on_request_finished")
int on_request_finished(struct pt_regs *ctx) {
    pid_t pid = (pid_t) (bpf_get_current_pid_tgid() >> 32);
    probe_config *c = bpf_map_lookup_elem(&config_map, &pid);

    if (!c)
        return 0;

    goroutine g = {0, 0};

    g.pid = pid;
    g.g = get_g(ctx, c, pid);

    bpf_map_delete_elem(&request_map, &g);

    return 0;
}
#endif
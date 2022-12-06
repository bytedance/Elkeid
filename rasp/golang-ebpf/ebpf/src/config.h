#ifndef GO_PROBE_EBPF_CONFIG_H
#define GO_PROBE_EBPF_CONFIG_H

#include <stdbool.h>
#include <sys/types.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#define REGISTER_BASED  0x1
#define FRAME_POINTER   0x2

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, pid_t);
    __type(value, __u64);
} config_map SEC(".maps");

static __always_inline bool is_register_based(pid_t pid) {
    __u64 *config = bpf_map_lookup_elem(&config_map, &pid);

    if (!config)
        return false;

    return *config & REGISTER_BASED;
}

static __always_inline bool has_frame_pointer(pid_t pid) {
    __u64 *config = bpf_map_lookup_elem(&config_map, &pid);

    if (!config)
        return false;

    return *config & FRAME_POINTER;
}

#endif //GO_PROBE_EBPF_CONFIG_H

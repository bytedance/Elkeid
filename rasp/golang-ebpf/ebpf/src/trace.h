#ifndef GO_PROBE_EBPF_TRACE_H
#define GO_PROBE_EBPF_TRACE_H

#include <linux/bpf.h>
#include <linux/ptrace.h>
#include "event.h"
#include "macro.h"
#include "config.h"

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, pid_t);
    __type(value, probe_config);
} config_map SEC(".maps");

#ifdef ENABLE_HTTP
typedef struct {
    pid_t pid;
    uintptr_t g;
} goroutine;

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, goroutine);
    __type(value, probe_request);
} request_map SEC(".maps");
#endif

#ifdef USE_RING_BUFFER
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");
#else
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} events SEC(".maps");
#endif

#if ENABLE_HTTP || !USE_RING_BUFFER
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, 4096);
    __uint(max_entries, 1);
} cache SEC(".maps");

static __always_inline void *get_cache() {
    __u32 index = 0;
    return bpf_map_lookup_elem(&cache, &index);
}
#endif

static __always_inline uintptr_t get_g(struct pt_regs *ctx, probe_config *c, pid_t pid) {
    volatile uintptr_t g = GO_REGS_ABI_0_G(ctx);

    if (c->register_based)
        g = GO_REGS_G(ctx);

    return g;
}

static __always_inline int traceback(struct pt_regs *ctx, probe_event *event) {
    if (bpf_probe_read_user(event->stack_trace, sizeof(uintptr_t), (void *) PT_REGS_RET(ctx)) < 0)
        return -1;

    uintptr_t fp = PT_REGS_FP(ctx);

    UNROLL_LOOP
    for (int i = 1; i < TRACE_COUNT; i++) {
        if (!fp) {
            event->stack_trace[i] = 0;
            break;
        }

        if (bpf_probe_read_user(event->stack_trace + i, sizeof(uintptr_t), (void *) fp + sizeof(uintptr_t)) < 0)
            break;

        if (!event->stack_trace[i])
            break;

        if (bpf_probe_read_user(&fp, sizeof(uintptr_t), (void *) fp) < 0)
            break;
    }

    return 0;
}

static __always_inline probe_event *new_event(pid_t pid, int class_id, int method_id, int count) {
#ifdef USE_RING_BUFFER
    probe_event *event = bpf_ringbuf_reserve(&events, sizeof(probe_event), 0);
#else
    probe_event *event = get_cache();
#endif
    if (!event)
        return NULL;

    event->pid = pid;
    event->class_id = class_id;
    event->method_id = method_id;
    event->count = count;

    UNROLL_LOOP
    for (int i = 0; i < count; i++)
        event->args[i][0] = 0;

    event->stack_trace[0] = 0;

#ifdef ENABLE_HTTP
    event->request.method[0] = 0;
    event->request.uri[0] = 0;
    event->request.host[0] = 0;
    event->request.remote[0] = 0;
#ifndef DISABLE_HTTP_HEADER
    event->request.headers[0][0][0] = 0;
#endif
#endif

    return event;
}

static __always_inline void free_event(probe_event *event) {
#ifdef USE_RING_BUFFER
    bpf_ringbuf_discard(event, 0);
#endif
}

static __always_inline void submit_event(struct pt_regs *ctx, probe_config *c, probe_event *event) {
    if (c->fp && traceback(ctx, event) < 0) {
        free_event(event);
        return;
    }

#ifdef ENABLE_HTTP
    goroutine g = {0, 0};

    g.pid = event->pid;
    g.g = get_g(ctx, c, event->pid);

    probe_request *request = bpf_map_lookup_elem(&request_map, &g);

    if (request)
        __builtin_memcpy(&event->request, request, sizeof(probe_request));
#endif

#ifdef USE_RING_BUFFER
    bpf_ringbuf_submit(event, 0);
#else
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, event, sizeof(probe_event));
#endif
}

#endif //GO_PROBE_EBPF_TRACE_H

// SPDX-License-Identifier: GPL-2.0-only

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <poll.h>
#include <time.h>
#include <signal.h>
#include <fcntl.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <bpf/btf.h>
#include <linux/bpf.h>
#include <linux/btf.h>
#include "hids/hids.h"
#define __SD_XFER_DE__
#include "hids/xfer.h"

#define PERF_BUFFER_PAGES       8
#define PERF_POLL_TIMEOUT_MS	100

char g_pb_event[256] = "/sys/fs/bpf/bpfd/trace/hids/map/" PERF_BUFFER_EVENT;
char g_map_rodata[256] =  "/sys/fs/bpf/bpfd/trace/hids/map/" RODATA_SECTION_MAP;
char g_msg[SD_STR_MAX + 8];
char *g_rodata;

static void event_handling(void *ctx, int cpu, void *data, __u32 data_sz)
{
    int rec = data_sz, rc;

    rc = sd_unpack(&g_msg[0], SD_STR_MAX, data, &rec);
    if (rc > 0)
        sd_show_msg(g_msg, rc);
    else
        sd_hexdump(data, data_sz);
}

static void event_missing(void *ctx, int cpu, __u64 lost_cnt)
{
    fprintf(stderr, "Lost %llu events on CPU #%d!\n", lost_cnt, cpu);
}

int main(int argc, char **argv)
{
    struct bpf_map_info info;
    struct perf_buffer *pb;
    __u32 len = sizeof(info), rokey = 0;
    int pb_fd = -1, rodat_fd = -1, ret = 0;

    rodat_fd = bpf_obj_get(g_map_rodata);
    if (rodat_fd < 0) {
        fprintf(stderr, "ERROR: failed to located rodata: %s\n", g_map_rodata);
        goto cleanup;
    }

    memset(&info, 0, sizeof(info));
    ret = bpf_obj_get_info_by_fd(rodat_fd, &info, &len);
    if (ret) {
        ret = -errno;
        goto cleanup;
    }
    if (info.type != BPF_MAP_TYPE_ARRAY && info.max_entries != 1) {
        ret = -EINVAL;
        goto cleanup;
    }
    len = info.value_size;

    g_rodata = malloc(len);
    if (!g_rodata) {
        ret = -ENOMEM;
        goto cleanup;
    }

    /* load rodata */
    memset(g_rodata, 0, len);
    /* bpf_map_get_fd_by_id() */
    ret = bpf_map_lookup_elem(rodat_fd, &rokey, g_rodata);
    if (ret) {
        printf("failed to load rodata of fd %d: %d\n", rodat_fd, ret);
        goto cleanup;
    }

    ret = sd_init_format(g_rodata, len, -1, -1);
    if (ret) {
        printf("failed to load formats from fd %d\n", rodat_fd);
    }

    pb_fd = bpf_obj_get(g_pb_event);
    if (pb_fd < 0) {
        fprintf(stderr, "ERROR: failed to located events: %s\n", g_pb_event);
        goto cleanup;
    }

    pb = perf_buffer__new(pb_fd, PERF_BUFFER_PAGES,
                          event_handling, event_missing,
                          NULL, NULL);
    ret = libbpf_get_error(pb);
    if (ret) {
        printf("failed to setup perf_buffer: %d\n", ret);
        goto cleanup;
    }

    do {
        ret = perf_buffer__poll(pb, PERF_POLL_TIMEOUT_MS);
    } while (ret >= 0);

cleanup:

    if (g_rodata)
        free(g_rodata);
    if (pb_fd >= 0)
        close(pb_fd);
    if (rodat_fd >= 0)
        close(rodat_fd);

    return ret;
}


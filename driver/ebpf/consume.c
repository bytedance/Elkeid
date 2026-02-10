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
#include <sys/time.h>

#include <src/libbpf.h>
#include <src/bpf.h>
#include <src/btf.h>
#include <linux/bpf.h>
#include <linux/btf.h>
#include "hids/hids.h"
#include "../xfer/ring.h"

#define __SD_XFER_DE__
#include "../xfer/xfer.h"

/*
 * HIDS ebpf program version
 */
static char g_ebpf_version[16] = EBPF_PROG_VERSION;

/*
 * pinned maps in bpffs
 */

#define MAX_MAP_PATH (255)
static char g_pb_event[MAX_MAP_PATH + 1] = BPF_SYS ELK_MAP PERF_BUFFER_EVENT;
static char g_map_rodata[MAX_MAP_PATH + 1] = BPF_SYS ELK_MAP RODATA_SECTION_MAP;
static char g_trusted_cmds[MAX_MAP_PATH + 1] = BPF_SYS ELK_MAP TRUSTED_CMDS;
static char g_trusted_exes[MAX_MAP_PATH + 1] = BPF_SYS ELK_MAP TRUSTED_EXES;

struct map_item {
    char *path;
    char *name;
} control_maps[] = {
    {g_pb_event, PERF_BUFFER_EVENT},
    {g_map_rodata, RODATA_SECTION_MAP},
    {0, 0}
};

struct map_item trusted_maps[] = {
    {g_trusted_cmds, TRUSTED_CMDS},
    {g_trusted_exes, TRUSTED_EXES},
    {0, 0}
};

static int build_maps(char *control, struct map_item *maps)
{
    int i, len;

    if (!control)
        return -EINVAL;
    len = strlen(control);
    if (!len || len >= MAX_MAP_PATH)
        return -EINVAL;

    for (i = 0; maps[i].name; i++) {
        char *path = maps[i].path;
        strncpy(path, control, MAX_MAP_PATH);
        if (access(path, F_OK)) {
            printf("elkeid: path %s is not accessible.\n", path);
            return -errno;
        }
        if (path[len - 1] != '/') {
            path[len] = '/';
        }
        if (len + strlen(maps[i].name) >= MAX_MAP_PATH)
            return -EINVAL;
        strncat(path, maps[i].name, MAX_MAP_PATH);
        if (access(path, F_OK)) {
            printf("elkeid: map %s does not exist.\n", path);
            return -errno;
        }
    }

    return 0;
}

/*
 * event formats loading
 */

static struct sd_event_point *g_se_events;
static unsigned int g_num_se_events;

static char se_event_proto_start[32] = { SD_EVENT_PROTO_MAGIC };
static char se_event_point_start[32] = { SD_EVENT_POINT_MAGIC };

static int se_locate_magic(char *sd, int sz, char *ss, int ls)
{
    int i;

    for (i = 0; i < sz - ls; i++) {
        if (!memcmp(&sd[i], ss, ls))
	    return i;
    }
    return -1;
}

static int se_locate_proto(char *sd, int len)
{
    return se_locate_magic(sd, len, se_event_proto_start, 32);
}

static int se_locate_event(char *sd, int len)
{
    return se_locate_magic(sd, len, se_event_point_start, 20);
}

static int se_init_format(char *sd, int len, int proto, int event)
{
    struct sd_event_point *sep;
    uint32_t offset = 0;
    int i, rc = -ENOENT;

    proto = event = -1;
    if (proto < 0 || event <= 0) {
        proto = se_locate_proto(sd, len);
        event = se_locate_event(sd, len);
        if (event) {
            memcpy(g_ebpf_version, sd + event + 20, 12);
            DEBUG(printf("elkeid: ebpf version %s\n", g_ebpf_version));
        }
    }
    if (proto < 0|| event <= 0)
       goto out;

    sep = (struct sd_event_point *)(sd + event + 32);
    for (i = 0; sep[i].eid; i++) {
        DEBUG(printf("%4.4d: eid:%d %s\n", i, sep[i].eid, sep[i].name));
        sep[i].ent = (void *)sd + proto + 32 + offset;
        offset += sep[i].fmt;
    }
    g_se_events = sep;
    g_num_se_events = i;
    DEBUG(sd_hexdump(sd + proto, event - proto + i * sizeof(*sep)));
    rc = 0;
out:
    return rc;
}

/* return length of type meta */
static struct sd_item_ent *se_query_event(void *data, int *rec)
{
    struct sd_item_ent *head = data + sizeof(uint64_t);
    uint32_t eid = head->eid;

    if (eid > 0 && eid <= g_num_se_events) {
        struct sd_item_ent *item = g_se_events[eid - 1].ent;
        /* now we do some verifications */
        if (eid != item[0].eid || head[0].size <= item[1].meta ||
            head[1].meta != item[1].meta || head[1].xid != item[1].xid) {
            sd_hexdump(head, sizeof(*head) * 2);
            sd_hexdump(item, sizeof(*item) * 2);
            return 0;
        }
        *rec = head[0].size;
        return item;
    }

    return NULL;
}

/*
 * message consuming routines
 */

#define TB_BUFFER_SIZE  (96 * 1024UL)
static struct tb_ebpf {
    void *ctx; /* user's private context */
    struct perf_buffer *pb; /* perf buffer object */
    char *rodata; /* rodata & global formats*/
    char *pool; /* message temporary storage */
    int bufsz; /* size of message pool */
    int start; /* length of consumed message */
    int msgsz; /* valid length of saved message */
    int szfmt; /* size of global formats / rodata */
    int pbfd; /* map fd of perf buffer */
    int timeout; /* perf buffer poll timeout */

    int exe_fd; /* map fd of trusted_exes */
    int cmd_fd; /* map fd of trusted_cmds */
} g_tb_ebpf;


static void tb_fini_trace()
{
    if (g_tb_ebpf.pool)
        free(g_tb_ebpf.pool);
    g_tb_ebpf.pool = NULL;
}

static int tb_init_trace()
{
    tb_fini_trace();

    g_tb_ebpf.bufsz = TB_BUFFER_SIZE;
    g_tb_ebpf.pool = malloc(g_tb_ebpf.bufsz);
    if (!g_tb_ebpf.pool)
        return -5;

    return 0;
}

#define PERF_BUFFER_PAGES       16
#define PERF_POLL_TIMEOUT_MS	100

static void event_handling(void *ctx, int cpu, void *data, __u32 data_sz)
{
    struct sd_item_ent *head = data + sizeof(uint64_t);

    if (data_sz <= sizeof(uint64_t) + 2 * sizeof(struct sd_item_ent))
        return;
    if (data_sz < head->size) {
        DEBUG(printf("elkeid: New arriving: %u / %u remained: %u\n", data_sz, head->size, g_tb_ebpf.msgsz));
        DEBUG(sd_hexdump(data, data_sz));
        return;
    }
    if (g_tb_ebpf.msgsz + head->size <= g_tb_ebpf.bufsz) {
        memcpy(&g_tb_ebpf.pool[g_tb_ebpf.msgsz], data, head->size);
        g_tb_ebpf.msgsz += head->size;
        DEBUG(printf("elkeid: data arrived: %d / %d bytes\n", data_sz, g_tb_ebpf.msgsz));
    } else {
        /* dropped */
        printf("elkeid: data dropped: %d / %d bytes\n", data_sz, g_tb_ebpf.msgsz);
    }
}

static void event_missing(void *ctx, int cpu, __u64 lost_cnt)
{
    /* dropped */
}

int tb_init_ebpf(int dev, char *control)
{
    struct bpf_map_info info;
    struct perf_buffer *pb;
    char *rodata = NULL;
    unsigned int len = sizeof(info), rokey = 0;
    int pb_fd = -1, rodat_fd = -1, ret;

    printf("elkeid: starting ebpf loader %s ...\n", EBPF_PROG_VERSION);

    tb_init_trace();

    /* construct pathes of control maps */
    if (control && strlen(control) > 0) {
        ret = build_maps(control, control_maps);
        if (ret) {
            fprintf(stderr, "elkeid: invalid path: %s.\n", control);
            goto cleanup;
        }
    }

    /* load event formats from global rodata map */
    rodat_fd = bpf_obj_get(g_map_rodata);
    if (rodat_fd < 0) {
        fprintf(stderr, "elkeid: failed to located rodata: %s\n", g_map_rodata);
        goto cleanup;
    }

    memset(&info, 0, sizeof(info));
    ret = bpf_obj_get_info_by_fd(rodat_fd, &info, &len);
    if (ret) {
        ret = -errno;
        goto cleanup;
    }
    if (info.type != BPF_MAP_TYPE_ARRAY ||
        info.max_entries != 1 || !info.value_size) {
        ret = -EINVAL;
        goto cleanup;
    }
    len = info.value_size;

    rodata = malloc(len);
    if (!rodata) {
        ret = -ENOMEM;
        goto cleanup;
    }

    /* load rodata */
    memset(rodata, 0, len);
    ret = bpf_map_lookup_elem(rodat_fd, &rokey, rodata);
    if (ret) {
        printf("elkeid: failed to load rodata of fd %d: %d\n", rodat_fd, ret);
        goto cleanup;
    }

    ret = se_init_format(rodata, len, -1, -1);
    if (ret) {
        printf("elkeid: failed to load formats from fd %d\n", rodat_fd);
    }

    /* open and initialize events */
    pb_fd = bpf_obj_get(g_pb_event);
    if (pb_fd < 0) {
        fprintf(stderr, "elkeid: failed to located events: %s\n", g_pb_event);
        goto cleanup;
    }

    pb = perf_buffer__new(pb_fd, PERF_BUFFER_PAGES,
                          event_handling, event_missing,
                          &g_tb_ebpf, NULL);
    if (!pb) {
        ret = libbpf_get_error(pb);
        printf("elkeid: failed to setup perf_buffer: %d\n", ret);
        goto cleanup;
    }

    /* saving fd and rodata for cleaning up */
    g_tb_ebpf.rodata = rodata;
    g_tb_ebpf.pbfd = pb_fd;
    g_tb_ebpf.pb = pb;
    g_tb_ebpf.timeout = PERF_POLL_TIMEOUT_MS;

    /* close map fd of rodata */
    close(rodat_fd);

    printf("elkeid: ebpf module %s loaded.\n", g_ebpf_version);

    return 0;

cleanup:

    if (rodat_fd >= 0)
        close(rodat_fd);
    if (pb_fd >= 0)
        close(pb_fd);
    if (rodata)
        free(rodata);
    tb_fini_trace();
    return ret;
}

int tb_fini_ebpf(int type)
{
    if (type != RING_EBPF)
        return -1;

    /* closing related fd and releasing memory */
    if (g_tb_ebpf.pbfd >= 0)
        close(g_tb_ebpf.pbfd);
    if (g_tb_ebpf.rodata)
        free(g_tb_ebpf.rodata);

    tb_fini_trace();
    memset(&g_tb_ebpf, 0, sizeof(g_tb_ebpf));
    return 0;
}

/*
 * tb_read_ebpf返回值描述：
 *
 * >0: 正常情况
 * =0: 无数据返回，一般是收到signal 或者 msg/len过小
 *
 * -EBADFD: ebpf的map无效等错误
 * -ENOENT: 没有找到对应日志的格式信息，比如ringbuf的数据损坏
 * -EPROTO: 日志长度 与 对应的格式描述 不符合，数据损坏的可能
 *    ... : 系统函数read()返回-1时的错误码，已处理成负数
 */
int tb_read_ebpf(char *msg, int len, int (*cb)(int *), int *ctx)
{
    struct tb_ebpf *tb = &g_tb_ebpf;
    int rc = 0;

    if (!tb->pb)
        return -EBADFD;

    do {

        /* process the remained messages in pool */
        while (tb->start + sizeof(uint64_t) + 2 * sizeof(struct sd_item_ent) < tb->msgsz) {
            char *dat = g_tb_ebpf.pool;
            int ret, rec = tb->msgsz - tb->start;

            ret = sd_unpack(&msg[rc], len - rc, &dat[tb->start],
                            &rec, 1, se_query_event);
            /* len - rc: isn't long enough for new event */
            if (rc && !ret) {
                printf("elkeid: failed to unpack: len: %d/%d, ret: %d\n", rc, len, ret);
                break;
            }

            /* got error in unpacking or msg is too small */
            DEBUG(printf("elkeid: original message at %d: record: %xh ret: %d\n", tb->start, rec, ret));
            DEBUG(sd_hexdump(&dat[tb->start], rec));

            tb->start += rec;
            if (ret <= 0) {
                printf("uelkeid: npacked record too small: %d msg: %u/%u rec: %u\n", ret, tb->start, tb->msgsz, rec);
                break;
            }
            DEBUG(printf("elkeid: decoded message at %d: %d\n", rc, ret));
            DEBUG(sd_hexdump(&msg[rc], ret));

            /*
             * vsnprintf returns the length of generated output,
             * could be longer than size of input buffer, but it
             * won't overflow
             */
            rc += ret;
            if (rc > len)
                rc = len;

#if defined(HAVE_EVENTS_MULTIPLE)
            /* try to fill up user buffer */
            if (rc >= len)
                goto out;
#else
            /* fill only 1 event to user buffer and return */
            if (rc > 0)
                goto out;
#endif
        }

        if (rc || cb(ctx))
            break;

        /* retrieve payloads from kernel to internal pool */
        tb->start = 0;
        tb->msgsz = 0;

        /* wait for new messages */
        while (tb->msgsz == 0) {
            perf_buffer__poll(g_tb_ebpf.pb, g_tb_ebpf.timeout);
            if (cb(ctx))
                break;
        }

        /* get new messages or timeout */
        if (tb->msgsz > 0) {
            DEBUG(printf("elkeid: message reveived: %d\n", tb->msgsz));
            DEBUG(sd_hexdump(&g_tb_ebpf.pool[0], tb->msgsz));
        } else {
            rc = -errno;
        }

    } while (rc < len && rc >= 0);

out:
    return rc;
}

/*
 * open & close maps pinned to bpffs
 */

static int open_map(const char *name)
{
    return bpf_obj_get(name);
}

static void close_map(int mapfd)
{
    if (mapfd >= 0)
        close(mapfd);
}

/*
 * allowlist related routines
 */

static int add_trusted_item(int mapfd, int sid, char *str, int len)
{
    struct exe_item ei = {0};

    ei.hash = hash_murmur_OAAT64(str, len + 1); /* including trailing \0 */
    ei.len = len + 1;
    ei.sid = sid;
    strncpy(ei.name, str, CMDLINE_LEN - 1);
    if (len >= CMDLINE_LEN - 1)
        ei.name[CMDLINE_LEN - 1] = 0;

    return bpf_map_update_elem(mapfd, &ei.hash, &ei, BPF_NOEXIST);
}

static int check_trusted_item(int mapfd, char *str, int len)
{
    struct exe_item ei = {0};

    ei.hash = hash_murmur_OAAT64(str, len + 1);
    ei.len = len + 1;

    return !bpf_map_lookup_elem(mapfd, &ei.hash, &ei);
}

static int del_trusted_item(int mapfd, char *str, int len)
{
    uint64_t hash = hash_murmur_OAAT64(str, len + 1);
    return bpf_map_delete_elem(mapfd, &hash);
}

static int enum_trusted_map(int mapfd, char *buf, int len)
{
    struct exe_item ei = {0};
    uint64_t item = 0, next = 0;
    int sz = 0;

    while (bpf_map_get_next_key(mapfd, &item, &next) == 0) {
        item = next;
        if (0 == bpf_map_lookup_elem(mapfd, &next, &ei)) {
            if (buf) {
                int l = strlen(ei.name) + 1;
                if (sz + l > len)
                    break;
                memcpy(&buf[sz], ei.name, l);
                sz += l;
            } else {
                printf("[ELKEID EBPF] %u %llx %s\n", ei.sid, ei.hash, ei.name);
            }
        }
    }

    return sz;
}

static void clear_trusted_map(int mapfd)
{
    uint64_t item = 0, next = 0;

    while (bpf_map_get_next_key(mapfd, &item, &next) == 0) {
        bpf_map_delete_elem(mapfd, &next);
        item = next;
    }
}

int ac_init_ebpf(int type, char *trace)
{
    int ret = 0;

    if (type != RING_EBPF)
        return -1;

    /* construct pathes of trusted maps */
    if (trace && strlen(trace) > 0) {
        ret = build_maps(trace, trusted_maps);
        if (ret) {
            fprintf(stderr, "elkeid: invalid path: %s.\n", trace);
            goto cleanup;
        }
    }

    g_tb_ebpf.cmd_fd = open_map(g_trusted_cmds);
    g_tb_ebpf.exe_fd = open_map(g_trusted_exes);

cleanup:
    return ret;
}

int ac_fini_ebpf(int type)
{
    if (type != RING_EBPF)
	return -1;

    if (g_tb_ebpf.cmd_fd)
        close_map(g_tb_ebpf.cmd_fd);
    if (g_tb_ebpf.exe_fd)
        close_map(g_tb_ebpf.exe_fd);

    g_tb_ebpf.cmd_fd = 0;
    g_tb_ebpf.exe_fd = 0;
    return 0;
}

int ac_setup_ebpf(int ac, char *item, int len)
{
    int rc = -1;

    if (ac == AL_EBPF_ARGV)
        rc = add_trusted_item(g_tb_ebpf.cmd_fd, 0, item, len);
    else if (ac == AL_EBPF_EXE)
        rc = add_trusted_item(g_tb_ebpf.exe_fd, 0, item, len);

    return rc;
}

int ac_clear_ebpf(int ac)
{
    if (ac == AL_EBPF_ARGV)
        clear_trusted_map(g_tb_ebpf.cmd_fd);
    else if (ac == AL_EBPF_EXE)
        clear_trusted_map(g_tb_ebpf.exe_fd);

    return 0;
}

int ac_erase_ebpf(int ac, char *ptr, int len)
{
    if (!ptr)
        return ac_clear_ebpf(ac);

    if (ac == AL_EBPF_ARGV)
        del_trusted_item(g_tb_ebpf.cmd_fd, ptr, len);
    else if (ac == AL_EBPF_EXE)
        del_trusted_item(g_tb_ebpf.exe_fd, ptr, len);

    return 0;
}

int ac_check_ebpf(int ac, char *ptr, int len)
{
    int rc = 0;

    if (!ptr)
        return rc;

    if (ac == AL_EBPF_ARGV)
        rc = check_trusted_item(g_tb_ebpf.cmd_fd, ptr, len);
    else if (ac == AL_EBPF_EXE)
        rc = check_trusted_item(g_tb_ebpf.exe_fd, ptr, len);

    return rc;
}

int ac_query_ebpf(int ac, char *buf, int len)
{
    int rc = 0;

    if (ac == AL_EBPF_ARGV)
        rc = enum_trusted_map(g_tb_ebpf.cmd_fd, buf, len);
    else if (ac == AL_EBPF_EXE)
        rc = enum_trusted_map(g_tb_ebpf.exe_fd, buf, len);

    return rc;
}

static int tb_is_passed_ebpf(struct timeval *tv, long cycle)
{
    struct timeval now;

    gettimeofday(&now, NULL);
    return ((int64_t)now.tv_sec * 1000000UL + now.tv_usec >=
            (int64_t)tv->tv_sec * 1000000UL + tv->tv_usec + cycle);
}

static int tb_stat_ebpf(struct ring_stat *stat)
{
    return 0;
}

static void tb_show_ebpf(struct ring_stat *s, struct ring_stat *l, struct ring_stat *n)
{
}

static int tb_register_binfmt_ebpf(void)
{
    return 0;
}

static int tb_unregister_binfmt_ebpf(void)
{
    return 0;
}

static int tb_pre_unload_ebpf(void)
{
    return tb_unregister_binfmt_ebpf();
}


static int ac_process_ebpf(char *control, char *ptr, int len, int quiet)
{
    return -1;
}

struct tb_ring_operations g_ring_ebpf = {
    type: RING_EBPF,
    version: 0x3005,

    ring_init: tb_init_ebpf,
    ring_fini: tb_fini_ebpf,

    ring_read: tb_read_ebpf,
    ring_is_passed: tb_is_passed_ebpf,
    ring_stat: tb_stat_ebpf,
    ring_show: tb_show_ebpf,

    register_binfmt: tb_register_binfmt_ebpf,
    unregister_binfmt: tb_unregister_binfmt_ebpf,
    pre_unload: tb_pre_unload_ebpf,


    ac_init: ac_init_ebpf,
    ac_fini: ac_fini_ebpf,

    ac_setup: ac_setup_ebpf,
    ac_erase: ac_erase_ebpf,
    ac_clear_allowlist: ac_clear_ebpf,
    ac_clear_blocklist: NULL,
    ac_clear: ac_clear_ebpf,

    ac_check: ac_check_ebpf,
    ac_query: ac_query_ebpf,
    ac_process: ac_process_ebpf,
};
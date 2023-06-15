// Based on execsnoop(8) from BCC by Brendan Gregg and others.
//
#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>

#include <bpf/bpf.h>
#include <bpf/btf.h>
#include <linux/bpf.h>
#include <linux/btf.h>

#include "errno_helpers.h"
#include "trace_helpers.h"
#include "btf_helpers.h"

#include "hids/hids.h"
#define __SD_XFER_DE__
#include "hids/xfer.h"
#include "hids.btf.h"

#define PERF_BUFFER_PAGES       4
#define PERF_POLL_TIMEOUT_MS    100

const char *program_version = "HIDS agent driver 0.1";

static volatile sig_atomic_t g_exiting = 0;
static void sig_int(int signo)
{
    g_exiting = 1;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
    if (level == LIBBPF_DEBUG)
        return 0;
    return vfprintf(stderr, format, args);
}

char g_msg[SD_STR_MAX + 8];
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

#include <sys/sysinfo.h>

static int get_pid_max(void)
{
    int pid_max = 4096;
    FILE *f;

    f = fopen("/proc/sys/kernel/pid_max", "r");
    if (!f)
        goto errorout;
    if (fscanf(f, "%d\n", &pid_max) != 1)
        pid_max = -1;
    fclose(f);

errorout:
    if (pid_max > 0)
        pid_max = pid_max < get_nprocs() * 1024 ? pid_max : get_nprocs() * 1024;
    else
        pid_max = get_nprocs() * 1024;

    return pid_max;
}

#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <limits.h>

/* both subdirs and parent should should have '/' at tail */
static size_t mkdirs(char *path,  const char *parent, const char *subdirs, mode_t mode)
{
    char *p;
    size_t len = 0, skip;

    strncpy(path, parent, PATH_MAX);
    strncat(path, subdirs, PATH_MAX);
    len = strlen(path);
    if (len == 0)
        return 0;
    if (len >= PATH_MAX - 2)
        return 0;
    while (len > 0 && path[len - 1] == '/')
        path[--len] = '\0';
    if (len == 0)
        return 0;
    skip = strlen(parent);
    for (p = path + skip; p <= path + len; p++) {
        if (*p == '/') {
            *p = '\0';
            if (access(path, F_OK))
                mkdir(path, mode);
            *p = '/';
        } else if (*p == 0) {
            if (access(path, F_OK))
                mkdir(path, mode);
            break;
        }
    }
    return len;
}

char g_pb_event[PATH_MAX];
char g_map_rodata[PATH_MAX];
char g_trusted_cmds[PATH_MAX];
char g_trusted_exes[PATH_MAX];

struct _ebpf_map {
    char *target;
    const char *bpffs;
    const char *path;
    const char *name;
    int mapfd;
} g_maps[] = {
    {g_map_rodata, "/sys/fs/bpf/", "bpfd/trace/hids/map/", RODATA_SECTION_MAP, },
    {g_pb_event, "/sys/fs/bpf/", "bpfd/trace/hids/map/", PERF_BUFFER_EVENT, },
    {g_trusted_cmds, "/sys/fs/bpf/", "bpfd/trace/hids/map/", TRUSTED_CMDS, },
    {g_trusted_exes, "/sys/fs/bpf/", "bpfd/trace/hids/map/", TRUSTED_EXES, },
};

static size_t prepare_map(char *path, const char *base, const char *subs, const char *map)
{
    size_t lp, lm;

    lm = strlen(map);
    lp = mkdirs(path, base, subs, S_IRWXU);
    if (!lp || !lm || lp + lm + 1 >= PATH_MAX)
        return 0;
    strncat(path, "/", PATH_MAX);
    strncat(path, map, PATH_MAX);
    unlink(path);
    return lp + lm;
}

static void load_maps(struct hids_btf *obj, struct bpf_map *rdmap, int pin)
{
    struct bpf_map *maps[] = {  rdmap, obj->maps.events,
                                obj->maps.trusted_cmds,
                                obj->maps.trusted_exes, 0};
    int i, err;

    for (i = 0; maps[i]; i++) {
        if (i >= sizeof(g_maps) / sizeof(struct _ebpf_map))
            break;
        g_maps[i].mapfd = bpf_map__fd(maps[i]);
        if (g_maps[i].mapfd <= 0)
            continue;
        if (!pin)
            continue;
        prepare_map(g_maps[i].target, g_maps[i].bpffs, g_maps[i].path, g_maps[i].name);
        err = bpf_obj_pin(g_maps[i].mapfd, g_maps[i].target);
        if (!err)
            printf("%s pinned to %s\n", g_maps[i].name, g_maps[i].target);
        else
            printf("failed to pin %s to %s with err %d\n", g_maps[i].name, g_maps[i].target, err);
    }
}

static int add_trusted_item(int mapfd, int sid, char *str, int len)
{
    struct exe_item ei = {0};

    ei.hash = hash_murmur_OAAT64(str, len);
    ei.sid = sid;
    ei.len = len;
    strncpy(ei.name, str, CMDLINE_LEN - 1);
    if (len >= CMDLINE_LEN - 1)
        ei.name[CMDLINE_LEN - 1] = 0;

    return bpf_map_update_elem(mapfd, &ei.hash, &ei, BPF_NOEXIST);
}

static int del_trusted_item(int mapfd, char *str, int len)
{
    struct exe_item ei = {0};

    ei.hash = hash_murmur_OAAT64(str, len);
    ei.len = len;

    if (bpf_map_lookup_elem(mapfd, &ei.hash, &ei))
        return 0;

    return bpf_map_delete_elem(mapfd, &ei.hash);
}

static void enum_trusted_map(int mapfd)
{
    struct exe_item ei = {0};
    uint64_t item = 0, next = 0;

    while (bpf_map_get_next_key(mapfd, &item, &next) == 0) {
        item = next;
        if (0 == bpf_map_lookup_elem(mapfd, &next, &ei)) {
            printf("%u %llx %s\n", ei.sid, ei.hash, ei.name);
        }
    }
}

static void clear_trusted_map(int mapfd)
{
    uint64_t item = 0, next = 0;

    while (bpf_map_get_next_key(mapfd, &item, &next) == 0) {
        bpf_map_delete_elem(mapfd, &next);
        item = next;
    }
}

static void process_trusted_exes(int mapfd)
{
    char *exes[] = {"/usr/bin/pwd",
                    "/usr/bin/top",
                    "/usr/bin/ls",
                    "/usr/bin/git",
                    "/usr/lib/git-core/git",
                    "/usr/bin/sleep",
                    "/usr/bin/uname",
                    "/usr/bin/pidstat",
                    NULL
                   };
    int i;

    for (i = 0; exes[i]; i++)
        add_trusted_item(mapfd, 0xEE000001 + i, exes[i],
                         strlen(exes[i]) + 1);

    printf("enumerating ...\n");
    enum_trusted_map(mapfd);

    del_trusted_item(mapfd, exes[1], strlen(exes[1]));

    printf("enumerating (after removing %s) ...\n", exes[1]);
    enum_trusted_map(mapfd);
}

static void process_trusted_cmds(int mapfd)
{
    char *cmds[] = {"test/rst -i 10",
                    "test/rst -i 20",
                    "test/rst -i 30",
                    NULL
                   };
    int i;

    for (i = 0; cmds[i]; i++)
        add_trusted_item(mapfd, 0xA0000001 + i, cmds[i],
                         strlen(cmds[i]) + 1);

    printf("enumerating ...\n");
    enum_trusted_map(mapfd);

    del_trusted_item(mapfd, cmds[1], strlen(cmds[1]));

    printf("enumerating (after removing %s) ...\n", cmds[1]);
    enum_trusted_map(mapfd);
}

int main(int argc, char **argv)
{
    LIBBPF_OPTS(bpf_object_open_opts, open_opts);

    struct perf_buffer *pb = NULL;
    struct hids_btf *obj = NULL;

    struct bpf_map *datmap;
    char *sd = NULL;

    struct btf *btf;
    const struct btf_type *datsec;
    struct btf_var_secinfo *infs;

    __u32 sd_event_point = -1, sd_event_proto = -1;

    int err, pid_max = get_pid_max();
    int pin = 0, datid, i;

    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
    libbpf_set_print(libbpf_print_fn);

    if (argc > 1 && 0 == strncasecmp(argv[1], "pin", 3))
        pin = 1;

    if (signal(SIGINT, sig_int) == SIG_ERR) {
        fprintf(stderr, "can't set signal handler: %s\n", strerror(errno));
        err = 1;
        goto cleanup;
    }

    err = ensure_core_btf(&open_opts);
    if (err) {
        fprintf(stderr, "failed to fetch necessary BTF for CO-RE: %s\n", strerror(-err));
        return 1;
    }

    obj = hids_btf__open_opts(&open_opts);
    if (!obj) {
        fprintf(stderr, "failed to open BPF object\n");
        return 1;
    }

    /* initialize global data (filtering options) */
    // obj->rodata->max_args = env.max_args;
    bpf_map__set_max_entries(obj->maps.g_tid_cache, pid_max);

    err = hids_btf__load(obj);
    if (err) {
        fprintf(stderr, "failed to load BPF object: %d\n", err);
        goto cleanup;
    }

    err = hids_btf__attach(obj);
    if (err) {
        fprintf(stderr, "failed to attach BPF programs\n");
        goto cleanup;
    }

    // Get BTF, we need it do find out the memory layout of .data
    btf = bpf_object__btf(obj->obj);
    err = libbpf_get_error(btf);
    if (err) {
        fprintf(stderr, "failed to quert btf\n");
        goto cleanup;
    }

    // Get the type ID of the datasection of .data
    datid = btf__find_by_name(btf, ".rodata");
    if (datid <= 0) {
        fprintf(stderr, "failed to locate .rodata section\n");
        err = -ENOENT;
        goto start;
    }
    // printf("rodata id: %d fd: %d\n", datid, bpf_map_get_fd_by_id(datid));

    // Get the actual BTF type from the ID
    datsec = btf__type_by_id(btf, datid);
    err = libbpf_get_error(datsec);
    if (err) {
        fprintf(stderr, "failed to get id of data section\n");
        goto start;
    }
    // printf("rodata: off:%8.8xh info: %u size: %u type: %u\n",
    //  datsec->name_off, datsec->info, datsec->size, datsec->type);

    // Get all secinfos, each of which will be a global variable
    infs = btf_var_secinfos(datsec);
    // Loop over all sections
    for(i = 0; i < btf_vlen(datsec); i++) {
        // Get the BTF type of the current var
        const struct btf_type *t = btf__type_by_id(btf, infs[i].type);
        // Get the name of the global variable
        const char *name = btf__name_by_offset(btf, t->name_off);
        if (!strcmp(name, "sd_event_proto_start")) {
            sd_event_proto = infs[i].offset;
        } else if (!strcmp(name, "sd_event_point_start")) {
            sd_event_point = infs[i].offset;
        }
    }

    datmap = bpf_object__find_map_by_name(obj->obj, ".rodata");
    err = libbpf_get_error(datmap);
    if (err) {
        fprintf(stderr, "failed to find map for .rodata\n");
        goto start;
    }

    /* loading pre-defined maps */
    load_maps(obj, datmap, pin);

    process_trusted_cmds(g_maps[2].mapfd);
    process_trusted_exes(g_maps[3].mapfd);

    /* loading */
    sd = malloc(datsec->size);
    if (sd) {
        uint32_t rokey = 0;
        memset(sd, 0, datsec->size);
        /* bpf_map_get_fd_by_id() */
        err = bpf_map_lookup_elem(g_maps[0].mapfd, &rokey, sd);
        if (sd_event_point >= bpf_map__value_size(datmap))
            goto start;
        err = sd_init_format(sd, datsec->size, sd_event_proto, sd_event_point);
        if (err)
            goto start;
    }

start:

    if (pin) {
        while (!g_exiting) {
            sleep(10);
        }
        goto cleanup;
    }

    /* setup event callbacks */
    pb = perf_buffer__new(g_maps[1].mapfd, PERF_BUFFER_PAGES,
                          event_handling, event_missing,
                          NULL, NULL);
    if (!pb) {
        err = -errno;
        fprintf(stderr, "failed to open perf buffer: %d\n", err);
        goto cleanup;
    }

    /* main: poll */
    while (!g_exiting) {
        err = perf_buffer__poll(pb, PERF_POLL_TIMEOUT_MS);
        if (err < 0 && err != -EINTR) {
            fprintf(stderr, "error polling perf buffer: %s\n", strerror(-err));
            goto cleanup;
        }
    }

cleanup:
    if (pb)
        perf_buffer__free(pb);
    if (obj)
        hids_btf__destroy(obj);
    cleanup_core_btf(&open_opts);

    if (sd)
        free(sd);
    return err;
}

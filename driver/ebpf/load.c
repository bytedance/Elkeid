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

#include <src/bpf.h>
#include <src/btf.h>
#include <linux/bpf.h>
#include <linux/btf.h>

#include "errno_helpers.h"
#include "trace_helpers.h"
#include "btf_helpers.h"

#define __SD_XFER_DE__
#include "../xfer/xfer.h"

#include "hids/hids.h"
#include "hids/hids_bpf.h"

#include <sys/sysinfo.h>
static int get_pid_max(void)
{
    FILE *f;
    int pid_max = 4096;

    f = fopen("/proc/sys/kernel/pid_max", "r");
    if (!f)
        goto err_out;
    if (fscanf(f, "%d\n", &pid_max) != 1)
        pid_max = -1;
    fclose(f);

err_out:

    if (pid_max > 0)
        pid_max = pid_max < get_nprocs() * 1024 ? pid_max : get_nprocs() * 1024;
    else
        pid_max = get_nprocs() * 1024;

    while (pid_max > 32UL * 1048576UL / sizeof(struct proc_tid))
        pid_max = pid_max / 2;
    return pid_max;
}

#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <limits.h>

/* both subdirs and parent should should have '/' at tail */
static size_t
mkdir_path(char *path,  const char *parent, const char *subdirs, mode_t mode)
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

static void
unlink_all(const char *parent, const char *subdirs, const char *maps[])
{
    char path[PATH_MAX]; 
    int len = 0, skip, i;

    strncpy(path, parent, PATH_MAX - 1);
    strncat(path, subdirs, PATH_MAX - 1);
    len = strlen(path);
    if (len == 0)
        return;
    if (len >= PATH_MAX - 2)
        return;
    while (len > 0 && path[len - 1] == '/')
        path[--len] = '\0';
    if (len <= 0)
        return;
    path[len] = '/';

    /* unlink all maps */
    for (i = 0; maps[i]; i++) {
        if (len + strlen(maps[i]) >= PATH_MAX)
            continue;
        strcpy(&path[len + 1], maps[i]);
        printf("elkeid: unlinking: %s\n", path);
        unlink((const char *)&path[0]);
    }

    /* unlink all subdirs */
    skip = strlen(parent);
    path[len] = 0;

    do {
        printf("elkeid: unlinking: %s\n", path);
        rmdir((const char *)&path[0]);
        while (--len > skip) {
            if (path[len] == '/') {
                path[len] = 0;
                break;
            }
        }
    } while (len > skip);
}

static char *loader_version = EBPF_PROG_VERSION;

static int print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
    if (level == LIBBPF_DEBUG)
        return 0;
    return vfprintf(stderr, format, args);
}

static const char *g_map_names[] = {
    RODATA_SECTION_MAP, PERF_BUFFER_EVENT,
    TRUSTED_CMDS, TRUSTED_EXES, NULL
};

static char g_pb_event[PATH_MAX];
static char g_map_rodata[PATH_MAX];
static char g_trusted_cmds[PATH_MAX];
static char g_trusted_exes[PATH_MAX];

static struct elkeid_bpf_map {
    const char *bpffs;
    const char *path;
    const char *name;
    char *target;
    int mapfd;
} g_maps[] = {
    {BPF_SYS, ELK_MAP, RODATA_SECTION_MAP, g_map_rodata,},
    {BPF_SYS, ELK_MAP, PERF_BUFFER_EVENT, g_pb_event,},
    {BPF_SYS, ELK_MAP, TRUSTED_CMDS, g_trusted_cmds,},
    {BPF_SYS, ELK_MAP, TRUSTED_EXES, g_trusted_exes,},
};

static size_t prepare_map(char *path, const char *base, const char *subs, const char *map)
{
    size_t lp, lm;

    lm = strlen(map);
    lp = mkdir_path(path, base, subs, S_IRWXU);
    if (!lp || !lm || lp + lm + 1 >= PATH_MAX)
        return 0;
    strncat(path, "/", PATH_MAX - 1);
    strncat(path, map, PATH_MAX - 1);
    unlink(path);
    return lp + lm;
}

static void pin_maps(struct hids_bpf *obj)
{
    struct bpf_map *maps[] = { obj->maps.rodata,
                               obj->maps.events,
                               obj->maps.trusted_cmds,
                               obj->maps.trusted_exes, 0};
    int i, err;

    for (i = 0; maps[i]; i++) {
        g_maps[i].mapfd = bpf_map__fd(maps[i]);
        if (g_maps[i].mapfd <= 0)
            continue;

        prepare_map(g_maps[i].target, g_maps[i].bpffs, g_maps[i].path, g_maps[i].name);
        err = bpf_obj_pin(g_maps[i].mapfd, g_maps[i].target);
        if (!err)
            printf("elkeid: %s pinned to %s\n", g_maps[i].name, g_maps[i].target);
        else
            printf("elkeid: failed to pin %s to %s with err %d\n", g_maps[i].name, g_maps[i].target, err);
    }
}

static int g_btf_inited;
static char g_bpf_path[PATH_MAX];
static struct hids_bpf *g_bpf_prog;
static struct bpf_object_open_opts g_bpf_opts = {.sz = sizeof(g_bpf_opts),};

/*
 * loader of bpf with BTF supported
 */

void tb_unload_ebpf()
{
    if (g_bpf_prog) {
        hids_bpf__destroy(g_bpf_prog);
        g_bpf_prog = NULL;
    }

    if (g_btf_inited) {
        cleanup_core_btf(&g_bpf_opts);
        g_btf_inited = 0;
    }

    memset(&g_bpf_opts, 0, sizeof(g_bpf_opts));
    unlink_all(BPF_SYS, ELK_MAP, g_map_names);
}

int tb_query_ebpf(char *version, size_t *sz)
{
    if (!version || !g_bpf_prog)
        return -EINVAL;
    memcpy(version, g_bpf_prog->rodata.ebpf_version, 12);
    if (sz)
        *sz = g_bpf_prog->skeleton->data_sz;
    return 0;
}

int tb_load_ebpf_with_btf(const char *path, const char *btf)
{
    struct hids_bpf *obj = NULL;
    int err, lp = 0;
    char ver[16] = {0};

    printf("elkeid: ebpf loader %s started.\n", loader_version);

    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
    libbpf_set_print(print_fn);

    /* construct file path of the bpf binary */
    if (!path)
        return -EINVAL;
    lp = strnlen(path, PATH_MAX);
    if (!lp || lp >= PATH_MAX)
        return -EINVAL;
    strncpy(g_bpf_path, path, PATH_MAX - 1);

    if (btf)
        g_bpf_opts.btf_custom_path = btf;
    err = ensure_core_btf(&g_bpf_opts);
    g_btf_inited = !err;
    if (g_btf_inited) {
        g_bpf_opts.object_name = "elkeid_btf";
    } else {
        if (strstr(path, "elkeid.btf-")) {
            fprintf(stderr, "elkeid: Current kernel doesn't support BTF. Try bpf instead.\n");
            return -EINVAL;
        }
        g_bpf_opts.object_name = "elkeid_bpf";
    }

    /* do cleaning if ebpf program was already loaded */
    if (g_bpf_prog) {
        hids_bpf__destroy(g_bpf_prog);
        g_bpf_prog = NULL;
    }

    /* prepare for ebpf program loading */
    obj = hids_bpf__open_opts(&g_bpf_opts, g_bpf_path);
    if (!obj) {
        fprintf(stderr, "elkeid: failed to open BPF objec: %s\n", g_bpf_path);
        err = -1;
        goto err_out;
    }

    /* initialize global data (filtering options) */
    /* obj->rodata->max_args = env.max_args; */
    bpf_map__set_max_entries(obj->maps.tid_cache, get_pid_max());

    err = hids_bpf__load(obj);
    if (err) {
        fprintf(stderr, "elkeid: failed to load BPF object: %d\n", err);
        goto err_out;
    }

    /* try to attach all hookpoints and start */
    err = hids_bpf__attach(obj);
    if (err) {
        fprintf(stderr, "elkeid: failed to attach BPF programs\n");
        goto err_out;
    }

    /* load and pin the pre-defined maps */
    pin_maps(obj);

    /* save hids_bpf pointer for cleanup */
    g_bpf_prog = obj;

    /* release ebpf data */
    hids_bpf__free_data(obj);

    tb_query_ebpf(ver, NULL);
    printf("elkeid: ebpf program %s to be loaded.\n", ver);

    return err;

err_out:

    if (obj)
        hids_bpf__destroy(obj);
    if (g_btf_inited)
        cleanup_core_btf(&g_bpf_opts);
    g_btf_inited = 0;

    return err;
}

int tb_load_ebpf(const char *path)
{
    return tb_load_ebpf_with_btf(path, NULL);
}

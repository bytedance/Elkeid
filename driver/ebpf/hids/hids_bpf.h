/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */

#ifndef __HIDS_BPF_SKEL_H__
#define __HIDS_BPF_SKEL_H__

#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <src/libbpf.h>

struct hids_bpf {
    const char *path; /* ebpf file, manally added */;
    const char *name;

    struct bpf_object_skeleton *skeleton;
    struct bpf_object *obj;
    struct {
        struct bpf_map *tid_cache;
        struct bpf_map *trusted_exes;
        struct bpf_map *trusted_cmds;
        struct bpf_map *events;
        struct bpf_map *rodata;
    } maps;
    struct {
        struct bpf_program *tp__proc_exec;
        struct bpf_program *tp__proc_fork;
        struct bpf_program *tp__proc_exit;
        struct bpf_program *tp__sys_exit;
        struct bpf_program *kp__inode_create;
        struct bpf_program *kp__inode_rename;
        struct bpf_program *kp__inode_link;
        struct bpf_program *kp__umh_exec;
        struct bpf_program *kp__init_module;
        struct bpf_program *kp__commit_creds;
        struct bpf_program *kp__filp_close;
        struct bpf_program *kp__task_prctl;
    } progs;
    struct {
        struct bpf_link *tp__proc_exec;
        struct bpf_link *tp__proc_fork;
        struct bpf_link *tp__proc_exit;

        struct bpf_link *tp__sys_exit;
        struct bpf_link *tp__sys_enter;
        struct bpf_link *kp__inode_create;
        struct bpf_link *kp__inode_rename;
        struct bpf_link *kp__inode_link;
        struct bpf_link *kp__umh_exec;
        struct bpf_link *kp__init_module;
        struct bpf_link *kp__commit_creds;
        struct bpf_link *kp__filp_close;
        struct bpf_link *kp__task_prctl;
    } links;
    struct hids_bpf__rodata {
        char *sd_event_proto_start;
        char *sd_event_point_start;
        char ebpf_version[16];
    } rodata;
};

static char se_event_proto_start[32] = { SD_EVENT_PROTO_MAGIC };
static char se_event_point_start[32] = { SD_EVENT_POINT_MAGIC };

static inline int hids_bpf__locate_magic(char *sd, int sz, char *ss, int ls)
{
    int i;

    for (i = 0; i < sz - ls; i++) {
        if (!memcmp(&sd[i], ss, ls))
            return i;
    }
    return -1;
}

static int hids_bpf__locate_proto(char *s, int len)
{
    return hids_bpf__locate_magic(s, len, se_event_proto_start, 32);
}

static int hids_bpf__locate_event(char *s, int len)
{
    return hids_bpf__locate_magic(s, len, se_event_point_start, 20);
}

static void *
hids_bpf__load_ebpf(struct hids_bpf *obj, size_t *sz)
{
    FILE *filp = NULL;
    char *data = NULL;
    int size, off;

    /* open ebpf binary */
    filp = fopen(obj->path, "rb");
    if (!filp) {
        printf("elkeid: failed to open ebpf progam %s\n", obj->path);
        goto err_out;
    }
    fseek(filp, 0, SEEK_END);
    size = ftell(filp);
    if (size <= 0)
        goto err_out;

    if (fseek(filp, 0, SEEK_SET))
        goto err_out;
        
    data = malloc(size);
    if (!data)
        goto err_out;

    if (fread(data, 1, size, filp) < size) {
        free(data);
        data = NULL;
    } else if (sz) {
        *sz = size;
        off = hids_bpf__locate_proto(data, size);
        if (off <= 0) {
            free(data);
            data = NULL;
            goto err_out;
        }
        obj->rodata.sd_event_proto_start = &data[off];
        off = hids_bpf__locate_event(data, size);
        if (off <= 0) {
            free(data);
            data = NULL;
            goto err_out;
        }
        obj->rodata.sd_event_point_start = &data[off];
        memcpy(obj->rodata.ebpf_version, &data[off + 20], 12);
    }

err_out:
    if (filp)
        fclose(filp);
    return data;
}

static void
hids_bpf__free_data(struct hids_bpf *obj)
{
    if (!obj->skeleton || !obj->skeleton->data)
        return;

    free((void *)obj->skeleton->data);
    obj->skeleton->data = NULL;
}

static void
hids_bpf__destroy(struct hids_bpf *obj)
{
    if (!obj)
        return;
    if (obj->skeleton) {
        if (obj->skeleton->data) {
            free((void *)obj->skeleton->data);
            obj->skeleton->data = NULL;
        }
        bpf_object__destroy_skeleton(obj->skeleton);
    }
    free(obj);
}

static inline int
hids_bpf__create_skeleton(struct hids_bpf *obj);

static inline struct hids_bpf *
hids_bpf__open_opts(const struct bpf_object_open_opts *opts, const char *path)
{
    struct hids_bpf *obj;
    int err;

    obj = (struct hids_bpf *)calloc(1, sizeof(*obj));
    if (!obj) {
        errno = ENOMEM;
        return NULL;
    }
    memset(obj, 0, sizeof(*obj));
    obj->path = path;
    obj->name = opts->object_name;

    err = hids_bpf__create_skeleton(obj);
    if (err) {
        printf("elkeid: hids_bpf__create_skeleton failed.\n");
        goto err_out;
    }

    err = bpf_object__open_skeleton(obj->skeleton, opts);
    if (err) {
        printf("elkeid: bpf_object__open_skeleton failed with %d\n", err);
        goto err_out;
    }

    return obj;
err_out:
    hids_bpf__destroy(obj);
    errno = -err;
    return NULL;
}

static inline int
hids_bpf__load(struct hids_bpf *obj)
{
    return bpf_object__load_skeleton(obj->skeleton);
}

static inline struct hids_bpf *
hids_bpf__open_and_load(char *name)
{
    struct hids_bpf *obj;
    int err;

    obj = hids_bpf__open_opts(NULL, name);
    if (!obj)
        return NULL;
    err = hids_bpf__load(obj);
    if (err) {
        hids_bpf__destroy(obj);
        errno = -err;
        return NULL;
    }
    return obj;
}

static inline int
hids_bpf__attach(struct hids_bpf *obj)
{
    return bpf_object__attach_skeleton(obj->skeleton);
}

static inline void
hids_bpf__detach(struct hids_bpf *obj)
{
    bpf_object__detach_skeleton(obj->skeleton);
}

#define MAX_MAPS  (8)
#define MAX_PROGS (16)

static inline int
hids_bpf__create_skeleton(struct hids_bpf *obj)
{
    struct bpf_object_skeleton *s;
    int err, n;

    s = (struct bpf_object_skeleton *)calloc(1, sizeof(*s));
    if (!s)	{
        err = -ENOMEM;
        goto err_out;
    }

    s->sz = sizeof(*s);
    s->obj = &obj->obj;
    s->name = obj->name;

    /* maps */
    s->map_skel_sz = sizeof(*s->maps);
    s->maps = (struct bpf_map_skeleton *)calloc(MAX_MAPS, s->map_skel_sz);
    if (!s->maps) {
        err = -ENOMEM;
        goto err_out;
    }
    n = -1;

    n++;
    s->maps[n].name = "tid_cache";
    s->maps[n].map = &obj->maps.tid_cache;

    n++;
    s->maps[n].name = "trusted_exes";
    s->maps[n].map = &obj->maps.trusted_exes;

    n++;
    s->maps[n].name = "trusted_cmds";
    s->maps[n].map = &obj->maps.trusted_cmds;

    n++;
    s->maps[n].name = "events";
    s->maps[n].map = &obj->maps.events;

    n++;
    s->maps[n].name = "elkeid_b.rodata";
    s->maps[n].map = &obj->maps.rodata;
    s->maps[n].mmaped = (void **)&obj->rodata;

    if (n >= MAX_MAPS) {
        printf("overflow in map array: %d vs %d\n", n, MAX_MAPS);
        exit(-1);
    }
    s->map_cnt = n + 1;

    /* programs */
    s->prog_skel_sz = sizeof(*s->progs);
    s->progs = (struct bpf_prog_skeleton *)calloc(MAX_PROGS, s->prog_skel_sz);
    if (!s->progs) {
        err = -ENOMEM;
        goto err_out;
    }
    n = -1;

    n++;
    s->progs[n].name = "tp__proc_exec";
    s->progs[n].prog = &obj->progs.tp__proc_exec;
    s->progs[n].link = &obj->links.tp__proc_exec;

    n++;
    s->progs[n].name = "tp__proc_fork";
    s->progs[n].prog = &obj->progs.tp__proc_fork;
    s->progs[n].link = &obj->links.tp__proc_fork;

    n++;
    s->progs[n].name = "tp__proc_exit";
    s->progs[n].prog = &obj->progs.tp__proc_exit;
    s->progs[n].link = &obj->links.tp__proc_exit;

    n++;
    s->progs[n].name = "tp__sys_exit";
    s->progs[n].prog = &obj->progs.tp__sys_exit;
    s->progs[n].link = &obj->links.tp__sys_exit;

    n++;
    s->progs[n].name = "kp__inode_create";
    s->progs[n].prog = &obj->progs.kp__inode_create;
    s->progs[n].link = &obj->links.kp__inode_create;

    n++;
    s->progs[n].name = "kp__inode_rename";
    s->progs[n].prog = &obj->progs.kp__inode_rename;
    s->progs[n].link = &obj->links.kp__inode_rename;

    n++;
    s->progs[n].name = "kp__inode_link";
    s->progs[n].prog = &obj->progs.kp__inode_link;
    s->progs[n].link = &obj->links.kp__inode_link;

    n++;
    s->progs[n].name = "kp__umh_exec";
    s->progs[n].prog = &obj->progs.kp__umh_exec;
    s->progs[n].link = &obj->links.kp__umh_exec;

    n++;
    s->progs[n].name = "kp__init_module";
    s->progs[n].prog = &obj->progs.kp__init_module;
    s->progs[n].link = &obj->links.kp__init_module;

    n++;
    s->progs[n].name = "kp__commit_creds";
    s->progs[n].prog = &obj->progs.kp__commit_creds;
    s->progs[n].link = &obj->links.kp__commit_creds;

    n++;
    s->progs[n].name = "kp__filp_close";
    s->progs[n].prog = &obj->progs.kp__filp_close;
    s->progs[n].link = &obj->links.kp__filp_close;

    n++;
    s->progs[n].name = "kp__task_prctl";
    s->progs[n].prog = &obj->progs.kp__task_prctl;
    s->progs[n].link = &obj->links.kp__task_prctl;

    if (n >= MAX_PROGS) {
        printf("overflow in prog array: %d vs %d\n", n, MAX_PROGS);
        exit(-1);
    }
    s->prog_cnt = n + 1;

    s->data = hids_bpf__load_ebpf(obj, &s->data_sz);
        if (!s->data)
                goto err_out;

    obj->skeleton = s;
    return 0;

err_out:
    bpf_object__destroy_skeleton(s);
    return err;
}

__attribute__((unused)) static void
hids_bpf__assert(struct hids_bpf *s __attribute__((unused)))
{
}

#endif /* __HIDS_BPF_SKEL_H__ */

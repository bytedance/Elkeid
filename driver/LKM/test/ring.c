// SPDX-License-Identifier: GPL-2.0

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <fcntl.h>
#include <errno.h>
#include <ctype.h>

#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>

#include "../include/trace.h"

/*
 * xfer:
 *
 * ring-buffer deserializing
 */

#define __SD_XFER_DE__
#include "../include/xfer.h"

struct sd_event_format *g_sd_formats;
struct sd_item_ent *   *g_sd_events;

static int sd_init_events(struct sd_event_format *fmt)
{
    int i, n;

    g_sd_events = (void *)fmt + fmt->size;
    for (n = sizeof(*fmt), i = 0; i < fmt->nids; i++) {
        struct sd_item_ent *e = (void *)fmt + n;
        if (e[0].eid != i + 1)
            return -1;
        if (e[0].size <= sizeof(*e) * 2)
            return -2;
        g_sd_events[i] = e;
        n += e[0].size;
        if (n > fmt->size)
            break;
    }

    return (i - fmt->nids);
}

static int sd_init_format(int fd)
{
    struct sd_event_format fmt = {0};
    int rc;

    fmt.size = sizeof(fmt);
    rc = ioctl(fd, TRACE_IOCTL_FORMAT, &fmt);
    if (rc != sizeof(fmt))
        return -1;
    if (fmt.size > 256 * 1024 || fmt.size < rc ||
        fmt.nids == 0 || fmt.nids > 1024)
        return -2;

    g_sd_formats = malloc(fmt.size + fmt.nids * sizeof(void *));
    if (!g_sd_formats)
        return -3;

    g_sd_formats->size = fmt.size;
    rc = ioctl(fd, TRACE_IOCTL_FORMAT, g_sd_formats);
    if (rc != fmt.size || fmt.size != g_sd_formats->size ||
        fmt.nids != g_sd_formats->nids) {
        free(g_sd_formats);
        g_sd_formats = NULL;
        return -4;
    }

    if (sd_init_events(g_sd_formats)) {
        free(g_sd_formats);
        g_sd_formats = NULL;
        g_sd_events = NULL;
        return -5;
    }

    return 0;
}

/* return length of type meta */
struct sd_item_ent *sd_query_event(void *data, int *rec)
{
    struct sd_item_ent *head = data + sizeof(uint64_t);
    uint32_t eid = head[0].eid;

    if (eid > 0 && eid <= g_sd_formats->nids) {
        struct sd_item_ent *item = g_sd_events[eid - 1];
        /* now we do some verifications */
        if (eid != item[0].eid || head[0].size < item[1].meta ||
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
 * trace-buffer support routines for user mode apps
 */
#define TB_BUFFER_SIZE  (64 * 1024UL)
struct tb_trace {
    char *pool;
    int bufsz;
    int start;
    int msgsz;
    int fd;
    int instances; /* allowlist + ringbuf consuming */
} g_tb_trace;

static int tb_init_format(int fd)
{
    g_tb_trace.bufsz = TB_BUFFER_SIZE;
    g_tb_trace.pool = malloc(g_tb_trace.bufsz);
    if (!g_tb_trace.pool)
        return -5;

    /* query events format */
    if (sd_init_format(fd)) {
        printf("Error: failed to init format\n");
        free(g_tb_trace.pool);
        g_tb_trace.pool = NULL;
        return -6;
    }
    return 0;
}

int tb_init_ring(int type, char *trace)
{
    char fds[64], rev[16];
    FILE *fp;
    int fd = -1, rc = 0;

    /* consuming channel was already opened */
    if (g_tb_trace.fd) {

        /* check whether trace pool is allocated */
        if (g_tb_trace.pool)
            goto opened;

        /* try to initialize formats */
        rc = tb_init_format(g_tb_trace.fd - 1);
        if (rc)
            return rc;
        goto opened;
    }

    /* control path must be provided manually */
    if (!trace)
        return -1;
    if (RING_KMOD != type)
        return -2;

    fp = fopen(trace, "rb");
    if (!fp) {
        printf("Error: Elkeid kernel module isn't loaded.\n");
        return -3;
    }

    if (fgets(fds, 64, fp))
        sscanf(fds, "KMOD: %s PIPE: %d\n", rev, &fd);
    if (fd < 0) {
        printf("Error: failed to open hids endpoint\n");
        return -4;
    }

    rc = tb_init_format(fd);
    if (rc) {
        close(fd);
        return rc;
    }
    g_tb_trace.fd = fd + 1;

opened:

    g_tb_trace.instances++;
    return 0;
}

void tb_fini_ring(void)
{
    int fd = g_tb_trace.fd - 1;

    if (g_tb_trace.fd <= 0)
        return;

    if (g_sd_formats)
        free(g_sd_formats);

    if (g_tb_trace.pool)
        free(g_tb_trace.pool);
    g_tb_trace.pool = NULL;
    g_tb_trace.start = 0;
    g_tb_trace.msgsz = 0;

    if (--g_tb_trace.instances > 0)
        return;

    close(fd);
}

/*
 * tb_read_ring返回值描述：
 *
 * >0: 正常情况
 * =0: 无数据返回，一般是收到signal 或者 msg/len过小
 *
 * -EBADFD: b_init_ring不成功，或者 /proc/elkeid-endpoint的fd被关闭
 * -ENOENT: 没有找到对应日志的格式信息，比如ringbuf的数据损坏
 * -EPROTO: 日志长度 与 对应的格式描述 不符合，数据损坏的可能
 *    ... : 系统函数read()返回-1时的错误码，已处理成负数
 */
int tb_read_ring(char *msg, int len, int (*cb)(int *), int *ctx)
{
    struct tb_trace *tb = &g_tb_trace;
    int rc = 0, fd =tb->fd - 1;

    if (tb->fd <= 0)
        return -EBADFD;

    do {

        /* process the remained messages in pool */
        while (tb->start < tb->msgsz) {
            char *dat = g_tb_trace.pool;
            int ret, rec = tb->msgsz - tb->start;

            ret = sd_unpack(&msg[rc], len - rc,
                            &dat[tb->start], &rec);
            /* len - rc: isn't long enough for new event */
            if (rc && !ret)
                break;

            /* got error in unpacking or msg is too small */
            tb->start += rec;
            if (ret <= 0)
                break;

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
        tb->msgsz = read(fd, tb->pool, tb->bufsz - 1);
        if (tb->msgsz < 0)
            rc = -errno;
    } while (rc < len && rc >= 0);

out:
    return rc;
}

int tb_is_passed(struct timeval *tv, long cycle)
{
    struct timeval now;

    gettimeofday(&now, NULL);
    return ((int64_t)now.tv_sec * 1000000UL + now.tv_usec >=
            (int64_t)tv->tv_sec * 1000000UL + tv->tv_usec + cycle);
}

int tb_stat_ring(struct ring_stat *stat)
{
    struct tb_stat ts = {0};
    int rc, fd = g_tb_trace.fd - 1;

    rc = ioctl(fd, TRACE_IOCTL_STAT, &ts);
    if (rc == sizeof(ts)) {
        gettimeofday(&stat->tv, NULL);
        stat->npros = ts.produced_events;
        stat->ncons = ts.consumed_events;
        stat->ndrop = ts.dropped_events + ts.rejected_events;
        stat->ndisc = ts.discarded_events + ts.overwritten_events;
        stat->cpros = ts.produced_size;
        stat->ccons = ts.consumed_size;
        stat->cdrop = ts.dropped_size + ts.rejected_size;
        stat->cdisc = ts.discarded_size + ts.overwritten_size;
        stat->nexcd = ts.rejected_events;
        stat->maxsz = ts.max_event_size;
        stat->nrings = ts.num_cpu_rings;
        stat->flags = ts.overwritable;
        return sizeof(*stat);
    } else {
        printf("faiiled to query ioctl: %d\n", rc);
    }
    return 0;
}

void tb_show_ring(struct ring_stat *s, struct ring_stat *l, struct ring_stat *n)
{
    double interval, elapsed, i1, i2;
    char  *u1, *u2;

    if (n->npros - l->npros > 500UL * 1000 * 1024) {
        u1 = "G";
        i1 = 1024.0 * 1024 * 1024;
    } else if (n->npros - l->npros > 900 * 1024) {
        u1 = "M";
        i1 = 1024.0 * 1024;
    } else if (n->npros - l->npros > 2 * 1024) {
        u1 = "K";
        i1 = 1024.0;
    } else {
        u1 = "n";
        i1 = 1.0;
    }

    if (n->cpros - l->cpros > 500UL * 1000 * 1024) {
        u2 = "GB";
        i2 = 1024.0 * 1024 * 1024;
    } else if (n->cpros - l->cpros > 900 * 1024) {
        u2 = "MB";
        i2 = 1024.0 * 1024;
    } else if (n->cpros - l->cpros > 2 * 1024) {
        u2 = "KB";
        i2 = 1024.0;
    } else {
        u2 = "bytes";
        i2 = 1.0;
    }

    interval = (double)((int64_t)(n->tv.tv_sec - l->tv.tv_sec) * 1000000UL +
                        n->tv.tv_usec - l->tv.tv_usec) / 1000000.0;

    elapsed = (double)((int64_t)(n->tv.tv_sec - s->tv.tv_sec) * 1000000UL +
                        n->tv.tv_usec - l->tv.tv_usec) / 1000000.0;

    if (s != l) {
        printf("\nCPU cores: %d  \tInterval: %.1fs  \t\tElapsed: %.1fs\t\tExtra-large payload: %lu/%u\n",
                n->nrings, interval, elapsed, n->nexcd, n->maxsz);
    } else {
        printf("\nCPU cores: %d  \tElapsed: %.1f (seconds)\t\tExtra-large payload: %lu/%u\n",
                n->nrings, elapsed, n->nexcd, n->maxsz);
    }
    printf("items (%s)\t\t\t\t\t\t\tbytes (%s)\n", u1, u2);
    printf("produced\tconsumed\t dropped\tdiscarded    "
           "\tproduced\tconsumed\t dropped\tdiscarded\n");
    printf("%8lu\t%8lu\t%8lu\t%8lu    "
           "\t%8lu\t%8lu\t%8lu\t%8lu\n",
            n->npros - l->npros,
            n->ncons - l->ncons,
            n->ndrop - l->ndrop,
            n->ndisc - l->ndisc,

            n->cpros - l->cpros,
            n->ccons - l->ccons,
            n->cdrop - l->cdrop,
            n->cdisc - l->cdisc
           );
    printf("%8.3f\t%8.3f\t%8.3f\t%8.3f    "
           "\t%8.3f\t%8.3f\t%8.3f\t%8.3f\n",
            (double)(n->npros - l->npros) / i1,
            (double)(n->ncons - l->ncons) / i1,
            (double)(n->ndrop - l->ndrop) / i1,
            (double)(n->ndisc - l->ndisc) / i1,

            (double)(n->cpros - l->cpros) / i2,
            (double)(n->ccons - l->ccons) / i2,
            (double)(n->cdrop - l->cdrop) / i2,
            (double)(n->cdisc - l->cdisc) / i2
           );

    if ((double)(n->npros - l->npros) > interval * 500UL * 1000 * 1024) {
        u1 = "G";
        i1 = 1024.0 * 1024 * 1024;
    } else if ((double)(n->npros - l->npros) > interval * 900 * 1024) {
        u1 = "M";
        i1 = 1024.0 * 1024;
    } else if ((double)(n->npros - l->npros) > interval * 2 * 1024) {
        u1 = "K";
        i1 = 1024.0;
    } else {
        u1 = "n";
        i1 = 1.0;
    }

    if ((double)(n->cpros - l->cpros) > interval * 500UL * 1000 * 1024) {
        u2 = "GB";
        i2 = 1024.0 * 1024 * 1024;
    } else if ((double)(n->cpros - l->cpros) > interval * 900 * 1024) {
        u2 = "MB";
        i2 = 1024.0 * 1024;
    } else if ((double)(n->cpros - l->cpros) > interval * 2 * 1024) {
        u2 = "KB";
        i2 = 1024.0;
    } else {
        u2 = "bytes";
        i2 = 1.0;
    }

    printf("items (%s/s)\t\t\t\t\t\t\tbytes (%s/s)\n", u1, u2);
    printf("produced\tconsumed\t dropped\tdiscarded    "
           "\tproduced\tconsumed\t dropped\tdiscarded\n");
    printf("%8.3f\t%8.3f\t%8.3f\t%8.3f    "
           "\t%8.3f\t%8.3f\t%8.3f\t%8.3f\n",
            (double)(n->npros - l->npros) / i1 / interval,
            (double)(n->ncons - l->ncons) / i1 / interval,
            (double)(n->ndrop - l->ndrop) / i1 / interval,
            (double)(n->ndisc - l->ndisc) / i1 / interval,

            (double)(n->cpros - l->cpros) / i2 / interval,
            (double)(n->ccons - l->ccons) / i2 / interval,
            (double)(n->cdrop - l->cdrop) / i2 / interval,
            (double)(n->cdisc - l->cdisc) / i2 / interval
           );
}

int tb_register_binfmt(void)
{
    int cmd = TRACE_IOCTL_FILTER + REGISTER_BINFMT;
    return ioctl(g_tb_trace.fd - 1, cmd, NULL);
}

int tb_unregister_binfmt(void)
{
    int cmd = TRACE_IOCTL_FILTER + UNREGISTER_BINFMT;
    return ioctl(g_tb_trace.fd - 1, cmd, NULL);
}

int tb_pre_unload(void)
{
    return tb_unregister_binfmt();
}

int ac_init(int type, char *trace)
{
    char fds[64], rev[16];
    FILE *fp;
    int fd = -1, rc = 0;

    /* consuming channel was already opened */
    if (g_tb_trace.fd) {
        g_tb_trace.instances++;
        return 0;
    }

    /* control path must be provided manually */
    if (!trace)
        return -1;
    if (RING_KMOD != type)
        return -2;

    fp = fopen(trace, "rb");
    if (!fp) {
        printf("Error: Elkeid kernel module isn't loaded.\n");
        return -3;
    }

    if (fgets(fds, 64, fp))
        sscanf(fds, "KMOD: %s PIPE: %d\n", rev, &fd);
    if (fd < 0) {
        printf("Error: failed to open hids endpoint\n");
        return -4;
    }

    g_tb_trace.fd = fd + 1;
    g_tb_trace.instances++;
    return 0;
}

void ac_fini(int type)
{
    if (RING_KMOD != type)
        return;

    if (g_tb_trace.fd <= 0)
        return;
    if (--g_tb_trace.instances > 0)
        return;
    close(g_tb_trace.fd - 1);
    g_tb_trace.fd = 0;
}

static uint8_t ac_char2hex(uint8_t b)
{
    if (b >= '0' && b <= '9')
        b = b - '0';
    else if (b >= 'a' && b <= 'f')
        b = b - 'a' + 10;
    else if (b >= 'A' && b <= 'F')
        b = b - 'A' + 10;
    else
        return 0xff;
    return b;
}

static int ac_pack_md5(image_hash_t *md5, char *id, char *size, char *hash)
{
    int i, cmd;

    if (strlen(id) < 8)
        return -EINVAL;
    memcpy(&md5->id[0], &id[2], 6); /* prifix: 'EL' omitted */
    md5->hlen = 16;
    md5->size = (uint64_t)(long)size;
    md5->hash.v64[0] = md5->hash.v64[1] = 0;
    for (i = 0; i < 16; i++) {
        uint8_t b1, b2;
        b1 = ac_char2hex(hash[i * 2]);
        if (b1 > 0x0f)
            return -EINVAL;
        b2 = ac_char2hex(hash[i * 2 + 1]);
        if (b2 > 0x0f)
            return -EINVAL;
        md5->hash.v8[i] = (b1 << 4) | b2;
    }
#if 0
    printf("MD5 Rule: EL%6.6s: %u ", md5->id, md5->hlen);
    for (i = 0; i < 16; i++)
        printf("%2.2x", md5->hash.v8[i]);
    printf(" %lu\n", md5->size);
#endif
    cmd = TRACE_IOCTL_FILTER + IMAGE_MD5_ADD;
    return ioctl(g_tb_trace.fd - 1, cmd, md5);
}

#define MAX_RULE_SIZE (65536)
static int ac_pack_rule(char *id, int nitems, char *items[])
{
    exe_rule_flex_t *rule;
    char *data;
    int i, cmd, rc, len = 0;

    if (strlen(id) < 8)
        return -EINVAL;

    data = malloc(MAX_RULE_SIZE);
    memset(data, 0, MAX_RULE_SIZE);
    rule = (exe_rule_flex_t *)data;
    memcpy(rule->id, id, 8);
    for (i = 0; i < nitems; i++) {
        if (!items[i])
            continue;
        rule->items[i].len = strlen(items[i]);
        if (!rule->items[i].len)
            continue;
        rule->items[i].off = len;
        len += rule->items[i].len + 1;
        if (len > MAX_RULE_SIZE) {
            printf("ac_pack_rule: given rule is too long.\n");
            return 0;
        }
        strcpy(&rule->data[rule->items[i].off], items[i]);
    }

    if (len) {
        rule->size = sizeof(exe_rule_flex_t) + len;
        rule->nitems = nitems;
        // printf("%s %s %s %s %s\n", id, items[0], items[1], items[2], items[3]);
        // sd_hexdump(rule, rule->size);
        cmd = TRACE_IOCTL_FILTER + IMAGE_EXE_ADD;
        rc = ioctl(g_tb_trace.fd - 1, cmd, data);
    }

    if (data)
        free(data);
    return 0;
}

#include "zua_parser_defs.h"
static int ac_setup_blocklist(int ac, char *json, int len)
{
    zval *response, *rules;
    int i, rc = -1;

    response = json_decode(json, (uint32_t)len);
    if (response->u2.errcode != 0) {
        printf("failed to parse json strings.\n");
        goto out;
    }

    rules = zua_get_value_by_path(response, ZUA_STR("R"));
    if (!rules)
        goto out;

    for (i = 0; ; i++) {
        zval *rule;
        rule = zua_get_value_by_index(rules, i);
        if (!rule)
           break;
        if (ac == BL_JSON_EXE) {
            zval *id, *exe, *cmd, *stdin, *stdout;
            char *items[4];
            id = zua_get_value_by_path(rule, ZUA_STR("ID"));
            exe = zua_get_value_by_path(rule, ZUA_STR("Exe"));
            cmd = zua_get_value_by_path(rule, ZUA_STR("Argv"));
            stdin = zua_get_value_by_path(rule, ZUA_STR("Stdin"));
            stdout = zua_get_value_by_path(rule, ZUA_STR("Stdout"));
            if (!id || !Z_STR_P(id))
                break;
            items[0] = (exe && Z_STR_P(exe)) ? ZSTR_VAL(Z_STR_P(exe)) : NULL;
            items[1] = (cmd && Z_STR_P(cmd)) ? ZSTR_VAL(Z_STR_P(cmd)) : NULL;
            items[2] = (stdin && Z_STR_P(stdin)) ? ZSTR_VAL(Z_STR_P(stdin)) : NULL;
            items[3] = (stdout && Z_STR_P(stdout)) ? ZSTR_VAL(Z_STR_P(stdout)) : NULL;
            rc = ac_pack_rule(ZSTR_VAL(Z_STR_P(id)), 4, items);
        } else if (ac == BL_JSON_MD5) {
            image_hash_t hash;
            zval *id, *md5, *size;
            id = zua_get_value_by_path(rule, ZUA_STR("ID"));
            md5 = zua_get_value_by_path(rule, ZUA_STR("M2MD5"));
            size = zua_get_value_by_path(rule, ZUA_STR("Size"));
            if (!id || !md5 || !size || !Z_STR_P(id) ||
                !Z_STR_P(md5) || !Z_STR_P(size))
                break;
            rc = ac_pack_md5(&hash, ZSTR_VAL(Z_STR_P(id)),
                            (char *)Z_STR_P(size),
                            ZSTR_VAL(Z_STR_P(md5)));
        } else if (ac == BL_JSON_DNS) {
        }
    }

out:
    if (response)
        zval_free(response);
    return rc;
}

static int ac_setup_allowlist(int ac, char *item, int len)
{
    int cmd;

    if (ac == AL_TYPE_ARGV)
        cmd = TRACE_IOCTL_FILTER + ADD_EXECVE_ARGV_ALLOWLIST;
    else if (ac == AL_TYPE_EXE)
        cmd = TRACE_IOCTL_FILTER + ADD_EXECVE_EXE_ALLOWLIST;
    else if (ac == AL_TYPE_PSAD)
        cmd = TRACE_IOCTL_FILTER + PSAD_IP_LIST;
    else
        return -2;

    return ioctl(g_tb_trace.fd - 1, cmd, item);
}

int ac_setup(int ac, char *item, int len)
{
    if (!item)
        return -1;

    if (ac >= AL_TYPE_ARGV && ac <= AL_TYPE_PSAD)
        return ac_setup_allowlist(ac, item, len);
    if (ac >= BL_JSON_DNS && ac <= BL_JSON_MD5)
        return ac_setup_blocklist(ac, item, len);
    return -2;
}

static int ac_erase_allowlist(int ac, char *item, int len)
{
    int cmd;

    if (ac == AL_TYPE_ARGV) {
        if (item)
            cmd = TRACE_IOCTL_FILTER + DEL_EXECVE_ARGV_ALLOWLIST;
        else
            cmd = TRACE_IOCTL_FILTER + DEL_ALL_EXECVE_ARGV_ALLOWLIST;
    } else if (ac == AL_TYPE_EXE) {
        if (item)
            cmd = TRACE_IOCTL_FILTER + DEL_EXECVE_EXE_ALLOWLIST;
        else
            cmd = TRACE_IOCTL_FILTER + DEL_ALL_EXECVE_EXE_ALLOWLIST;
    } else if (ac == AL_TYPE_PSAD) {
        cmd = TRACE_IOCTL_FILTER + PSAD_IP_LIST;
    }

    return ioctl(g_tb_trace.fd - 1, cmd, item);
}

int ac_erase(int ac, char *item, int len)
{
    if (ac >= AL_TYPE_ARGV && ac <= AL_TYPE_PSAD)
        return ac_erase_allowlist(ac, item, len);
    return -2;
}

int ac_clear_allowlist(int ac)
{
    int cmd;

    if (ac == AL_TYPE_ARGV)
        cmd = TRACE_IOCTL_FILTER + DEL_ALL_EXECVE_ARGV_ALLOWLIST;
    else if (ac == AL_TYPE_EXE)
        cmd = TRACE_IOCTL_FILTER + DEL_ALL_EXECVE_EXE_ALLOWLIST;
    else if (ac == AL_TYPE_PSAD)
        cmd = TRACE_IOCTL_FILTER + PSAD_IP_LIST;
    else
        return -2;

    return ioctl(g_tb_trace.fd - 1, cmd, NULL);
}

int ac_clear_blocklist(int ac)
{
    int cmd, rc = -2;

    if (ac == BL_JSON_MD5) {
        cmd = TRACE_IOCTL_FILTER + IMAGE_MD5_CLR;
        rc = ioctl(g_tb_trace.fd - 1, cmd, NULL);
    } else if (ac == BL_JSON_EXE) {
        cmd = TRACE_IOCTL_FILTER + IMAGE_EXE_CLR;
        rc = ioctl(g_tb_trace.fd - 1, cmd, NULL);
    }

    return rc;
}

int ac_clear(int ac)
{
    if (ac >= AL_TYPE_ARGV && ac <= AL_TYPE_PSAD)
        return ac_clear_allowlist(ac);
    if (ac >= BL_JSON_DNS && ac <= BL_JSON_MD5)
        return ac_clear_blocklist(ac);
    return -2;
}

int ac_check(int ac, char *item, int len)
{
    int cmd;

    if (!item)
        return -1;

    if (ac == AL_TYPE_ARGV)
        cmd = TRACE_IOCTL_FILTER + EXECVE_ARGV_CHECK;
    else if (ac == AL_TYPE_EXE)
        cmd = TRACE_IOCTL_FILTER + EXECVE_EXE_CHECK;
    else if (ac == BL_JSON_MD5)
        cmd = TRACE_IOCTL_FILTER + IMAGE_MD5_CHK;
    else if (ac == BL_JSON_EXE)
        cmd = TRACE_IOCTL_FILTER + IMAGE_EXE_CHK;
    else
        return -2;

    return ioctl(g_tb_trace.fd - 1, cmd, item);
}

int ac_query(int ac, char *buf, int len)
{
    int cmd;

    if (ac == AL_TYPE_ARGV)
        cmd = TRACE_IOCTL_FILTER + PRINT_ARGV_ALLOWLIST;
    else if (ac == AL_TYPE_EXE)
        cmd = TRACE_IOCTL_FILTER + PRINT_EXE_ALLOWLIST;
    else
        return -2;

    return ioctl(g_tb_trace.fd - 1, cmd, buf);
}

static int ac_process_kmod(char *control, char *ptr, int len, int quiet)
{
    char *arg = ptr;
    int cmd, i, rc;

    rc = ac_init(RING_KMOD, control);
    if (rc)
        return rc;

    while (isspace(arg[0]) || arg[0]== '\"' || arg[0]== '\'')
        arg++;
    while ((i = strlen(arg)) > 0) {
        if (isspace(arg[i - 1]) || arg[i - 1] == '\"' || arg[i - 1] == '\'')
            arg[i - 1] = 0;
        else
            break;
    }
    cmd = arg[0];
    arg++;

    while (arg[0]== '\"' || arg[0]== '\'')
        arg++;

    switch(cmd) {
        case ADD_EXECVE_EXE_ALLOWLIST:
             ac_setup(AL_TYPE_EXE, arg, strlen(arg));
             break;
        case EXECVE_EXE_CHECK:
             rc = ac_check(AL_TYPE_EXE, arg, strlen(arg));
             if (quiet)
                break;
             if (rc == 0 || rc == 1)
                printf("exe: %s is %sin allowlsit.\n", arg,
                       rc ? "" : "NOT ");
             else
                printf("exe query failed with %d.\n", rc);
             break;
        case DEL_EXECVE_EXE_ALLOWLIST:
             ac_erase(AL_TYPE_EXE, arg, strlen(arg));
             break;
        case DEL_ALL_EXECVE_EXE_ALLOWLIST:
             ac_erase(AL_TYPE_EXE, NULL, 0);
             break;

        case ADD_EXECVE_ARGV_ALLOWLIST:
            ac_setup(AL_TYPE_ARGV, arg, strlen(arg));
            break;
        case EXECVE_ARGV_CHECK:
            rc = ac_check(AL_TYPE_ARGV, arg, strlen(arg));
            if (quiet)
                break;
            if (rc == 0 || rc == 1)
                printf("cmd: %s is %sin allowlsit.\n", arg,
                        rc ? "" : "NOT ");
             else
                printf("cmd query failed with %d.\n", rc);
            break;
        case DEL_EXECVE_ARGV_ALLOWLIST:
            ac_erase(AL_TYPE_ARGV, arg, strlen(arg));
            break;
        case DEL_ALL_EXECVE_ARGV_ALLOWLIST:
            ac_erase(AL_TYPE_ARGV, NULL, 0);
            break;

        case PRINT_ARGV_ALLOWLIST:
        case PRINT_EXE_ALLOWLIST:
            if (len < 1024) {
                if (cmd == PRINT_ARGV_ALLOWLIST)
                    rc = ac_query(AL_TYPE_ARGV, NULL, 0);
                else
                    rc = ac_query(AL_TYPE_EXE, NULL, 0);
            } else {
                memset(ptr, 0, len);
                if (cmd == PRINT_ARGV_ALLOWLIST)
                    rc = ac_query(AL_TYPE_ARGV, ptr, len);
                else
                    rc = ac_query(AL_TYPE_EXE, ptr, len);
                if (quiet)
                    break;
                for (i = 0; i < rc; i++) {
                    if (ptr[i])
                        printf("%c", ptr[i]);
                    else
                        printf("\n");
                }
            }
            break;
    }

    ac_fini(RING_KMOD);
    return rc;
}

int ac_process(int type, char *control, char *ptr, int len, int quiet)
{
    if (type != RING_KMOD)
        return -1;

    return ac_process_kmod(control, ptr, len, quiet);
}

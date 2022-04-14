// SPDX-License-Identifier: GPL-2.0

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <fcntl.h>

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

int tb_hexdump(void *ptr, int len)
{
    uint8_t *dat = ptr;
    char str[18] = {0}, hex[50] = {0};
    int i, j, bytes = 0;

    for  (i = 0; i < len; i += 16) {
        memset(str, '.', 16);
        memset(hex, ' ', 48);
        for (j = 0; j < 16; j++) {
            if (i + j < len) {
                sprintf(&hex[3 * j], "%2.2X ", dat[i + j]);
                if (dat[i + j] >= 0x20 && dat[i + j] <= 0x7e)
                    str[j] = dat[i + j];
            } else {
                sprintf(&hex[3 * j], "   ");
            }
        }
        printf("%s | %s\n", hex, str);
    }
}

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
static struct sd_item_ent *sd_query_event(void *data, int *rec)
{
    struct sd_item_ent *head = data + sizeof(u64);
    uint32_t eid = head[0].eid;

    if (eid > 0 && eid <= g_sd_formats->nids) {
        struct sd_item_ent *item = g_sd_events[eid - 1];
        /* now we do some verifications */
        if (eid != item[0].eid || head[0].size <= item[1].meta ||
            head[1].meta != item[1].meta || head[1].xid != item[1].xid) {
            tb_hexdump(head, sizeof(*head) * 2);
            tb_hexdump(item, sizeof(*item) * 2);
            return 0;
        }
        *rec = head[0].size + sizeof(u64);
        return item;
    }

    return NULL;
}

/*
 * our own atoi() implementation to replace snprintf:
 * 3x faster than snprintf for integers serializing
 */
static inline int sd_u0toa(uint32_t v, char *s, int l)
{
    if (l < 2)
        return 0;
    s[0] = '0' + v;
    s[1] = SD_SEP_ENTRY;
    return 2;
}

static inline int sd_i0toa(int32_t v, char *s, int l)
{
    if (l < 3)
        return 0;
    s[0] = '-';
    s[1] = '0' - v;
    s[2] = SD_SEP_ENTRY;
    return 3;
}

/*
 * 10x10 lookup table of 2 decimal digis
 *
 * reference url:
 * https://lemire.me/blog/2021/11/18/converting-integers-to-fix-digit-representations-quickly/
 *
 */

static const char g_tab_2digs[200] = {
      0x30, 0x30, 0x30, 0x31, 0x30, 0x32, 0x30, 0x33, 0x30, 0x34, 0x30, 0x35,
      0x30, 0x36, 0x30, 0x37, 0x30, 0x38, 0x30, 0x39, 0x31, 0x30, 0x31, 0x31,
      0x31, 0x32, 0x31, 0x33, 0x31, 0x34, 0x31, 0x35, 0x31, 0x36, 0x31, 0x37,
      0x31, 0x38, 0x31, 0x39, 0x32, 0x30, 0x32, 0x31, 0x32, 0x32, 0x32, 0x33,
      0x32, 0x34, 0x32, 0x35, 0x32, 0x36, 0x32, 0x37, 0x32, 0x38, 0x32, 0x39,
      0x33, 0x30, 0x33, 0x31, 0x33, 0x32, 0x33, 0x33, 0x33, 0x34, 0x33, 0x35,
      0x33, 0x36, 0x33, 0x37, 0x33, 0x38, 0x33, 0x39, 0x34, 0x30, 0x34, 0x31,
      0x34, 0x32, 0x34, 0x33, 0x34, 0x34, 0x34, 0x35, 0x34, 0x36, 0x34, 0x37,
      0x34, 0x38, 0x34, 0x39, 0x35, 0x30, 0x35, 0x31, 0x35, 0x32, 0x35, 0x33,
      0x35, 0x34, 0x35, 0x35, 0x35, 0x36, 0x35, 0x37, 0x35, 0x38, 0x35, 0x39,
      0x36, 0x30, 0x36, 0x31, 0x36, 0x32, 0x36, 0x33, 0x36, 0x34, 0x36, 0x35,
      0x36, 0x36, 0x36, 0x37, 0x36, 0x38, 0x36, 0x39, 0x37, 0x30, 0x37, 0x31,
      0x37, 0x32, 0x37, 0x33, 0x37, 0x34, 0x37, 0x35, 0x37, 0x36, 0x37, 0x37,
      0x37, 0x38, 0x37, 0x39, 0x38, 0x30, 0x38, 0x31, 0x38, 0x32, 0x38, 0x33,
      0x38, 0x34, 0x38, 0x35, 0x38, 0x36, 0x38, 0x37, 0x38, 0x38, 0x38, 0x39,
      0x39, 0x30, 0x39, 0x31, 0x39, 0x32, 0x39, 0x33, 0x39, 0x34, 0x39, 0x35,
      0x39, 0x36, 0x39, 0x37, 0x39, 0x38, 0x39, 0x39,
};

static inline int sd_u32toa(uint32_t v, char *s, int l)
{
    char t[12];
    int i = 0;

    if (v <= 9)
        return sd_u0toa(v, s, l);

    while (v >= 100) {
        memcpy(&t[12 - (++i << 1)], &g_tab_2digs[(v % 100) << 1], 2);
        v = v / 100;
    }
    i = i << 1;
    if (i + 1 > l)
        return 0;

    while (v) {
        t[12 - ++i] = "0123456789"[v % 10];
        v = v / 10;
    }
    if (i + 1 > l)
        return 0;

    memcpy(s, &t[12 - i], i);
    s[i] = SD_SEP_ENTRY;

    return i + 1;
}

static inline int sd_u64toa(uint64_t v, char *s, int l)
{
    char t[24];
    int i = 0;

    if (v <= 9)
        return sd_u0toa((uint32_t)v, s, l);

    while (v >= 100) {
        memcpy(&t[24 - (++i << 1)], &g_tab_2digs[(v % 100) << 1], 2);
        v = v / 100;
    }
    i = i << 1;
    if (i + 1 > l)
        return 0;

    while (v) {
        t[24 - ++i] = "0123456789"[v % 10];
        v = v / 10;
    }
    if (i + 1 > l)
        return 0;

    memcpy(s, &t[24 - i], i);
    s[i] = SD_SEP_ENTRY;

    return i + 1;
}

static inline int sd_s32toa(int32_t v, char *s, int l)
{
    int rc = 0;

    if (v < 0 && v > -10) {
        return sd_i0toa(v, s, l);
    }
    if (v >= 0 && v <= 9) {
        return sd_u0toa((unsigned)v, s, l);
    }

    if (v < 0) {
        rc = sd_u32toa(0 - v, s + 1, l - 1);
        if (rc > 0) {
            *s = '-';
            return rc + 1;
        }
    } else {
        rc = sd_u32toa((unsigned)v, s, l);
    }

    return rc;
}

static inline int sd_s64toa(int64_t v, char *s, int l)
{
    int rc = 0;

    if (v < 0 && v > -10) {
        return sd_i0toa((int32_t)v, s, l);
    }
    if (v >= 0 && v <= 9) {
        return sd_u0toa((uint32_t)v, s, l);
    }

    if (v < 0) {
        rc = sd_u64toa(0 - v, s + 1, l - 1);
        if (rc > 0) {
            *s = '-';
            return rc + 1;
        }
    } else {
        rc = sd_u64toa((unsigned)v, s, l);
    }

    return rc;
}

#define SD_XFER_UNPACK_INTS(dt, fn, vt)                                     \
static inline int                                                           \
sd_xfer_unpack_##dt(void *b, int l, void *v, int s, int *r)                 \
{                                                                           \
    vt *d = (vt *)(v);                                                      \
    *r = sizeof(*d);                                                        \
    return sd_##fn##toa(*d, b, l);                                          \
}

SD_XFER_UNPACK_INTS(u8, u32, uint8_t)
SD_XFER_UNPACK_INTS(s8, s32, int8_t)
SD_XFER_UNPACK_INTS(u16, u32, uint16_t)
SD_XFER_UNPACK_INTS(s16, s32, int16_t)
SD_XFER_UNPACK_INTS(u32, u32, uint32_t)
SD_XFER_UNPACK_INTS(s32, s32, int32_t)
SD_XFER_UNPACK_INTS(u64, u64, uint64_t)
SD_XFER_UNPACK_INTS(s64, s64, int64_t)

static inline int sd_xfer_unpack_ip4(void *b, int l, void *v, int s, int *r)
{
    uint8_t *d = (uint8_t *)(v);
    *r = sizeof(struct ipaddr_v4);
    return snprintf(b, l, "%u.%u.%u.%u%c", d[0], d[1], d[2], d[3], SD_SEP_ENTRY);
}

static inline int sd_xfer_unpack_ip6(void *b, int l, void *v, int s, int *r)
{
    uint16_t *d = (uint16_t *)(v);
    *r = sizeof(struct ipaddr_v6);
    return snprintf(b, l, "%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x%c",
                    d[0], d[1], d[2], d[3], d[4], d[5], d[6], d[7], SD_SEP_ENTRY);
}

static inline int sd_xfer_unpack_ip4be(void *b, int l, void *v, int s, int *r)
{
    uint8_t *d = (uint8_t *)(v);
    *r = sizeof(struct ipaddr_v4);
    return snprintf(b, l, "%u.%u.%u.%u%c", d[3], d[2], d[1], d[0], SD_SEP_ENTRY);
}

static inline int sd_xfer_unpack_ip6be(void *b, int l, void *v, int s, int *r)
{
    uint16_t *d = (uint16_t *)(v);
    *r = sizeof(struct ipaddr_v6);;
    return snprintf(b, l, "%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x%c",
                    d[7], d[6], d[5], d[4], d[3], d[2], d[1], d[0], SD_SEP_ENTRY);
}

static int sd_xfer_unpack_string(void *b, int l, void *v, int s, int *r)
{
    uint16_t *pv = v;
    char *str;
    int rc = 0;

    if (pv[1] > 0) {
        rc = pv[1];
        str = (char *)v + pv[0];
    } else {
        rc = 6;
        str = "(null)";
    }
    if (rc > l)
        return 0;
    memcpy(b, str, rc);
    if (rc < l)
        ((char *)b)[rc++] = SD_SEP_ENTRY;
    *r = sizeof(uint16_t) * 2;

    return rc;
}

#define SD_XFER_UNPACK(dt)   sd_xfer_unpack_##dt

struct sd_type_ent {
    uint16_t type;
    uint16_t size;
    int (*unpack)(void *, int, void *, int, int *);
} g_sd_types[] = {

    [SD_TYPE_U8] = {SD_TYPE_U8, 1, SD_XFER_UNPACK(u8)},
    [SD_TYPE_S8] = {SD_TYPE_U8, 1, SD_XFER_UNPACK(s8)},

    [SD_TYPE_U16] = {SD_TYPE_U16, 2, SD_XFER_UNPACK(u16)},
    [SD_TYPE_S16] = {SD_TYPE_U16, 2, SD_XFER_UNPACK(s16)},

    [SD_TYPE_U32] = {SD_TYPE_U32, 4, SD_XFER_UNPACK(u32)},
    [SD_TYPE_S32] = {SD_TYPE_U32, 4, SD_XFER_UNPACK(s32)},

    [SD_TYPE_U64] = {SD_TYPE_U64, 8, SD_XFER_UNPACK(u64)},
    [SD_TYPE_S64] = {SD_TYPE_U64, 8, SD_XFER_UNPACK(s64)},

    [SD_TYPE_IP4] = {SD_TYPE_IP4, sizeof(struct ipaddr_v4), SD_XFER_UNPACK(ip4)},
    [SD_TYPE_IP6] = {SD_TYPE_IP6, sizeof(struct ipaddr_v6), SD_XFER_UNPACK(ip6)},
    [SD_TYPE_IP4BE] = {SD_TYPE_IP4BE, sizeof(struct ipaddr_v4), SD_XFER_UNPACK(ip4be)},
    [SD_TYPE_IP6BE] = {SD_TYPE_IP6BE, sizeof(struct ipaddr_v6), SD_XFER_UNPACK(ip6be)},

    [SD_TYPE_STRING] = {SD_TYPE_STRING, 4, SD_XFER_UNPACK(string)}
};

int tb_unpack(void *de, int sde, void *se, int *rec)
{
    struct sd_item_ent *it;
    int in = 0, i = 1, out, sse;

    if (*rec <= sizeof(u64) + sizeof(*it) * 2)
        return 0;
    it = sd_query_event(se, &sse);
    if (!it || sse > *rec)
        return 0;
    *rec = sse;

    /* skip ts + head + meta */
    in += sizeof(u64) + sizeof(*it) + sizeof(uint32_t);

    /* timestamp */
    out = sd_u64toa(*((uint64_t *)se), de, sde);
    if (out <= 0)
        return 0;
    while (in < sse && out < sde) {
        int rc, ri = 0;
        uint8_t t = (uint8_t)it[++i].item;

        /* validate the type of current item */
        if (!t && out)
            break;
        if (t >= sizeof(g_sd_types) / sizeof(struct sd_type_ent))
            return 0;
        if (!g_sd_types[t].unpack)
            return 0;
        if (g_sd_types[t].size != it[i].len)
            return 0;

        /* start deserializing */
        rc = g_sd_types[t].unpack(de + out, sde - out,
                                  se + in, sse - in, &ri);
        /* user buffer might overflow */
        if (rc <= 0 || ri != g_sd_types[t].size)
            return 0;

        in  += ri;
        out += rc;
    }

    /* filling record endian at the tail: SD_REC_ENDIAN */
    if (out && sde > out + 3) {
        *((uint32_t *)(de + out - 1)) = SD_REC_ENDIAN;
        out += 3;
    }

    return out;
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
} g_tb_trace;

int tb_init_ring(void)
{
    int fd, rc = 0;

    if (g_tb_trace.fd)
        return 0;

    g_tb_trace.bufsz = TB_BUFFER_SIZE;
    g_tb_trace.pool = malloc(g_tb_trace.bufsz);
    if (!g_tb_trace.bufsz)
        return -1;

    fd = open("/proc/elkeid-endpoint", O_RDONLY);
    if (fd < 0) {
        printf("Error: failed to open hids endpoint\n");
        free(g_tb_trace.pool);
        g_tb_trace.pool = NULL;
        return -2;
    }

    /* query events format */
    if (sd_init_format(fd)) {
        printf("Error: failed to open hids endpoint\n");
        free(g_tb_trace.pool);
        g_tb_trace.pool = NULL;
        close(fd);
        return -3;
    }

    g_tb_trace.fd = fd + 1;
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

    memset(&g_tb_trace, 0, sizeof(g_tb_trace));
    close(fd);
}

#define ALIGN(x, a) __ALIGN_MASK(x, (typeof(x))(a) - 1)
#define __ALIGN_MASK(x, mask) (((x) + (mask)) & ~(mask))

int tb_read_ring(char *msg, int len, int (*cb)(int *), int *ctx)
{
    struct tb_trace *tb = &g_tb_trace;
    int rc = 0, fd =tb->fd - 1;

    if (tb->fd <= 0)
        return rc;

    do {

        /* process the remained messages in pool */
        while (tb->start < tb->msgsz) {
            char *dat = g_tb_trace.pool;
            int ret, rec = tb->msgsz - tb->start;
            ret = tb_unpack(&msg[rc], len - rc,
                            &dat[tb->start], &rec);
            tb->start += rec;
            if (ret <= 0)
                break;

            rc += ret;
            if (rc >= len)
                goto out;
        }

        if (rc || cb(ctx))
            break;

        /* retrieve payloads from kernel to pool */
        tb->start = 0;
        tb->msgsz = read(fd, tb->pool, tb->bufsz - 1);

    } while (rc < len && tb->msgsz);

out:
    return rc;
}

int tb_is_elapsed(struct timeval *tv, long cycle)
{
    struct timeval now;

    gettimeofday(&now, NULL);
    return ((int64_t)now.tv_sec * 1000000UL + now.tv_usec >=
            (int64_t)tv->tv_sec * 1000000UL + tv->tv_usec + cycle);
}

int tb_query_stat_ring(struct ring_stat *stat)
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

void tb_show_stat_ring(struct ring_stat *s, struct ring_stat *l, struct ring_stat *n)
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

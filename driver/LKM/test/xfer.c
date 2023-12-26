// SPDX-License-Identifier: GPL-2.0

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <arpa/inet.h>

/*
 * xfer: event de-serializing
 */

#define __SD_XFER_DE__
#include "../include/xfer.h"

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
sd_xfer_unpack_##dt(void *b, int l, void *v, int s, int m, int *r)          \
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

static inline int sd_xfer_unpack_ip4(void *b, int l, void *v, int s, int m, int *r)
{
    uint8_t *d = (uint8_t *)(v);
    *r = sizeof(struct ipaddr_v4);
    return snprintf(b, l, "%u.%u.%u.%u%c", d[0], d[1], d[2], d[3], SD_SEP_ENTRY);
}

static inline int sd_xfer_unpack_ip6(void *b, int l, void *v, int s, int m, int *r)
{
    uint16_t *d = (uint16_t *)(v);
    *r = sizeof(struct ipaddr_v6);
    return snprintf(b, l, "%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x%c",
                    ntohs(d[0]), ntohs(d[1]), ntohs(d[2]), ntohs(d[3]), ntohs(d[4]),
                    ntohs(d[5]), ntohs(d[6]), ntohs(d[7]), SD_SEP_ENTRY);
}

static inline int sd_xfer_unpack_ip4be(void *b, int l, void *v, int s, int m, int *r)
{
    uint8_t *d = (uint8_t *)(v);
    *r = sizeof(struct ipaddr_v4);
    return snprintf(b, l, "%u.%u.%u.%u%c", d[3], d[2], d[1], d[0], SD_SEP_ENTRY);
}

static inline int sd_xfer_unpack_ip6be(void *b, int l, void *v, int s, int m, int *r)
{
    uint16_t *d = (uint16_t *)(v);
    *r = sizeof(struct ipaddr_v6);
    return snprintf(b, l, "%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x%c",
                    d[0], d[1], d[2], d[3], d[4], d[5], d[6], d[7], SD_SEP_ENTRY);
}

static inline int sd_xfer_unpack_xids(void *b, int l, void *v, int s, int m, int *r)
{
    uint32_t *d = (uint32_t *)(v);
    *r = sizeof(struct sd_xids);
    return snprintf(b, l, "%u|%u|%u|%u|%u|%u|%u|%u%c",
                    d[0], d[1], d[2], d[3], d[4], d[5], d[6], d[7], SD_SEP_ENTRY);
}

static __inline int sd_strncpy(char *d, int l, char *s)
{
    int r;

    if (!d || !s || l <= 1)
        return 0;

	r = strnlen(s, l);
	if (r <= 0)
        return 0;

    if (r >= l)
        r = l - 1;
    memcpy(d, s, r);
    return r;
}

static int sd_xfer_unpack_string(void *b, int l, void *v, int s, int m, int *r)
{
    uint16_t *pv = v;
    char *str;
    int rc = 0;

    if (pv[1] > 0) {
        rc = pv[1];
        str = (char *)v + pv[0] + m;
    } else {
        rc = 3;
        str = "-5";
    }
    if (rc > l)
        return 0;
    rc = sd_strncpy(b, rc, str);
    if (rc < l)
        ((char *)b)[rc++] = SD_SEP_ENTRY;
    *r = sizeof(uint16_t) * 2;

    return rc;
}

#define SD_XFER_UNPACK(dt)   sd_xfer_unpack_##dt

struct sd_type_ent {
    uint16_t type;
    uint16_t size;
    int (*unpack)(void *, int, void *, int, int, int *);
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

    [SD_TYPE_XIDS] = {SD_TYPE_XIDS, sizeof(struct sd_xids), SD_XFER_UNPACK(xids)},

    [SD_TYPE_STRING] = {SD_TYPE_STRING, 4, SD_XFER_UNPACK(string)}
};

struct sd_item_ent *sd_query_event(void *data, int *rec);
int sd_unpack(void *de, int sde, void *se, int *rec)
{
    struct sd_item_ent *it;
    int in = 0, i = 1, out = 0, sse;

    if (*rec <= sizeof(uint64_t) + sizeof(*it) * 2)
        return -EINVAL;
    it = sd_query_event(se, &sse);
    if (!it || sse > *rec)
        return -ENOENT;
    *rec = sse;

    /* skip timestamp + meta_head + meta_size */
    in +=  sizeof(uint64_t) + sizeof(*it) + sizeof(uint32_t);

#if defined(HAVE_EVENT_TIMESTAMP)
    /* timestamp */
    out = sd_u64toa(*((uint64_t *)se), de, sde);
    if (out <= 0)
        return out;
#endif

    while (in < sse && out < sde) {
        int rc, ri = 0;
        uint8_t t = (uint8_t)it[++i].item;

        /* validate the type of current item */
        if (!t && out)
            break;
        if (t >= sizeof(g_sd_types) / sizeof(struct sd_type_ent))
            return -ENOENT;
        if (!g_sd_types[t].unpack)
            return -ENOENT;
        if (g_sd_types[t].size != it[i].len)
            return -EPROTO;

        /* start deserializing */
        rc = g_sd_types[t].unpack(de + out, sde - out,
                                  se + in, sse - in,
                                  it[1].meta - in, &ri);
        if (ri != g_sd_types[t].size)
            return -EPROTO;

        /* user buffer might overflow */
        if (rc <= 0)
            return 0;

        in  += ri;
        out += rc;
    }

#if defined(HAVE_EVENTS_MULTIPLE)
    /* filling record endian at the tail: SD_REC_ENDIAN */
    if (out && sde > out + 3) {
        *((uint32_t *)(de + out - 1)) = SD_REC_ENDIAN;
        out += 3;
    }
#endif

    return out;
}


void sd_hexdump(void *ptr, int len)
{
    uint8_t *dat = ptr;
    char str[18] = {0}, hex[50] = {0};
    int i, j;

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
        printf("%8.8x %s | %s\n", i, hex, str);
    }
}

void sd_show_msg(char *str, int len)
{
    int i, s = 0;

    for (i = 1; i < len; i++) {
        if (str[i] != SD_SEP_ENTRY || i <= s)
            continue;
        if (i + 4 <= len && *((uint32_t *)&str[i]) == SD_REC_ENDIAN) {
            str[i + 1] = str[i + 2] = 0;
            printf("%*s\n", i - s, &str[s]);
            s = i + 4;
        } else if (i + 1 < len) {
            str[i] = 0x20;
        } else if (i > s + 4) {
            printf("%*s\n", i - s, &str[s]);
        }
    }
}


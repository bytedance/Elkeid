/* SPDX-License-Identifier: GPL-2.0 */

#ifndef _TRACE_EVENT_H
#define _TRACE_EVENT_H

#include "../include/trace_buffer.h"

/*
 * allowlist related defintions (exe_path or exe_argv)
 */

#define TRACE_IOCTL_STAT    (0xd00dbef0)    /* ioctl command for stat */
#define TRACE_IOCTL_FORMAT  (0xd00dbef1)    /* ioctl command for format query */
#define TRACE_IOCTL_FILTER  (0xd00dbf00)    /* allowlist filter controlling */
#define TRACE_IOCTL_MASK    (0xffffff00)    /* allostlist ioctl code bit-mask */

#define ADD_EXECVE_EXE_ALLOWLIST 70         /* F */
#define DEL_EXECVE_EXE_ALLOWLIST 89         /* Y */
#define DEL_ALL_EXECVE_EXE_ALLOWLIST 113    /* q */
#define EXECVE_EXE_CHECK 122                /* z */
#define PRINT_EXE_ALLOWLIST 42              /* * */
#define PRINT_ARGV_ALLOWLIST 43             /* + */
#define ADD_EXECVE_ARGV_ALLOWLIST 74        /* J */
#define DEL_EXECVE_ARGV_ALLOWLIST 109       /* m */
#define DEL_ALL_EXECVE_ARGV_ALLOWLIST 110   /* n */
#define EXECVE_ARGV_CHECK 125               /* k */
#define IMAGE_MD5_ADD  0x41                 /* A */
#define IMAGE_MD5_DEL  0x42                 /* B */
#define IMAGE_MD5_CLR  0x61                 /* a */
#define IMAGE_MD5_CHK  0x63                 /* c */
#define IMAGE_MD5_ENUM 0x45                 /* E */
#define IMAGE_EXE_ADD  0x62                 /* b */
#define IMAGE_EXE_DEL  0x44                 /* D */
#define IMAGE_EXE_CLR  0x43                 /* C */
#define IMAGE_EXE_CHK  0x64                 /* d */
#define IMAGE_EXE_ENUM 0x65                 /* e */
#define REGISTER_BINFMT 0x52                /* R */
#define UNREGISTER_BINFMT 0x55              /* U */
#define PSAD_IP_LIST   0x4e                 /* N */

/*
 * ip allowlist for psad
 */
struct psad_ip_list {
    uint32_t   type; /* 4: ipv4 / 10: ipv6 */
    uint32_t   nips; /* number of ips */
    uint32_t   ips[];
} __attribute__((packed));

/*
 * md5 hash description for exec blocklist
 */
typedef struct image_hash {
    uint64_t size; /* content length */
    uint16_t hlen; /* length of hash in bytes */
    char id[6]; /* rule id, without prefix "EL" */
    union {
        uint64_t v64[2];
        uint32_t v32[4];
        uint16_t v16[8];
        uint8_t v8[16];
    } hash; /* 128-bit md5 hash */
} __attribute__((packed)) image_hash_t;

/*
 * exe path/cmdline blocking rules
 */
typedef struct exe_rule_item {
    uint16_t off;
    uint16_t len;
} __attribute__((packed)) exe_rule_item_t;

typedef struct exe_rule_flex {
    uint16_t                size;   /* total size */
    uint16_t                nitems; /* num of items */
    char                    id[8];  /* rule id */

    union {
        exe_rule_item_t     items[4];
        struct {
            exe_rule_item_t exe;
            exe_rule_item_t cmd;
            exe_rule_item_t stdin;
            exe_rule_item_t stdout;
        };
    };
    char                    data[];
} __attribute__((packed)) exe_rule_flex_t;

struct exe_item {
    char               *item;
    int16_t             size;
};

#ifdef __KERNEL__
extern ssize_t (*smith_strscpy)(char *dest, const char *src, size_t count);
static __inline int sd_strncpy(char *d, int l, char *s)
{
    int rc;

    if (!d || !s || l <= 1)
       return 0;
    rc = smith_strscpy(d, s, l);
    if (rc < 0)
	return l;
    return rc;
}

extern uint64_t (*smith_ktime_get_real_ns)(void);
static __inline uint64_t sd_get_ns_time(void)
{
    return smith_ktime_get_real_ns();
}

/*
 * serializing related
 */
#define __SD_XFER_SE__
#include "../include/xfer.h"

/*
 * unique id of HIDS event (eg: 602 can have 3 event formats, thus 3 ids)
 */
#define SD_XFER_TYPEID_NAME(x)      XFER_TYPEID_##x
#undef  SD_XFER_DEFINE
#define SD_XFER_DEFINE(n, p, x)     SD_XFER_TYPEID_##n,

enum sd_xfer_typeid {
    XFER_TYPEID_null = 0,
#include "../include/kprobe_print.h"
#include "../include/anti_rootkit_print.h"
};

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 8, 0)
#define SMITH_NO_SANITIZE  __attribute__((no_sanitize("undefined")))
#else
#define SMITH_NO_SANITIZE
#endif

extern struct tb_ring *g_trace_ring;

#define SD_XFER_DEFINE_N(n, p, x)                               \
    SD_XFER_DEFINE_E(n, p, x);                                  \
    SMITH_NO_SANITIZE                                           \
    static inline int SD_XFER(n, SD_DECL_##p)                   \
    {                                                           \
        struct SD_XFER_EVENT_##n *__ev;                         \
        struct tb_event *__tr_event;                            \
        uint32_t __tr_used;                                     \
        uint32_t __tr_size;                                     \
        SD_ENTS_STRP_##x                                        \
        SD_ENTS_STRS_##x                                        \
        int __l_strs = 0 SD_DATA_##x;                           \
                                                                \
        /* initialize trace_record */                           \
        __tr_size = ALIGN(sizeof(*__ev) + __l_strs, 4);         \
        __tr_used = 0;                                          \
        /* try to allocate space from trace ringbuffer */       \
        __tr_event = tb_lock_reserve(g_trace_ring, __tr_size);  \
        if (likely(__tr_event)) {                               \
            __ev = tb_event_data(__tr_event);                   \
            __ev->e_timestamp = sd_get_ns_time();               \
            __ev->e_head.size = __tr_size;                      \
            __ev->e_head.eid = SD_XFER_TYPEID_##n;              \
            __ev->e_meta = sizeof(*__ev);                       \
            SD_ENTS_PACK_##x                                    \
            tb_unlock_commit(g_trace_ring);                     \
            return __tr_size;                                   \
        }                                                       \
        return 0;                                               \
    }

#else

/*
 * core routines for user mode consuming of trace-buffer
 */

#define RING_KMOD (0x5254004B)  /* kmod: elkeid/smith/hids_driver/ash */
#define RING_EBPF (0x52540045)  /* ebpf version */
int tb_init_ring(int type, char *control);

void tb_fini_ring(void);
int tb_read_ring(char *msg, int len, int (*cb)(int *), int *ctx);

/* manually register or cleanup binfmt callbacks */
int tb_register_binfmt(void);
int tb_unregister_binfmt(void);

/* tell LKM driver that it's to be unloaded */
int tb_pre_unload(void);

/*
 * statatics support routines
 */

struct ring_stat {
    uint32_t        nrings;
    uint32_t        flags;

    struct timeval  tv;
    uint64_t        npros;  /* number of messages producted */
    uint64_t        ncons;  /* number of messages consumed */
    uint64_t        ndrop;  /* dropped by producer when ring is full */
    uint64_t        ndisc;  /* discarded by producer for overwriting */
    uint64_t        nexcd;  /* total dropped messages (too long to save) */
    uint64_t        cpros;  /* bytes of produced messages */
    uint64_t        ccons;  /* bytes of consumed messages */
    uint64_t        cdrop;  /* bytes of dropped messages */
    uint64_t        cdisc;  /* bytes of discarded messages */
    uint32_t        maxsz;
};

int tb_is_passed(struct timeval *tv, long cycle);
int tb_stat_ring(struct ring_stat *stat);
void tb_show_ring(struct ring_stat *s, struct ring_stat *l, struct ring_stat *n);

/*
 * access-control for allowlist / blocklist
 */

/* dev must be RING_KMOD, RING_EBPF not supported */
int ac_init(int dev, char *control);
void ac_fini(int dev);

/* allowlist filters */
#define AL_TYPE_ARGV (0xA1)
#define AL_TYPE_EXE  (0xA2)

/* 设置端口扫描白名单，目前只支持ipv4设置，不支持查询、ipv6 */
#define AL_TYPE_PSAD (0xA3)

/* blocklist types */
#define BL_JSON_DNS  (0xB0)
#define BL_JSON_EXE  (0xB1) /* 同一json可包含命令行规则及可执行文件路径规则，有限通配符支持 */
#define BL_JSON_MD5  (0xB2)

/* 设置规则，支持list或json格式 */
int ac_setup(int ac, char *ptr, int len);

/* 清除特定类型的所有规则 */
int ac_clear(int ac);

/* 检测规则生效与否，仅适用于allowlist */
int ac_check(int ac, char *ptr, int len);

/* 删除特定规则，仅适用于allowlist */
int ac_erase(int ac, char *ptr, int len);

/* 读取当前所有规则，目前仅适用于allowlist */
int ac_query(int ac, char *ptr, int len);

int ac_process(int type, char *control, char *ptr, int len, int quiet);

#endif /* !__KERNEL__ */

#endif /* _TRACE_EVENT_H */

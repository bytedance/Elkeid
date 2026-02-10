/*
 * HIDS device types
 */

#define RING_KMOD (0x5254004B)  /* kmod: smith/hids_driver/ash */
#define RING_EBPF (0x52540045)  /* ebpf */

#define RING_TYPE(x)    (int)(((unsigned int)(x)) & 0xFFFF00FF)
#define RING_KMOD_V1_7  (0x5254174B)  /* kmod: hids_driver/ash */
#define RING_KMOD_V1_8  (0x5254184B)  /* kmod: smith */
#define RING_KMOD_V1_9  (0x5254194B)  /* kmod: elkeid */

/*
 * LKM & ringbuffer related routines
 */

/* control: "/sys/module/smith/parameters/control_trace" */
int tb_init_kmod(int dev, char *control);
int tb_fini_kmod(int dev);
int tb_read_kmod(char *msg, int len, int (*cb)(int *), int *ctx);

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
int tb_stat_kmod(struct ring_stat *stat);
void tb_show_kmod(struct ring_stat *s, struct ring_stat *l, struct ring_stat *n);

/*
 * ebpf (loader & consumer) related routines
 */

int tb_load_ebpf(const char *path);
void tb_unload_ebpf();

int tb_init_ebpf(int dev, char *control);
int tb_fini_ebpf(int dev);
int tb_read_ebpf(char *msg, int len, int (*cb)(int *), int *ctx);

/* query version and size of ebpf program */
int tb_query_ebpf(char *version, size_t *sz);

/*
 * general control routines for HIDS (kmod or ebpf)
 */

int tb_init(int dev, char *control);
int tb_read(char *msg, int len, int (*cb)(int *), int *ctx);
void tb_fini(int dev);

/*
 * access-control for allowlist / blocklist
 */

/* allowlist filters for LKM */
#define AL_TYPE_ARGV (0xA1)
#define AL_TYPE_EXE  (0xA2)

/* 设置端口扫描白名单，目前只支持ipv4设置，不支持查询、ipv6 */
#define AL_TYPE_PSAD (0xA3)

/* allowlist filters for ebpf */
#define AL_EBPF_ARGV (0xAA)
#define AL_EBPF_EXE  (0xAE)

/* blocklist types */
#define BL_JSON_DNS  (0xB0)
#define BL_JSON_EXE  (0xB1) /* 同一json可包含命令行规则及可执行文件路径规则，有限通配符支持 */
#define BL_JSON_MD5  (0xB2)

/* dev must be RING_KMOD or RING_EBPF */
int ac_init(int dev, char *control);
void ac_fini(int dev);

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

/* 仅用于kmod方式，用于兼容v1.7的消息输入格式 */
int ac_process(int type, char *control, char *ptr, int len, int quiet);

struct tb_ring_operations {
    int type;
    int version;

    int (*ring_init)(int type, char *trace);
    int (*ring_fini)(int type);
    int (*ring_read)(char *msg, int len, int (*cb)(int *), int *ctx);
    int (*ring_is_passed)(struct timeval *tv, long cycle);

    int (*ring_stat)(struct ring_stat *stat);
    void (*ring_show)(struct ring_stat *s, struct ring_stat *l, struct ring_stat *n);
    int (*register_binfmt)(void);
    int (*unregister_binfmt)(void);
    int (*pre_unload)(void);

    int (*ac_init)(int type, char *trace);
    int (*ac_fini)(int type);
    int (*ac_setup)(int ac, char *item, int len);
    int (*ac_erase)(int ac, char *item, int len);
    int (*ac_clear_allowlist)(int ac);
    int (*ac_clear_blocklist)(int ac);
    int (*ac_clear)(int ac);

    int (*ac_check)(int ac, char *item, int len);
    int (*ac_query)(int ac, char *buf, int len);
    int (*ac_process)(char *control, char *ptr, int len, int quiet);
};

/*
 * kernen panic evasion for LKM & ebpf drivers
 */

/*
 * 避让检测函数，返回1表示不用避让，其它值表示出错或需要避让；每次加载LKM或ebpf之前调用，
 * 此函数会在driver plugin同目录下创建并修改safeboot.dat文件
 */
int safeboot_check(void);

/*
 * 解除避让函数，每次安全卸载LKM或ebpf程序后执行即可，或者直接删除同目录下的避让描述文件
 * 即safeboot.dat文件（不建议直接删除）
 */
int safeboot_clear(void);


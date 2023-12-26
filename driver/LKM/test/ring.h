#include <stdlib.h>

/*
 * HIDS device types
 */

#define RING_KMOD (0x5254004B)  /* kmod: elkeid/smith/hids_driver/ash */
#define RING_EBPF (0x52540045)  /* ebpf version */

/*
 * ring buffer consuming routines
 */

/* control: "/sys/module/elkeid/parameters/control_trace" */
int tb_init_ring(int dev, char *control);
void tb_fini_ring(void);
int tb_pre_unload(void);

int tb_read_ring(char *msg, int len, int (*cb)(int *), int *ctx);

/*
 * access-control for allowlist / blocklist
 */

/* dev must be RING_KMOD, RING_EBPF not supported */
int ac_init(int dev, char *control);
void ac_fini(int dev);

/* allowlist filters */
#define AL_TYPE_ARGV (0xA1)
#define AL_TYPE_EXE  (0xA2)

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

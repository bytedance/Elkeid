/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __PROCLIST_H
#define __PROCLIST_H

#define PAGE_SIZE               (4096)
#define PAGE_MASK               (4095)
#define TASK_COMM_LEN           (16)
#define NODE_NAME_LEN           (64) /* __NEW_UTS_LEN */
#define PIDTREE_LEN             (32 * 8)
#define PIDTREE_MASK            (PIDTREE_LEN - 1)
#define STDIO_NAME_LEN          (64)
#define TTY_NAME_LEN            (64)
#define PATH_NAME_LEN           (256)
#define PATH_NAME_MASK          (255)
#define MAX_PATH_ENTS           (16)
#define CMDLINE_LEN             (2048)
#define CMDLINE_MASK            (2047)
#define CMD_ARGS_MAX            (16)

struct sd_event_point {
    uint32_t  fmt;
    uint32_t  eid;
    uint64_t  ent;
    char name[48];
};

struct cred_xids {
    union {
        uint32_t  xids[8];
        struct {
            uint32_t uid;
            uint32_t gid;
            uint32_t suid;
            uint32_t sgid;
            uint32_t euid;
            uint32_t egid;
            uint32_t fsuid;
            uint32_t fsgid;
        };
    };
};

struct proc_tid {
	pid_t pid;
	pid_t tgid;
	pid_t ppid;
	pid_t pgid;
	struct cred_xids xids;
	__u32 sid;
	__u32 epoch;
	__u64 mntns_id;
	__u64 root_mntns_id;
	__u32 exe_path_len; /* trailing \0 included */
	__u32 pidtree_len; /* trailing \0 included */
	__u32 args_len; /* trailing \0 included */
	__u32 node_len;
	__u64 args_hash;
	__u64 exe_path_hash;
	char comm[TASK_COMM_LEN];
	char node[NODE_NAME_LEN];
	char pidtree[PIDTREE_LEN];
	char exe_path[CMDLINE_LEN];
	char args[CMDLINE_LEN];
};

/* trailing \0 included */
static inline uint64_t hash_murmur_OAAT64(char *s, int len)
{
    uint64_t h = 525201411107845655ull;
    int i;

    for (i = 0; i < CMDLINE_LEN; i++) {
        if (i >= len)
            break;
        h ^= (uint64_t)(s[i]);
        h *= 0x5bd1e9955bd1e995;
        h ^= h >> 47;
    }
    return h;
}

static inline void exe_murmur_OAAT64(struct proc_tid *tid)
{
    uint64_t h = 525201411107845655ull;
    int i;

#if LOOPS_UNROLL
#   pragma unroll
#endif
    for (i = 0; i < CMDLINE_LEN; i++) {
        if (i >= tid->exe_path_len)
            break;
        h ^= (uint64_t)(tid->exe_path[i & CMDLINE_MASK]);
        h *= 0x5bd1e9955bd1e995;
        h ^= h >> 47;
    }
    tid->exe_path_hash = h;
}

static inline void cmd_murmur_OAAT64(struct proc_tid *tid)
{
    uint64_t h = 525201411107845655ull;
    int i;

#if LOOPS_UNROLL
#   pragma unroll
#endif
    for (i = 0; i < CMDLINE_LEN; i++) {
        if (i >= tid->args_len)
            break;
        h ^= (uint64_t)(tid->args[i & CMDLINE_MASK]);
        h *= 0x5bd1e9955bd1e995;
        h ^= h >> 47;
    }
    tid->args_hash = h;
}

/* trusted app to be bypassed */
#define MAX_N_TRUSTED_APPS   (2048)
struct exe_item {
    int   len;  /* length of string, trailing \0 not included */
    __u32 sid;  /* string id, reserved for plugin to locate real path */
    __u64 hash; /* hash value of exe_path or cmdline via exe_murmur_OAAT64 */
    char  name[CMDLINE_LEN];
} __attribute__((packed));

/*
 * bpffs interfaces for global pinning of rodata and perf event ringbuf
 */
#define RODATA_SECTION_MAP "_rodata"      /* .rodata -> _rodata */
#define PERF_BUFFER_EVENT  "events"       /*  events ->  events */
#define TRUSTED_CMDS       "trusted_cmds" /* cmds (with full args) to be bypassed */
#define TRUSTED_EXES       "trusted_exes" /* trusted excutable imgs in full path */

#endif /* __PROCLIST_H */

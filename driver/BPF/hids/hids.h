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
	__u32 exe_path_len;
	__u32 pidtree_len;
	__u32 args_len;
	__u32 node_len;
	char *exe_path;
	char comm[TASK_COMM_LEN];
	char node[NODE_NAME_LEN];
	char pidtree[PIDTREE_LEN];
	char exe_path_dat[CMDLINE_LEN];
	char args[CMDLINE_LEN];
};

/*
 * bpffs interfaces for global pinning of rodata and perf event ringbuf
 */
#define RODATA_SECTION_MAP	"_rodata"
#define PERF_BUFFER_EVENT	"events"

#endif /* __PROCLIST_H */

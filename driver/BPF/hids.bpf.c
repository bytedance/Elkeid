// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)

#include "hids/vmlinux.h"
#include "hids/hids.h"

/*
 * global variables & maps for ebpf-hids
 */

struct proc_tid empty_tid SEC(".rodata") = {};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 10240);
	__type(key, u32);
	__type(value, struct proc_tid);
} g_tid_cache SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
} events SEC(".maps");

#ifndef bpf_printk
#define bpf_printk(fmt, ...)                             \
({                                                       \
    char _fmt[] = fmt;                                   \
    bpf_trace_printk(_fmt, sizeof(_fmt), ##__VA_ARGS__); \
})
#endif

/*
 * global maps for event logging & xfer serializing
 */

#ifndef SD_EVENT_MAX
#define SD_EVENT_MAX    (16384)
#define SD_EVENT_MASK   (SD_EVENT_MAX - 1)
#endif

/* BPF ringbuf map */
// struct {
// 	__uint(type, BPF_MAP_TYPE_RINGBUF);
//	__uint(max_entries, 256 * 1024 /* 256 KB */);
// } g_trace_ring SEC(".maps");

struct sd_percpu_data {
    __u8 data[SD_EVENT_MAX];
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, __u32);
	__type(value, struct sd_percpu_data);
	__uint(max_entries, 2);
} g_percpu_data SEC(".maps");

static void *sd_get_percpu_data(uint32_t size, int id)
{
    if (size > SD_EVENT_MAX)
        return NULL;

    return bpf_map_lookup_elem(&g_percpu_data, &id);
    // return bpf_ringbuf_reserve(&g_trace_ring, SD_EVENT_MAX, 0);
}

static void sd_put_percpu_data(void *ptr)
{
    // bpf ringbuf is not overwritable !!!!!
    // https://lore.kernel.org/bpf/20220906195656.33021-3-flaniel@linux.microsoft.com/T/

    // bpf_ringbuf_discard(ptr, 0);
    // bpf_ringbuf_submit(ptr, 0);
}

static __always_inline void *sd_get_local(uint32_t size)
{
    return sd_get_percpu_data(size, 1);
}

static __always_inline void sd_put_local(void *ptr)
{
    sd_put_percpu_data(ptr);
}

#define __SD_XFER_SE__
#include "hids/xfer.h"

/*
 * general event id definitions
 */

#define IS_ENABLED(x)  (1)

/*
 * unique id of HIDS event (eg: 602 can have 3 event formats, thus 3 ids)
 */

#define SD_XFER_TYPEID_NAME(x)      XFER_TYPEID_##x
#undef  SD_XFER_DEFINE
#define SD_XFER_DEFINE(n, p, x)     SD_XFER_TYPEID_##n,

enum sd_xfer_typeid {
    XFER_TYPEID_null = 0,
#include "hids/kprobe_print.h"
#include "hids/anti_rootkit_print.h"
};

/***************************************
 *
 *  event logging format description
 *
 ***************************************/

/*
 * length of event format description
 */

#define SD_XFER_META_SIZE(...)      ((SD_N_ARGS(__VA_ARGS__) + 3) * sizeof(uint32_t) * 2)
#define SD_XFER_META_XFER(...)      SD_XFER_META_SIZE(__VA_ARGS__)

// prototypes of event elements

#define SD_TYPE_ENTRY_XID(v)    {v}}, {{SD_TYPE_U32}, {4}}

#define SD_TYPE_ENTRY_U8( n, v) {{SD_TYPE_U32}, {4}}
#define SD_TYPE_ENTRY_U16(n, v) {{SD_TYPE_U32}, {4}}
#define SD_TYPE_ENTRY_U32(n, v) {{SD_TYPE_U32}, {4}}
#define SD_TYPE_ENTRY_U64(n, v) {{SD_TYPE_U64}, {8}}
#define SD_TYPE_ENTRY_S8( n, v) {{SD_TYPE_S32}, {4}}
#define SD_TYPE_ENTRY_S16(n, v) {{SD_TYPE_S32}, {4}}
#define SD_TYPE_ENTRY_S32(n, v) {{SD_TYPE_S32}, {4}}
#define SD_TYPE_ENTRY_S64(n, v) {{SD_TYPE_S64}, {8}}

#define SD_TYPE_ENTRY_INT       SD_TYPE_ENTRY_S32
#define SD_TYPE_ENTRY_UINT      SD_TYPE_ENTRY_U32

#if BITS_PER_LONG == 32
# define SD_TYPE_ENTRY_LONG     SD_TYPE_ENTRY_S32
# define SD_TYPE_ENTRY_ULONG    SD_TYPE_ENTRY_U32
#else
# define SD_TYPE_ENTRY_LONG     SD_TYPE_ENTRY_S64
# define SD_TYPE_ENTRY_ULONG    SD_TYPE_ENTRY_U64
#endif

#define SD_TYPE_ENTRY_IP4(n, v) {{SD_TYPE_IP4}, {4}}
#define SD_TYPE_ENTRY_IP6(n, v) {{SD_TYPE_IP6}, {16}}
#define SD_TYPE_ENTRY_XIDS(n, v) {{SD_TYPE_XIDS}, {sizeof(struct sd_xids)}}

#define SD_TYPE_ENTRY_STR(n, v) {{SD_TYPE_STR}, {4}}
#define SD_TYPE_ENTRY_STL(...)  {{SD_TYPE_STR}, {4}}

#define SD_TYPE_POINTER_IP4     SD_TYPE_ENTRY_IP4
#define SD_TYPE_POINTER_IP6     SD_TYPE_ENTRY_IP6
#define SD_TYPE_POINTER_XIDS    SD_TYPE_ENTRY_XIDS
#define SD_TYPE_POINTER_STR     SD_TYPE_ENTRY_STR
#define SD_TYPE_POINTER_STL     SD_TYPE_ENTRY_STL

#define SD_TYPE_I(n, ...)       SD_ENTS_N##n(n, ARG, ENT, SD_TYPE, __VA_ARGS__)
#define SD_TYPE_N(n, ...)       SD_TYPE_I(n, __VA_ARGS__)
#define SD_TYPE_D(...)          SD_TYPE_N(SD_N_ARGS(__VA_ARGS__), __VA_ARGS__)
#define SD_TYPE_XFER(...)       SD_TYPE_D(__VA_ARGS__)

#define SD_XFER_DEFINE_P(n, p, x)                               \
    SD_XFER_DEFINE_E(n, p, x);                                  \
    struct sd_item_ent SD_XFER_PROTO_##n[] SEC(".rodata")= {    \
        {{SD_XFER_META_##x}, {SD_XFER_TYPEID_##n}},             \
        {{sizeof(struct SD_XFER_EVENT_##n)},                    \
        SD_TYPE_##x,                                            \
        {{0}, {0}} };
#undef SD_XFER_DEFINE
#define SD_XFER_DEFINE(n, p, x) SD_XFER_DEFINE_P(n, p, x)

char sd_event_proto_start[32] SEC(".rodata")= {
        SD_EVENT_PROTO_MAGIC
    };
#include "hids/kprobe_print.h"
#include "hids/anti_rootkit_print.h"

#define SD_XFER_PROTO_PAIR_EXP(n)   0, #n
#define SD_XFER_PROTO_PAIR(n)       SD_XFER_PROTO_PAIR_EXP(n)
#define SD_XFER_DEFINE_X(n, p, x)                               \
            { sizeof(SD_XFER_PROTO_##n), SD_XFER_TYPEID_##n,    \
              SD_XFER_PROTO_PAIR(SD_XFER_PROTO_##n) },
#undef SD_XFER_DEFINE
#define SD_XFER_DEFINE(n, p, x) SD_XFER_DEFINE_X(n, p, x)

char sd_event_point_start[16] SEC(".rodata")= {
        SD_EVENT_POINT_MAGIC
    };
struct sd_event_point g_sd_events[] SEC(".rodata") = {
#include "hids/kprobe_print.h"
#include "hids/anti_rootkit_print.h"
        {.fmt = 0, .eid = 0, .ent = 0,}
    };
#define N_SD_TYPES (sizeof(g_sd_events)/sizeof(struct sd_event_point) - 1)

/***************************************
 *
 *  event logging support routines
 *
 ***************************************/

/*
 * event serializing routines
 */

#undef  SD_XFER_DEFINE
#define SD_XFER_DEFINE(n, p, x) SD_XFER_DEFINE_N(n, p, x)

/*
 * support routine
 */
static struct proc_tid *find_current_tid(void);
static struct proc_tid *construct_tid(struct task_struct *, int);

#ifndef BPF_F_CURRENT_CPU
#define BPF_F_CURRENT_CPU 4294967295ULL
#endif
/*
 * must be inline to support > 5 parameters; to save overall stack usage,
 * could call these serializing functions in a __noinline function, such
 * like show_dns_request()
 */
#define SD_XFER_DEFINE_N(n, p, x)                                       \
    static __always_inline int SD_XFER(n, SD_DECL_##p)                  \
    {                                                                   \
        struct proc_tid *__tid = find_current_tid();                    \
                                                                        \
        if (likely(__tid)) {                                            \
            struct SD_XFER_EVENT_##n *__ev;                             \
            SD_ENTS_STRP_##x                                            \
            SD_ENTS_STRS_##x                                            \
            uint32_t __tr_used = 0;                                     \
            uint32_t __tr_size = SD_DATA_##x;                           \
                                                                        \
            /* initialize trace_record */                               \
            __tr_size = ALIGN(sizeof(*__ev) + __tr_size, 4);            \
            if (__tr_size > SD_EVENT_MAX)                               \
                return -7 /* E2BIG */;                                  \
            /* try to allocate swap space */                            \
            __ev = sd_get_percpu_data(__tr_size, 0);                    \
            if (likely(__ev)) {                                         \
                __ev->e_head.size = __tr_size;                          \
                __ev->e_head.eid = SD_XFER_TYPEID_##n;                  \
                __ev->e_meta = sizeof(*__ev);                           \
                SD_ENTS_PACK_##x                                        \
                bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU,  \
                                      __ev, __tr_size & SD_EVENT_MASK); \
                sd_put_percpu_data(__ev);                               \
                return __tr_size;                                       \
            }                                                           \
            return 0;                                                   \
        }                                                               \
        return -2; /* -ENOENT */                                        \
    }

#include "hids/kprobe_print.h"

/*
 * For kernels after 5.2, bounded loops are permitted, which could
 * minimize ebpf instructions count a lot. But for kernels <= 5.2
 * all loops must be unrolled: placing the following constructions
 * before each loop:
 *   #pragma unroll
 *       or
 *   #pragma clang loop unroll(full)
 */

#if LINUX_VERSION_CODE <= KERNEL_VERSION(5, 2, 0)
#define LOOPS_UNROLL    (1)
#else
#define LOOPS_UNROLL    (0)
#endif

/*
 * general support routines for kernel or user memory access
 */

#define LOAD_KERN(e)                                                    \
    ({                                                                  \
        typeof(e) __v;                                                  \
        clang_builtin_memset((void *)&__v, 0, sizeof(__v));             \
        bpf_probe_read((void *)&__v, sizeof(__v), &e);                  \
        __v;                                                            \
    })

#define LOAD_USER(e)                                                    \
    ({                                                                  \
        typeof(e) __v;                                                  \
        clang_builtin_memset((void *)&__v, 0, sizeof(__v));             \
        bpf_probe_read_user((void *)&__v, sizeof(__v), &e);             \
        __v;                                                            \
    })

#define LOAD_KERN_TYPED(t, e)                                           \
    ({                                                                  \
        t __v;                                                          \
        clang_builtin_memset((void *)&__v, 0, sizeof(__v));             \
        bpf_probe_read((void *)&__v, sizeof(__v), &e);                  \
        __v;                                                            \
    })

#define LOAD_USER_TYPED(t, e)                                           \
    ({                                                                  \
        t __v;                                                          \
        clang_builtin_memset((void *)&__v, 0, sizeof(__v));             \
        bpf_probe_read_user((void *)&__v, sizeof(__v), &e);             \
        __v;                                                            \
    })

/* BTF/CORE support switch */
#ifdef  BPF_NO_PRESERVE_ACCESS_INDEX
#undef  HAVE_CORE_SUPPORT
#else
#define HAVE_CORE_SUPPORT
#endif

#ifdef HAVE_CORE_SUPPORT

/*
 * read kernel or user memory space
 *
 * WARNING:
 *   struct.member can only be the last parameter
 *
 * working case:
 *	   inum = READ_KERN(task, nsproxy, mnt_ns, ns.inum);
 *
 * wrong case:
 *     sb = (void *)READ_KERN(task, fs, root.mnt, mnt_sb);
 *
 * must be converted into:
 *      mnt = (void *)READ_KERN(task, fs, root.mnt);
 *      if (mnt)
 *          sb = (void *)READ_KERN(mnt, mnt_sb);
 *
 */
#define READ_KERN(...) BPF_CORE_READ(__VA_ARGS__)
#define READ_USER(...) BPF_CORE_READ(__VA_ARGS__)

/* syscall args */
#define SC_REGS_PARM1(regs) PT_REGS_PARM1_CORE_SYSCALL(regs)
#define SC_REGS_PARM2(regs) PT_REGS_PARM2_CORE_SYSCALL(regs)
#define SC_REGS_PARM3(regs) PT_REGS_PARM3_CORE_SYSCALL(regs)
#define SC_REGS_PARM4(regs) PT_REGS_PARM4_CORE_SYSCALL(regs)
#define SC_REGS_PARM5(regs) PT_REGS_PARM5_CORE_SYSCALL(regs)

/* function call args */
#define FC_REGS_PARM1(regs) PT_REGS_PARM1_CORE(regs)
#define FC_REGS_PARM2(regs) PT_REGS_PARM2_CORE(regs)
#define FC_REGS_PARM3(regs) PT_REGS_PARM3_CORE(regs)
#define FC_REGS_PARM4(regs) PT_REGS_PARM4_CORE(regs)
#define FC_REGS_PARM5(regs) PT_REGS_PARM5_CORE(regs)

/* return code */
#define RC_REGS(regs)       PT_REGS_RC_CORE(regs)

#else

/* variadic macros defintions for kernel / user memory loading */

#define RD_N_ARGS(...) RD_ARGS_C(__VA_ARGS__, RD_ARGS_S)
#define RD_ARGS_C(...) RD_ARGS_N(__VA_ARGS__)
#define RD_ARGS_N(_1, _2, _3, _4, _5, _6, _7, N, ...) N
#define RD_ARGS_S  7, 6, 5, 4, 3, 2, 1, 0

#define READ_OPo(mode, n, s, e, ...)                                    \
    ({                                                                  \
        typeof((s)->e) _p_##e##_##n = LOAD_##mode((s)->e);              \
        READ_##mode##_##n(mode, n, _p_##e##_##n, ##__VA_ARGS__);        \
    })
#define READ_OPe(mode, n, s, e, ...)                                    \
    ({                                                                  \
        typeof((s)->e) _p_##e##_##n = LOAD_##mode((s)->e);              \
        READ_##mode##_##n(mode, n, _p_##e##_##n, ##__VA_ARGS__);        \
    })

#define READ_KERN_7(mode, n, ...)  READ_OPo(mode, 6, ## __VA_ARGS__)
#define READ_KERN_6(mode, n, ...)  READ_OPe(mode, 5, ## __VA_ARGS__)
#define READ_KERN_5(mode, n, ...)  READ_OPo(mode, 4, ## __VA_ARGS__)
#define READ_KERN_4(mode, n, ...)  READ_OPe(mode, 3, ## __VA_ARGS__)
#define READ_KERN_3(mode, n, ...)  READ_OPo(mode, 2, ## __VA_ARGS__)
#define READ_KERN_2(mode, n, s, e) LOAD_KERN((s)->e)
#define READ_KERN_1(mode, n, e)    LOAD_KERN(e)

#define READ_USER_7(mode, n, ...)  READ_OPo(mode, 6, ## __VA_ARGS__)
#define READ_USER_6(mode, n, ...)  READ_OPe(mode, 5, ## __VA_ARGS__)
#define READ_USER_5(mode, n, ...)  READ_OPo(mode, 4, ## __VA_ARGS__)
#define READ_USER_4(mode, n, ...)  READ_OPe(mode, 3, ## __VA_ARGS__)
#define READ_USER_3(mode, n, ...)  READ_OPo(mode, 2, ## __VA_ARGS__)
#define READ_USER_2(mode, n, s, e) LOAD_USER((s)->e)
#define READ_USER_1(mode, n, e)    LOAD_USER(e)

#define READ_OPX(mode, n, ...) READ_##mode##_##n(mode, n, __VA_ARGS__)
#define READ_OPx(mode, n, ...) READ_OPX(mode, n, __VA_ARGS__)
#define READ_KERN(...)  READ_OPx(KERN, RD_N_ARGS(__VA_ARGS__), __VA_ARGS__)
#define READ_USER(...)  READ_OPx(USER, RD_N_ARGS(__VA_ARGS__), __VA_ARGS__)

/* syscall args */
#define SC_REGS_PARM1(regs) LOAD_KERN(PT_REGS_PARM1_SYSCALL(regs))
#define SC_REGS_PARM2(regs) LOAD_KERN(PT_REGS_PARM2_SYSCALL(regs))
#define SC_REGS_PARM3(regs) LOAD_KERN(PT_REGS_PARM3_SYSCALL(regs))
#define SC_REGS_PARM4(regs) LOAD_KERN(PT_REGS_PARM4_SYSCALL(regs))
#define SC_REGS_PARM5(regs) LOAD_KERN(PT_REGS_PARM5_SYSCALL(regs))

/* function call args */
#define FC_REGS_PARM1(regs) LOAD_KERN(PT_REGS_PARM1(regs))
#define FC_REGS_PARM2(regs) LOAD_KERN(PT_REGS_PARM2(regs))
#define FC_REGS_PARM3(regs) LOAD_KERN(PT_REGS_PARM3(regs))
#define FC_REGS_PARM4(regs) LOAD_KERN(PT_REGS_PARM4(regs))
#define FC_REGS_PARM5(regs) LOAD_KERN(PT_REGS_PARM5(regs))

/* return code */
#define RC_REGS(regs)       PT_REGS_RC(regs)

#endif

/*
 * query the file struct represented by fd for specified task
 */
 #define FD_MAX (65536)
static __noinline struct file *fget_raw(struct task_struct *task, int nr)
{
    /* valid fd range: [0,  files_fdtable(task->files)->max_fds) */
    if (nr < 0 || nr >= FD_MAX)
        return NULL;

    struct files_struct *files = (void *)READ_KERN(task, files);
    if (files == NULL)
        return NULL;
    struct fdtable *fdt = (struct fdtable *)READ_KERN(files, fdt);
    if (fdt == NULL)
        return NULL;
    if (nr >= (int)READ_KERN(fdt, max_fds))
        return NULL;
    struct file **fds = (struct file **)READ_KERN(fdt, fd);
    if (fds == NULL)
        return NULL;
    struct file *file = (struct file *)LOAD_KERN(fds[nr]);
    if (file == NULL)
        return NULL;

    return file;
}

static inline struct socket *SOCKET_I(struct inode *inode)
{
	return &container_of(inode, struct socket_alloc, vfs_inode)->socket;
}

#define S_IFMT  00170000
#define S_IFSOCK 0140000
#define S_IFLNK	 0120000
#define S_IFREG  0100000
#define S_IFBLK  0060000
#define S_IFDIR  0040000
#define S_IFCHR  0020000
#define S_IFIFO  0010000
#define S_ISUID  0004000
#define S_ISGID  0002000
#define S_ISVTX  0001000

static __noinline struct socket *socket_from_file(struct file *file)
{
    struct inode *inode;
    struct socket *sock = NULL;
    umode_t mode;

    inode = (struct inode *)READ_KERN(file, f_inode);
    if (!inode)
        goto errorout;

    mode = (umode_t)READ_KERN(inode, i_mode);
    if (((mode) & S_IFMT) == S_IFSOCK)
        sock = SOCKET_I(inode);

errorout:
    return sock;
}

static __noinline struct sock *sock_from_file(struct file *file)
{
    struct inode *inode;
    struct sock *sk = NULL;
    umode_t mode;

    inode = (struct inode *)READ_KERN(file, f_inode);
    if (!inode)
        goto errorout;

    mode = (umode_t)READ_KERN(inode, i_mode);
    if (((mode) & S_IFMT) == S_IFSOCK) {
        struct socket *sock = SOCKET_I(inode);
        if (sock)
            sk = (struct sock *)READ_KERN(sock, sk);
    }

errorout:
    return sk;
}

static __noinline struct sock *sockfd_lookup(struct task_struct *task, long fd)
{
    struct file *file;

    file = fget_raw(task, fd);
    if (!file)
        return NULL;

    return sock_from_file(file);
}

static __noinline struct sock *find_sock_internal(struct file **fds, int nr, int max)
{
    struct sock *sk = NULL;

    if (nr >= max)
        goto out;

    struct file *file = (struct file *)LOAD_KERN(fds[nr]);
    if (!file)
        goto out;

    struct socket *sock = socket_from_file(file);
    if (!sock)
        goto out;

    socket_state state = READ_KERN(sock, state);
    if (state == SS_CONNECTING || state == SS_CONNECTED ||
        state == SS_DISCONNECTING)
        sk = READ_KERN(sock, sk);

out:
    return sk;
}

static __noinline struct sock *find_sockfd(struct task_struct *task)
{
    struct sock *sk;
    int nr, max;

    struct files_struct *files = (void *)READ_KERN(task, files);
    if (files == NULL)
        return NULL;
    struct fdtable *fdt = (struct fdtable *)READ_KERN(files, fdt);
    if (fdt == NULL)
        return NULL;
    max = READ_KERN(fdt, max_fds);
    struct file **fds = (struct file **)READ_KERN(fdt, fd);
    if (fds == NULL)
        return NULL;

#if LOOPS_UNROLL
#   pragma unroll
#endif
    for (nr = 0; nr < 16; nr++) { /* EXECVE_GET_SOCK_FD_LIMIT */
        sk = find_sock_internal(fds, nr, max);
        if (sk)
            break;
    }

    return sk;
}

static __noinline struct sock *process_socket(struct task_struct *task, pid_t *pid)
{
    struct task_struct *parent;
    struct sock *sk;

    /* try find sockfd for current (given) task */
    sk = find_sockfd(task);
    if (sk) {
        *pid = READ_KERN(task, tgid);
        goto out;
    }
    /* process for parent process of current */
    parent = (struct task_struct *)READ_KERN(task, real_parent);
    if (!parent || parent == task)
        goto out;
    sk = find_sockfd(parent);
    if (sk) {
        *pid = READ_KERN(parent, tgid);
        goto out;
    }
    /* process grandfather process */
    task = parent;
    parent = (struct task_struct *)READ_KERN(task, real_parent);
    if (!parent || parent == task)
        goto out;
    sk = find_sockfd(parent);
    if (sk) {
        *pid = READ_KERN(parent, tgid);
        goto out;
    }

out:
    return sk;
}

static __noinline u16 swap16(u16 port)
{
    return ((port & 0xFF) << 8) | ((port & 0xFF00) >> 8);
}

/* issues with sk_protocol, due to different defs of struct sock */
#if 0
struct sock___v55 {
        /* ... */
        __u32 sk_txhash;
        unsigned int __sk_flags_offset[0];
        unsigned int sk_padding: 1;
        unsigned int sk_kern_sock: 1;
        unsigned int sk_no_check_tx: 1;
        unsigned int sk_no_check_rx: 1;
        unsigned int sk_userlocks: 4;
        unsigned int sk_protocol: 8;
        unsigned int sk_type: 16;
        u16 sk_gso_max_segs;
} __attribute__((preserve_access_index));

struct sock___v56 {
    /* ... */
    __u32			sk_txhash;

	/*
	 * Because of non atomicity rules, all
	 * changes are protected by socket lock.
	 */
	u8			sk_padding : 1,
				sk_kern_sock : 1,
				sk_no_check_tx : 1,
				sk_no_check_rx : 1,
				sk_userlocks : 4;
	u8			sk_pacing_shift;
	u16			sk_type;
	u16			sk_protocol;
	u16			sk_gso_max_segs;
} __attribute__((preserve_access_index));
#endif

/* query protocol of user sock connection: udp (dgram) or tcp ? */
static __noinline int sock_prot(struct sock *sk)
{
#ifdef HAVE_CORE_SUPPORT

    unsigned long long prot = 0;
    unsigned int offset = __builtin_preserve_field_info(sk->sk_protocol, BPF_FIELD_BYTE_OFFSET);
    unsigned int size = __builtin_preserve_field_info(sk->sk_protocol, BPF_FIELD_BYTE_SIZE);

    bpf_probe_read(&prot, size, (void *)sk + offset);
    prot <<= __builtin_preserve_field_info(sk->sk_protocol, BPF_FIELD_LSHIFT_U64);
    prot >>= __builtin_preserve_field_info(sk->sk_protocol, BPF_FIELD_RSHIFT_U64);
    return (int)prot;

#else

# if LINUX_VERSION_CODE < KERNEL_VERSION(5, 6, 0)
    int prot;
    prot = READ_KERN(sk, __sk_flags_offset[0]);
    return (prot & 0xFF00) >> 8;
# else
    return READ_KERN(sk, sk_protocol);
# endif

#endif
}

/* Supported address families. */
#define AF_UNSPEC	0
#define AF_UNIX		1	/* Unix domain sockets 		*/
#define AF_LOCAL	1	/* POSIX name for AF_UNIX	*/
#define AF_INET		2	/* Internet IP Protocol 	*/
#define AF_AX25		3	/* Amateur Radio AX.25 		*/
#define AF_IPX		4	/* Novell IPX 			*/
#define AF_APPLETALK	5	/* AppleTalk DDP 		*/
#define AF_NETROM	6	/* Amateur Radio NET/ROM 	*/
#define AF_BRIDGE	7	/* Multiprotocol bridge 	*/
#define AF_ATMPVC	8	/* ATM PVCs			*/
#define AF_X25		9	/* Reserved for X.25 project 	*/
#define AF_INET6	10	/* IP version 6			*/

static __noinline int sock_family(struct sock *sk)
{
    return READ_KERN(sk, __sk_common.skc_family);
}

static __noinline int query_ipv4(struct sock *sk,
                      __be32 *sip, int *sport,
                      __be32 *dip, int *dport)
{
    struct inet_sock *inet = (void *)sk;
    int port;

    if (!inet)
        return -22 /*-EINVAL*/;

    if (sock_family(sk) != AF_INET)
        return -22 /*-EINVAL*/;

    /* read sip & sport */
    *sip = READ_KERN(inet, sk.__sk_common.skc_rcv_saddr);
    if (!*sip)
        *sip = READ_KERN(inet, inet_saddr);
    port = READ_KERN(inet, inet_sport);
    *sport = swap16(port);

    /* read dip & dport */
    *dip = READ_KERN(inet, sk.__sk_common.skc_daddr);
    port = READ_KERN(inet, sk.__sk_common.skc_dport);
    *dport = swap16(port);

    return 0;
}

static bool ipv6_addr_any(const struct in6_addr *a)
{
#if defined(CONFIG_HAVE_EFFICIENT_UNALIGNED_ACCESS) && BITS_PER_LONG == 64
	const unsigned long *ul = (const unsigned long *)a;

	return (ul[0] | ul[1]) == 0UL;
#else
	return (a->in6_u.u6_addr32[0] | a->in6_u.u6_addr32[1] |
		a->in6_u.u6_addr32[2] | a->in6_u.u6_addr32[3]) == 0;
#endif
}

static __noinline int query_ipv6(struct sock *sk,
                      struct in6_addr *sip, int *sport,
                      struct in6_addr *dip, int *dport)
{
    struct inet_sock *inet = (void *)sk;
    struct ipv6_pinfo *inet6;
    int port;

    if (!inet)
        return -22 /*-EINVAL*/;
    inet6 = (void *)READ_KERN(inet, pinet6);

    if (sock_family(sk) != AF_INET6)
        return -22 /*-EINVAL*/;

    /* read sip & sport */
    *sip = READ_KERN(inet, sk.__sk_common.skc_v6_rcv_saddr);
    if (ipv6_addr_any(sip) && inet6)
        *sip = READ_KERN(inet6, saddr);
    port = READ_KERN(inet, inet_sport);
    *sport = swap16(port);

    /* read dip & dport */
    *dip = READ_KERN(inet, sk.__sk_common.skc_v6_daddr);
    port = READ_KERN(inet, sk.__sk_common.skc_dport);
    *dport = swap16(port);

    return 0;
}

/*
 * dns answer record processing
 */

/* marked as noinline to save 253 times of expansion in query_dns_record() */
static __noinline int process_domain_name(char *data, char *name, int *flag, int i)
{
    char rc = *(data + 12 + i);
    int v = *flag;

    /* got the end of the domain name */
    if (0 == rc)
        return 0;

    /* continue domain name processing */
    if (v == 0) {
        v = rc;
        name[i - 1] = 46; /* 0x2e: '.' */
    } else {
        name[i - 1] = rc;
        v = v - 1;
    }

    *flag = v;
    return 1;
}

static __noinline int query_dns_record(char *data, char *name, int *type)
{
    int i, flag;

    flag = *(data + 12);
    /*
     * TIPS:
     *   bounded loop supported for kernels after 5.2
     *
     * WARNING:
     *   loop count limited to 150 rather than 253, otherwise it'll
     *   violate ebpf limitation of 1M instructions
     */
#if LOOPS_UNROLL
#   define DNS_N_LOOPS  (75) /* workaround for ebpf insts limit */
#   pragma unroll
#else
# ifdef __NATIVE_EBPF__
#   define DNS_N_LOOPS  (150)
# else
#   define DNS_N_LOOPS  (75)
# endif
#
#endif
    /* maximum characters of a domain name: 253 */
    for (i = 1; i < DNS_N_LOOPS; i++) {
        if (!process_domain_name(data, name, &flag, i))
            break;
    }

    // dns queries type: https://en.wikipedia.org/wiki/List_of_DNS_record_types
    *type = swap16(*((uint16_t *)(data + i + 13)));
    return i;
}

struct smith_ip_addr {

    int sa_family;
    int sport;
    int dport;

    union {
        struct {
            __be32 dip4;
            __be32 sip4;
        };
        struct {
            struct in6_addr dip6;
            struct in6_addr sip6;
        };
    };
};

struct var_dns {
        char data[512];
        char name[256];
        struct sock *sk;
        struct smith_ip_addr ip;
        int opcode, rcode, type;
};

static int dns_query_ip(struct var_dns *dns)
{
    dns->ip.sa_family = sock_family(dns->sk);
    if (dns->ip.sa_family == AF_INET6 /* ipv6 */) {
        return query_ipv6(dns->sk, &dns->ip.sip6, &dns->ip.sport, &dns->ip.dip6, &dns->ip.dport);
    } else if (dns->ip.sa_family == AF_INET /* ipv4 */) {
        return query_ipv4(dns->sk, &dns->ip.sip4, &dns->ip.sport, &dns->ip.dip4, &dns->ip.dport);
    }

    return -2;
}

#define DNS_RECORD_MASK (511)
/* mark as noinline to minimize codes generations, to be called twice (by 2 different callers) */
static __noinline int process_dns_record(struct var_dns *dns, char *data, int len)
{
    int rc = 0;

    if (dns_query_ip(dns))
        goto out;

    /* we only care port 53 or 5353 */
    if (dns->ip.sport != 53 && dns->ip.sport != 5353 &&
        dns->ip.dport != 53 && dns->ip.dport != 5353)
        goto out;

    /* domain name stored in the heading 511 bytes */
    if (len > DNS_RECORD_MASK)
        len = DNS_RECORD_MASK;

    rc = bpf_probe_read_user(dns->data, len & DNS_RECORD_MASK, data);
    if (rc)
        goto out;
    dns->data[DNS_RECORD_MASK] = 0;
    if (!(dns->data[2] & 0x80)) /* query result: failed ? */
        goto out;

    /* query dns info from received data */
    dns->opcode = (dns->data[2] >> 3) & 0x0f;
    dns->rcode = dns->data[3] & 0x0f;
    rc = query_dns_record(dns->data, dns->name, &dns->type);

out:
    return rc;
}

/* must be noinline to release stack usage after returning to caller */
static __noinline void show_dns_request(void *ctx, struct var_dns *dns, int len)
{
    if (dns->ip.sa_family == AF_INET6 /* ipv6 */) {
        dns6_print(ctx, &dns->ip.dip6, dns->ip.dport, &dns->ip.dip6, dns->ip.sport, 
                   dns->opcode, dns->rcode, dns->name, len, dns->type);
    } else if (dns->ip.sa_family == AF_INET /* ipv4 */) {
        dns4_print(ctx, dns->ip.dip4, dns->ip.dport, dns->ip.sip4, dns->ip.sport,
                   dns->opcode, dns->rcode, dns->name, len, dns->type);
    }
}

static __noinline int process_dns_request(void *ctx, struct sock *sk, char *data, int len)
{
    struct var_dns *dns = NULL;
    int rc = 0;

    /* data is too short to analyze ? */
    if (len < 20)
        goto out;

    /* ignore if socket is NOT udp */
    if (IPPROTO_UDP != sock_prot(sk))
        goto out;

    dns = sd_get_local(sizeof(*dns));
    if (!dns)
        goto out;
    dns->sk = sk;

    rc = process_dns_record(dns, data, len);
    if (rc <= 0)
        goto out;
    show_dns_request(ctx, dns, rc);

out:
    if (dns)
        sd_put_local(dns);
    return rc;
}

/*
 * query original cmdline or executing arguments
 */
static __noinline unsigned int append_string(char *s, int len, int n, int max, void *msg)
{
    unsigned int rc;

    if (len >= max)
        return 0;
    if (len + n > max)
        n = max - len;
    rc = bpf_probe_read(&s[len & SD_STR_MASK], n & SD_STR_MASK, msg);
    if (rc)
        return 0;
    if (len)
        s[(len - 1) & SD_STR_MASK] = 0x20;
    return n;
}

static __noinline unsigned int read_args(struct proc_tid *tid, struct task_struct *task)
{
    struct var_swap {
        char skip[SD_EVENT_MAX - 2 * SD_STR_MAX];
        char args[SD_STR_MAX];
        char swap[SD_STR_MAX];
    } *swap;

    swap = sd_get_local(sizeof(*swap));
    if (!swap)
        return 0;

    unsigned long args, arge;
    unsigned int larg, rc, len = 0;

    args = READ_KERN(task, mm, arg_start);
    arge = READ_KERN(task, mm, arg_end);
    larg = (unsigned int)(arge - args);

    if (!args || !larg)
        goto out;

    if (larg >= SD_STR_MAX)
        larg = SD_STR_MASK;

#if LOOPS_UNROLL
#   pragma unroll
#endif
    for (int i = 0; i < CMD_ARGS_MAX; i++) {
        rc = bpf_probe_read_str(swap->swap, SD_STR_MASK, (void *)(args + len));
        if (rc <= 0)
            break;
        rc = append_string(swap->args, len, rc, larg, swap->swap);
        if (!rc)
            break;
        len += rc;
    }
    len = bpf_probe_read_str(tid->args, len & CMDLINE_MASK, swap->args);

out:
    sd_put_local(swap);
    return len;
}

static __noinline void construct_xids(struct task_struct *task, struct cred_xids *xids)
{
    xids->uid = READ_KERN(task, real_cred, uid.val);
    xids->gid = READ_KERN(task, real_cred, gid.val);

    xids->suid = READ_KERN(task, real_cred, suid.val);
    xids->sgid = READ_KERN(task, real_cred, sgid.val);

    xids->euid = READ_KERN(task, real_cred, euid.val);
    xids->egid = READ_KERN(task, real_cred, egid.val);

    xids->fsuid = READ_KERN(task, real_cred, fsuid.val);
    xids->fsgid = READ_KERN(task, real_cred, fsgid.val);
}

static __noinline int validate_xids(struct cred_xids *old, struct cred_xids *new, uint32_t skip)
{
    uint32_t bit;

#if LOOPS_UNROLL
#   pragma unroll
#endif
    for (bit = 0; bit < 8; bit++) {
        if (!(skip & (1 << bit)) && old->xids[bit] &&
            (old->xids[bit] != new->xids[bit]))
            return (bit + 1);
    }

    return 0;
}

static __noinline void privilege_escalation(void *ctx, struct task_struct *task, uint32_t skip)
{
    struct proc_tid *tid;
    struct cred_xids ids;
    pid_t tgid;

    /* locate tid cache in map: g_tid_cache */
    tgid = READ_KERN(task, tgid);
    tid = bpf_map_lookup_elem(&g_tid_cache, &tgid);
    if (!tid)
        return;

    construct_xids(task, &ids);
    if (validate_xids(&tid->xids, &ids, skip))
            privilege_escalation_print(ctx, tgid, &tid->xids, &ids);

    tid->xids = ids;
}

static __noinline int prepend_path(char *path, uint32_t *len, char *entry, int num)
{
    /* trailing \0 also counted in len */
    if (!num)
        return 0;
    if (*len + num > SD_STR_MAX)
        return -36; /* -ENAMETOOLONG */

    bpf_probe_read(&path[(SD_STR_MAX - *len - num) & SD_STR_MASK],
                   num & (PATH_NAME_LEN - 1), entry);
    *len += num;
    return 0;
}

static __noinline int prepend_entry(char *path, uint32_t *len, char *swap, struct dentry *de)
{
    char *name;
    int rc;

    if (!de)
        return -2;
    name = (char *)READ_KERN(de, d_name.name);
    if (!name)
        return -2;
    /* trailing \0 counted in rc */
    rc = bpf_probe_read_str(&swap[4], PATH_NAME_LEN, name);
    if (rc <= 0)
        return -2;
    if (swap[4] != '/')
        rc = prepend_path(path, len, &swap[3], rc);
    else if (rc > 2) /* ignore toppest '/' */
        rc = prepend_path(path, len, &swap[4], rc - 1);
    return rc;
}

static __noinline struct dentry *d_parent(struct dentry *de)
{
    struct dentry *next = (void *)READ_KERN(de, d_parent);
    if (next == de)
        return NULL;
    return next;
}

static __always_inline struct mount *real_mount(struct vfsmount *mnt)
{
    return container_of(mnt, struct mount, mnt);
}

/* length of path: SD_STR_MAX; length of swap: PATH_NAME_LEN + 4 */
static __noinline char * d_path(char *data, char *swap, struct path *path, uint32_t *sz)
{
    struct dentry *dentry = path->dentry;
    struct vfsmount *vfsmnt = path->mnt;
    struct mount *mount = real_mount(vfsmnt); // get mount by vfsmnt
    struct mount *mnt_parent;
    uint32_t len = 1;

    mnt_parent = READ_KERN(mount, mnt_parent);
    data[SD_STR_MASK] = 0;
    swap[3] = '/';

#if LOOPS_UNROLL
#   pragma unroll
#endif
    for (int i = 0; i < MAX_PATH_ENTS; i++) {
        struct dentry *root = READ_KERN(vfsmnt, mnt_root);
        struct dentry *parent = READ_KERN(dentry, d_parent);
        // 1. dentry == d_parent means we reach the dentry root
        // 2. dentry == mnt_root means we reach the mount root
        if (dentry == root || dentry == parent) {
            // We reached root, but not mount root - escaped?
            if (dentry != root)
                break;

            // dentry == mnt_root: we get to local mount root, but not the
            // global root, so continue with mnt_mountpoint (upper layer)
            if (mount != mnt_parent) {
                dentry = (void *)READ_KERN(mount, mnt_mountpoint);
                mount = (void *)READ_KERN(mount, mnt_parent);
                mnt_parent = (void *)READ_KERN(mount, mnt_parent);
                vfsmnt = (void *)&mount->mnt;
                continue;
            }
            // dentry == mnt_root && mnt_p == mnt_parent_p: global root
            break;
        }
        if (prepend_entry(data, &len, swap, dentry))
            break;
        dentry = parent;
    }

    *sz = len;
    return &data[(SD_STR_MAX - len) & SD_STR_MASK];
}

/* length of path: SD_STR_MAX; length of swap: PATH_NAME_LEN + 4 */
static __noinline char * dentry_path(char *path, char *swap, struct dentry *de, uint32_t *sz)
{
    uint32_t len = 1;

    path[SD_STR_MASK] = 0;
    swap[3] = '/';

#if LOOPS_UNROLL
#   pragma unroll
#endif
    for (int i = 0; i < MAX_PATH_ENTS; i++) {
        if (prepend_entry(path, &len, swap, de))
            break;
        de = d_parent(de);
    }

    *sz = len;
    return &path[(SD_STR_MAX - len) & SD_STR_MASK];
}

static __always_inline int construct_exe_path(struct task_struct *task, struct proc_tid *tid)
{
    struct var_swap {
        char skip[SD_EVENT_MAX - SD_STR_MAX - PATH_NAME_LEN - 4];
        char path[SD_STR_MAX];
        char swap[PATH_NAME_LEN + 4];
    } *swap;

    swap = sd_get_local(sizeof(*swap));
    if (!swap)
        return -4;
    struct path exe;
    exe.mnt = READ_KERN(task, mm, exe_file, f_path.mnt);
    exe.dentry = READ_KERN(task, mm, exe_file, f_path.dentry);
    tid->exe_path = d_path(tid->exe_path_dat, swap->swap,
                           &exe, &tid->exe_path_len);

    sd_put_local(swap);
    return 0;
}

static __noinline int do_u32toa(uint32_t v, char *s, int l)
{
    char t[16] = {0};
    int i;

#if LOOPS_UNROLL
#   pragma unroll
#endif
    for (i = 0; i < 12; i++) {
        t[12 - i] = 0x30 + (v % 10);
        v = v / 10;
        if (!v)
            break;
    }
    if (i + 1 > l)
        return 0;
    bpf_probe_read(s, (i + 1) & 15, &t[(12 - i) & 15]);
    return (i + 1);
}

static __noinline int prepend_pid_tree(struct task_struct *task, struct proc_tid *tid)
{
    char *comm;
    pid_t pid;
    int rc = 0, len, last;

    pid = READ_KERN(task, pid);
    if (!pid)
        return 0;

    len = last = tid->pidtree_len;
    if (len) {
        tid->pidtree[len & PIDTREE_MASK] = '<';
        len = len + 1;
    }
    rc = do_u32toa(pid, &tid->pidtree[len & PIDTREE_MASK],
                   PIDTREE_LEN - len);
    if (!rc)
        goto out;
    len += rc;
    tid->pidtree[len & PIDTREE_MASK] = '.';
    len = len + 1;
    comm = READ_KERN(task, comm);
    if (!comm)
        goto out;
    rc = bpf_probe_read_str(&tid->pidtree[len & PIDTREE_MASK],
                             (PIDTREE_LEN - len) & PIDTREE_MASK,
                             comm);
    if (rc <= 1)
        goto out;
    if (rc > TASK_COMM_LEN)
        rc = TASK_COMM_LEN;
    len += rc - 1;

    tid->pidtree[len & PIDTREE_MASK] = 0;
    tid->pidtree_len = len;
    return len;

out:
    tid->pidtree[last & PIDTREE_MASK] = 0;
    return 0;
}

static __always_inline int construct_pid_tree(struct task_struct *task, struct proc_tid *tid)
{
    struct task_struct *parent;
    int i;

    tid->pidtree_len = 0;

#if LOOPS_UNROLL
#   pragma unroll
#endif
    for (i = 0; i < 12; i++) {
        if (!prepend_pid_tree(task, tid))
            break;
        parent = READ_KERN(task, real_parent);
        if (!parent || parent == task)
            break;
        task = parent;
    }

    /* trailing \0 added */
    if (tid->pidtree_len)
        tid->pidtree_len++;
    return (int)tid->pidtree_len;
}

static __noinline void refresh_tid(struct task_struct *task, struct proc_tid *tid)
{
    construct_exe_path(task, tid); /* WARNING: will destroy local map: sd_get_local */

    bpf_get_current_comm(tid->comm, sizeof(tid->comm));

    /* update pidtree */
    construct_pid_tree(task, tid);

    /* build cmdline */
    tid->args_len = read_args(tid, task);

    /* save owner's credentials */
    construct_xids(task, &tid->xids);
}

static __noinline struct task_struct *query_systemd(struct task_struct *task)
{
#if LOOPS_UNROLL
#   pragma unroll
#endif
    for (int i = 0; i < 32; i++) {
        if (READ_KERN(task, pid) == 1)
            return task;
        task = READ_KERN(task, real_parent);
        if (!task)
            break;
    }

    return NULL;
}

static __noinline __u64 query_mntns_id(struct task_struct *task)
{
	struct super_block *sb = NULL;
    struct vfsmount *mnt;
	__u64 mntns_id;
	unsigned int inum;

	inum = READ_KERN(task, nsproxy, mnt_ns, ns.inum);
    mnt = (void *)READ_KERN(task, fs, root.mnt);
    if (mnt)
	    sb = (void *)READ_KERN(mnt, mnt_sb);

	mntns_id = sb ? (unsigned long)sb : -1;
	mntns_id = (~mntns_id) << 16; /* canonical address */
	mntns_id = (mntns_id & 0xFFFFFFFF00000000ULL) | inum;

	return mntns_id;
}

static __noinline __u64 query_root_mntns_id(struct task_struct *task)
{
    struct task_struct *systemd = query_systemd(task);

    if (!systemd)
        return query_mntns_id(task);

    return query_mntns_id(systemd);
}

static __noinline pid_t query_sid(struct task_struct *task)
{
    struct pid_namespace *ns;
    struct pid *pid;
    pid_t sid = READ_KERN(task, pid);
    unsigned int level;

    level = READ_KERN(task, thread_pid, level);
    ns = (void *)READ_KERN(task, thread_pid, numbers[level].ns);
    pid = (void *)READ_KERN(task, signal, pids[PIDTYPE_SID]);
    if (!ns || !pid)
        goto out;

    level = READ_KERN(ns, level);
    if (level <= READ_KERN(pid, level)) {
        struct pid_namespace *pid_ns = READ_KERN(pid, numbers[level].ns);
        if (pid_ns == ns)
            sid = READ_KERN(pid, numbers[level].nr);
    }

out:
    return sid;
}

static __noinline pid_t query_pgid(struct task_struct *task)
{
    struct pid_namespace *ns;
    struct pid *pid;
    pid_t pgid = READ_KERN(task, tgid);
    unsigned int level;

    level = READ_KERN(task, thread_pid, level);
    ns = (void *)READ_KERN(task, thread_pid, numbers[level].ns);
    pid = (void *)READ_KERN(task, signal, pids[PIDTYPE_PGID]);
    level = READ_KERN(ns, level);
    if (level <= READ_KERN(pid, level)) {
        struct pid_namespace *pid_ns = READ_KERN(pid, numbers[level].ns);
        if (pid_ns == ns)
            pgid = READ_KERN(pid, numbers[level].nr);
    }
    return pgid;
}

static __noinline pid_t query_epoch(struct task_struct *task)
{
    struct task_struct *parent = READ_KERN(task, real_parent);

    if (!parent)
        parent = task;

    return query_sid(parent);
}

#ifndef BPF_NOEXIST
#define BPF_NOEXIST  1
#endif

#define PF_KTHREAD 0x00200000 /* kernel thread */
static __noinline struct proc_tid *construct_tid(struct task_struct *task, int fork)
{
    struct proc_tid *tid;
    pid_t tgid, pid;

    /* bypass all kernel threads */
    if (READ_KERN(task, flags) & PF_KTHREAD)
        return NULL;

    pid = READ_KERN(task, pid);
    tgid= READ_KERN(task, tgid);

    /* reserve cache from g_tid_cache for this task */
    if (bpf_map_update_elem(&g_tid_cache, &tgid, &empty_tid, BPF_NOEXIST))
        return NULL;

    /* locate tid cache in map: g_tid_cache */
    tid = bpf_map_lookup_elem(&g_tid_cache, &tgid);
    if (!tid)
        return NULL;

    tid->pid = pid;
    tid->tgid = tgid;
    tid->ppid = READ_KERN(task, real_parent, tgid);
    tid->pgid = query_pgid(task);

    char *nodename = READ_KERN(task, nsproxy, uts_ns, name.nodename);
    if (nodename) {
        tid->node_len = bpf_probe_read_str(tid->node, NODE_NAME_LEN,
                                           nodename);
    } else {
        clang_builtin_memcpy(tid->node, "<host>", 7);
        tid->node_len = 7;
    }

    /* construct img/pidtree/cmdline/credinfo for tid cache */
    refresh_tid(task, tid);

    /* query mntns id */
    tid->mntns_id = query_mntns_id(task);
    tid->root_mntns_id = query_root_mntns_id(task);

    /* query sid/epoch of current task */
    tid->sid = query_sid(task);
    if (fork)
        tid->epoch = query_sid(task);
    else
        tid->epoch = query_epoch(task);

    return tid;
}

static __noinline struct proc_tid *find_current_tid(void)
{
    struct task_struct *task;
    struct proc_tid *tid;
    pid_t tgid;

    task = (struct task_struct *)bpf_get_current_task();
    tgid = READ_KERN(task, tgid);

    /* tid cache was already built for current task */
    tid = bpf_map_lookup_elem(&g_tid_cache, &tgid);
    return tid;
}

static __noinline int sysret_ptrace(void *ctx, long request, long pid, void *addr, long ret)
{
    struct var_ptrace {
        char data[PATH_NAME_LEN];
    } *ptrace;
    int rc;

    if (request != 1 /* PTRACE_POKETEXT */ &&
        request != 2 /* PTRACE_POKEDATA */)
        return 0;

    ptrace = sd_get_local(PATH_NAME_LEN);
    if (!ptrace)
        return 0;

    rc = bpf_probe_read_str(ptrace->data, PATH_NAME_LEN, addr);
    if (rc > 0)
        ptrace_print(ctx, request, pid, addr, ptrace->data, rc);

    sd_put_local(ptrace);
    return 0;
}

struct mount_parms {
    char *dev;
    char *dir;
    char *type;
    void *data;
    long flags;
};

static __noinline int sysret_mount(void *ctx, struct mount_parms *args, long ret)
{
    struct var_mount {
        char dev[PATH_NAME_LEN];
        char dir[PATH_NAME_LEN];
        char fsid[32];
        char type[32];
        char data[PATH_NAME_LEN];
        int dev_len, dir_len, type_len, data_len;
    } *mount;
    int rc;

    mount = sd_get_local(sizeof(*mount));
    if (!mount)
        return 0;

    rc = bpf_probe_read_str(mount->dev, PATH_NAME_LEN, args->dev);
    mount->dev_len = rc > 0 ? rc : 0;

    rc = bpf_probe_read_str(mount->dir, PATH_NAME_LEN, args->dir);
    mount->dir_len = rc > 0 ? rc : 0;

    rc = bpf_probe_read_str(mount->type, 32, args->type);
    mount->type_len = rc > 0 ? rc : 0;

    rc = bpf_probe_read_str(mount->data, PATH_NAME_LEN, args->data);
    mount->data_len = rc > 0 ? rc : 0;

    mount_print(ctx, mount->dev, mount->dev_len, mount->dir,
                mount->dir_len, NULL /* fsid */, mount->type,
                mount->type_len, args->flags, mount->data,
                mount->data_len);

    sd_put_local(mount);
    return 0;
}

/* create new session id (-1 if got errors) */
static __noinline int sysret_setsid(void *ctx, int ret)
{
    struct task_struct *task = (void *)bpf_get_current_task();
    struct proc_tid *tid;
    pid_t tgid;

    setsid_print(ctx, ret);

    /* locate tid cache in map: g_tid_cache */
    tgid = READ_KERN(task, tgid);
    tid = bpf_map_lookup_elem(&g_tid_cache, &tgid);
    if (tid)
        tid->sid = query_sid(task);

    return 0;
}

static __noinline int sysret_prctl(void *ctx, long option, char *name_ptr)
{
    struct var_prctl {
        char name[PATH_NAME_LEN];
    } *prctl;
    int rc;

    if (option != 15 /* PR_SET_NAME*/ || !name_ptr)
        return 0;

    prctl = sd_get_local(PATH_NAME_LEN);
    if (!prctl)
        return 0;

    rc = bpf_probe_read_str(prctl->name, PATH_NAME_LEN, name_ptr);
    if (rc > 0)
        prctl_print(ctx, option, prctl->name, rc);

    sd_put_local(prctl);
    return 0;
}

static __noinline int sysret_memfd_create(void *ctx, char *name, long flags, int ret)
{
    struct var_memfd_create {
        char name[PATH_NAME_LEN];
    } *memfd;
    int rc;

    memfd = sd_get_local(PATH_NAME_LEN);
    if (!memfd)
        return 0;

    rc = bpf_probe_read_str(memfd->name, PATH_NAME_LEN, name);
    if (rc > 0)
        memfd_create_print(ctx, memfd->name, rc, flags);

    sd_put_local(memfd);
    return 0;
}

static __noinline void show_connect_ipv4(void *ctx, struct sock *sk, int ret)
{
    __be32 sip, dip;
    int sport, dport;

    if (query_ipv4(sk, &sip, &sport, &dip, &dport))
        return;

    connect4_print(ctx, dip, dport, sip, sport, ret);
}

static __noinline void show_connect_ipv6(void *ctx, struct sock *sk, int ret)
{
    struct in6_addr sip, dip;
    int sport, dport;

    if (query_ipv6(sk, &sip, &sport, &dip, &dport))
        return;

     connect6_print(ctx, &dip, dport, &sip, sport, ret);
}

static __noinline int sysret_connect(void *ctx, int fd, int ret)
{
    struct task_struct *task = (void *)bpf_get_current_task();
    struct sock *sk;
    int sa_family;

    if (!task || fd < 0)
        return 0;

    sk = sockfd_lookup(task, fd);
    if (!sk)
        return 0;

    sa_family = sock_family(sk);
    if (sa_family == AF_INET)
        show_connect_ipv4(ctx, sk, ret);
    else if (sa_family == AF_INET6)
        show_connect_ipv6(ctx, sk, ret);

    return 0;
}

static __noinline int sysret_recvdat(void *ctx, int fd, char *data, int ret)
{
    struct sock *sk;

    /* too small for dns query */
    if (!data || ret < 20)
        return 0;

    if (fd < 0)
        return 0;

    sk = sockfd_lookup((void *)bpf_get_current_task(), fd);
    if (!sk)
        return 0;

    return process_dns_request(ctx, sk, data, ret);
}

static __noinline int sysret_recvmsg(void *ctx, int fd, unsigned long umsg, int ret)
{
    struct user_msghdr *msg = (void *)umsg;
    struct sock *sk;
    struct iovec iov = {0}, *uiov;

    if (fd < 0 || ret < 20)
        return 0;

    sk = sockfd_lookup((void *)bpf_get_current_task(), fd);
    if (!sk)
        return 0;

    uiov = READ_USER(msg, msg_iov);
    if (!uiov)
        return 0;
    iov = LOAD_USER(*uiov);
    if (!iov.iov_base || iov.iov_len < 20)
        return 0;

    return process_dns_request(ctx, sk, iov.iov_base, iov.iov_len);
}

static __noinline int sysret_bind(void *ctx, int fd, long ret)
{
    struct task_struct *task = (void *)bpf_get_current_task();
    struct sock *sk;
    struct smith_ip_addr ip;

    if (!task || fd < 0)
        return 0;

    sk = sockfd_lookup(task, fd);
    if (!sk)
        return 0;

    ip.sa_family = sock_family(sk);
    if (ip.sa_family == AF_INET) {
        if (!query_ipv4(sk, &ip.sip4, &ip.sport, &ip.dip4, &ip.dport))
            bind4_print(ctx, ip.sip4, ip.sport, ret);
    } else if (ip.sa_family == AF_INET6) {
        if (!query_ipv6(sk, &ip.sip6, &ip.sport, &ip.dip6, &ip.dport))
            bind6_print(ctx, &ip.sip6, ip.sport, ret);
    }

    return 0;
}

static __noinline int sysret_accept(void *ctx, int fd)
{
    struct task_struct *task = (void *)bpf_get_current_task();
    struct sock *sk;
    struct smith_ip_addr ip;

    if (!task || fd < 0)
        return 0;

    sk = sockfd_lookup(task, fd);
    if (!sk)
        return 0;

    ip.sa_family = sock_family(sk);
    if (ip.sa_family == AF_INET) {
        if (!query_ipv4(sk, &ip.sip4, &ip.sport, &ip.dip4, &ip.dport))
            accept4_print(ctx, ip.dip4, ip.dport, ip.sip4, ip.sport, fd);
    } else if (ip.sa_family == AF_INET6) {
        if (!query_ipv6(sk, &ip.sip6, &ip.sport, &ip.dip6, &ip.dport))
            accept6_print(ctx, &ip.dip6, ip.dport, &ip.sip6, ip.sport, fd);
    }

    return 0;
}

/*
 * execve related routines
 */

struct var_exec {
    struct sock *sk;
    struct smith_ip_addr ip;
    char *pwd;
    char pwd_dat[SD_STR_MAX];
    char tmp[PATH_NAME_LEN + 4];
    char tty[TTY_NAME_LEN];
    char *input, *output;
    char input_dat[SD_STR_MAX];
    char output_dat[SD_STR_MAX];
    char envs[SD_STR_MAX];
    char *ssh, *ld, *lib;
    uint32_t pwd_len, in_len, out_len;
    uint32_t ssh_len, ld_len, lib_len, tty_len;
    int pid;
    int ret;
};

static __noinline char *construct_fd_path(struct task_struct *task, int fd, char *path_dat, char *swap, uint32_t *len)
{
    char *path = NULL;
    struct file *fp = fget_raw(task, fd);
    if (!fp)
        goto out;
    struct path f_path = READ_KERN(fp, f_path);
    path = d_path(path_dat, swap, &f_path, len);

out:
    return path;
}

static __noinline int match_key(char *envs, int lenv, uint64_t key, int es)
{
    uint64_t *d = (void *)envs;
    return (lenv > es && *d == key && envs[es & SD_STR_MASK] == '=');
}

static __noinline int match_envs(unsigned long env, unsigned int lenv, unsigned int *len, struct var_exec *exec, unsigned int *off)
{
    void *envs = (void *)(env + *len);
    int rc = bpf_probe_read_str(exec->tmp, PATH_NAME_LEN, envs);
    if (rc <= 0)
        return 0;

    if (match_key(exec->tmp, rc, 0x4e4e4f435f485353UL, 14)) {
        /* SSH_CONN */
        exec->ssh = &exec->envs[(*off + 15) & SD_STR_MASK];
        exec->ssh_len = rc;
    } else if (match_key(exec->tmp, rc, 0x4f4c4552505f444cUL, 10)) {
        /* LD_PRELO */
        exec->ld = &exec->envs[(*off + 11) & SD_STR_MASK];
        exec->ld_len = rc;
    } else if (match_key(exec->tmp, rc, 0x415242494c5f444cUL, 15)) {
        /* LD_LIBRA */
        exec->lib = &exec->envs[(*off + 16) & SD_STR_MASK];
        exec->lib_len = rc;
    } else {
        goto out;
    }

    bpf_probe_read(&exec->envs[*off & SD_STR_MASK], rc & PATH_NAME_MASK, exec->tmp);
    *off += rc;

out:

    if (rc > 0) {
        *len += rc;
        if (*len + 10 >= lenv)
            return 0;
        return 1;
    }
    return 0;
}

static __noinline void process_envs(struct task_struct *task, struct var_exec *exec)
{
    unsigned long envs, enve;
    unsigned int lenv, i, len = 0, out = 0;

    exec->ssh = exec->ld = exec->lib = NULL;
    exec->ssh_len = exec->ld_len = exec->lib_len = 0;

    envs = READ_KERN(task, mm, env_start);
    enve = READ_KERN(task, mm, env_end);
    lenv = (unsigned int)(enve - envs);
    if (!envs || !lenv)
        goto out;

    /* maximumily 80 envs to be processed (max of bounded loops) */
#if LOOPS_UNROLL
#   pragma unroll
#endif
    for (i = 0; i < 80; i++) {
        if (!match_envs(envs, lenv, &len, exec, &out))
            break;
    }

out:
    return;
}

static __noinline void show_execve6(void *ctx, struct var_exec *exec)
{
    query_ipv6(exec->sk, &exec->ip.sip6, &exec->ip.sport,
               &exec->ip.dip6, &exec->ip.dport);
    execve6_print(ctx, exec->pwd, exec->pwd_len, exec->input, exec->in_len,
                  exec->output, exec->out_len, &exec->ip.dip6, exec->ip.dport,
                  &exec->ip.sip6, exec->ip.sport, exec->pid, exec->tty,
                  exec->tty_len, exec->ssh, exec->ssh_len, exec->ld,
                  exec->ld_len, exec->lib, exec->lib_len, exec->ret);
}

static __noinline void show_execve4(void *ctx, struct var_exec *exec)
{
    query_ipv4(exec->sk, &exec->ip.sip4, &exec->ip.sport,
               &exec->ip.dip4, &exec->ip.dport);
    execve4_print(ctx, exec->pwd, exec->pwd_len, exec->input, exec->in_len,
                  exec->output, exec->out_len, exec->ip.dip4, exec->ip.dport,
                  exec->ip.sip4, exec->ip.sport,exec->pid, exec->tty,
                  exec->tty_len, exec->ssh, exec->ssh_len, exec->ld,
                  exec->ld_len, exec->lib, exec->lib_len, exec->ret);
}

static __noinline void show_execve0(void *ctx, struct var_exec *exec)
{
    execve0_print(ctx, exec->pwd, exec->pwd_len, exec->input, exec->in_len,
                  exec->output, exec->out_len, exec->tty, exec->tty_len,
                  exec->ssh, exec->ssh_len, exec->ld, exec->ld_len, exec->lib,
                  exec->lib_len, exec->ret);
}

static __noinline int sysret_exec(void *ctx, int ret)
{
    struct task_struct *task = (void *)bpf_get_current_task();
    struct var_exec *exec;

    /*
     * WARNING:
     *   refresh_tid will use and destroy local cache,
     *   don't call refresh_tid() between sd_get_local
     *   and sd_put_local.
     */
    exec = sd_get_local(sizeof(*exec));
    if (!exec)
        return 0;
    exec->ret = ret;

    /* enumerate fd to locate 1st socket connection */
    exec->sk = process_socket(task, &exec->pid);
    if (exec->sk)
        exec->ip.sa_family = sock_family(exec->sk);
    else
        exec->ip.sa_family = 0;

    char *tty_name = READ_KERN(task, signal, tty, name);
    if (tty_name) {
        exec->tty_len = bpf_probe_read_str(exec->tty, 64, tty_name);
    } else {
        exec->tty[0] = 0;
        exec->tty_len = 0;
    }

    /* build path for current location (pwd) */
    struct path pwd = READ_KERN(task, fs, pwd);
    exec->pwd = d_path(exec->pwd_dat, exec->tmp, &pwd, &exec->pwd_len);

    /* query tty input & output devices */
    exec->in_len = 0;
    exec->input = construct_fd_path(task, 0, exec->input_dat, exec->tmp, &exec->in_len);
    exec->out_len = 0;
    exec->output = construct_fd_path(task, 1, exec->output_dat, exec->tmp, &exec->out_len);

    /* process environments */
    process_envs(task, exec);

    if (exec->ip.sa_family == AF_INET6 /* ipv6 */)
        show_execve6(ctx, exec);
    else if (exec->ip.sa_family == AF_INET /* ipv4 */)
        show_execve4(ctx, exec);
    else
        show_execve0(ctx, exec);

    sd_put_local(exec);

    return 0;
}

/*
 * 32-bit processes: 32-bit executable images
 */

/* sub-functions for socketcall */
#define SYS_SOCKET	1		/* sys_socket(2)		*/
#define SYS_BIND	2		/* sys_bind(2)			*/
#define SYS_CONNECT	3		/* sys_connect(2)		*/
#define SYS_LISTEN	4		/* sys_listen(2)		*/
#define SYS_ACCEPT	5		/* sys_accept(2)		*/
#define SYS_GETSOCKNAME	6		/* sys_getsockname(2)		*/
#define SYS_GETPEERNAME	7		/* sys_getpeername(2)		*/
#define SYS_SOCKETPAIR	8		/* sys_socketpair(2)		*/
#define SYS_SEND	9		/* sys_send(2)			*/
#define SYS_RECV	10		/* sys_recv(2)			*/
#define SYS_SENDTO	11		/* sys_sendto(2)		*/
#define SYS_RECVFROM	12		/* sys_recvfrom(2)		*/
#define SYS_SHUTDOWN	13		/* sys_shutdown(2)		*/
#define SYS_SETSOCKOPT	14		/* sys_setsockopt(2)		*/
#define SYS_GETSOCKOPT	15		/* sys_getsockopt(2)		*/
#define SYS_SENDMSG	16		/* sys_sendmsg(2)		*/
#define SYS_RECVMSG	17		/* sys_recvmsg(2)		*/
#define SYS_ACCEPT4	18		/* sys_accept4(2)		*/
#define SYS_RECVMMSG	19		/* sys_recvmmsg(2)		*/
#define SYS_SENDMMSG	20		/* sys_sendmmsg(2)		*/

#if defined(__TARGET_ARCH_x86)

static inline int syscall_get_nr(struct pt_regs *regs)
{
    return LOAD_KERN(regs->orig_ax);
}

#define TS_COMPAT 0x0002 /* 32bit syscall active (64BIT)*/
static __noinline int in_compat_task(void)
{
    struct thread_info *ti = (void *)bpf_get_current_task();
    u32 status;

    status = READ_KERN(ti, status);
    return !!(status & TS_COMPAT);
}

static __noinline int is_compat_exec(int syscallid)
{
    return (syscallid == 11 || syscallid == 358);

    /*
     * exec related: context of execved task
     * 11:  __NR_ia32_execve
     * 358:  __NR_ia32_execveat
     */
}

static __noinline int compat_sysret_exit(struct bpf_raw_tracepoint_args *ctx)
{
    struct pt_regs *regs = (struct pt_regs *)ctx->args[0];
    int rc = 0, ret, id, skip = 0;

    /* get return code of current syscall */
    ret = READ_KERN(regs, ax); /* ctx->args[1]; */
    /* query syscall id */
    id = syscall_get_nr(regs);

    /* try constructing new cache for current task */
    if (id != 1 && id != 252) {
        if (!find_current_tid())
            construct_tid((void *)bpf_get_current_task(), 0);
    }

    switch (id) {

    /*
     * exec related: context of execved task
     */
    case 11: /* __NR_ia32_execve */
    case 358: /* __NR_ia32_execveat */
        break;

    case 0x46: /* setreuid16 */
    case 0xcb: /* setreuid */
        skip = 1 | (1 << 2) | (1 << 6);
        break;
    case 0x47: /* setregid16 */
    case 0xcc: /* setregid */
        skip = 2 | (1 << 3) | (1 << 7);
        break;
    case 0xa4: /* setresuid16 */
    case 0xd0: /* setresuid */
        skip = 1 | (1 << 2) | (1 << 4) | (1 << 6);
        break;
    case 0xaa: /* setresgid16 */
    case 0xd1: /* setresgid */
        skip = 2 | (1 << 3) | (1 << 5) | (1 << 7);
        break;
    case 0x17: /* setuid16 */
    case 0xd5: /* setuid */
        skip = 1;
        break;
    case 0x2e: /* setgid16 */
    case 0xd6: /* setgid */
        skip = 2;
        break;
    case 0x8a: /* setfsuid16 */
    case 0xd7: /* setfsuid */
        skip = 1 << 6;
        break;
    case 0x8b: /* setfsgid16 */
    case 0xd8: /* setfsgid */
        skip = 1 << 7;
        break;

    case 26: /* __NR_ia32_ptrace: PTRACE_POKETEXT and PTRACE_POKEDATA */
        rc = sysret_ptrace(ctx, READ_KERN(regs, bx), READ_KERN(regs, cx),
                           (void *)READ_KERN(regs, dx), ret);
        break;

    case 31: /* __NR_ia32_mount */
    {
        struct mount_parms mount;
        mount.dev = (void *)READ_KERN(regs, bx);
        mount.dir = (void *)READ_KERN(regs, cx);
        mount.type = (void *)READ_KERN(regs, dx);
        mount.data = (void *)READ_KERN(regs, di);
        mount.flags = READ_KERN(regs, si);
        rc = sysret_mount(ctx, &mount, ret);
        break;
    }

    case 66 /*__NR_ia32_setsid */:
        rc = sysret_setsid(ctx, ret);
        break;

    case 128: /* 0x80: __NR_ia32_init_module */
    case 350: /* 0x15e: __NR_ia32_finit_module */
        break;

    case 172: /* prctl: x86_64: 157 / i386: 172 */
        rc = sysret_prctl(ctx, READ_KERN(regs, bx),
                        (char *)READ_KERN(regs, cx));
        break;

    case 356 /* __NR_ia32_memfd_create */:
        rc = sysret_memfd_create(ctx, (char *)READ_KERN(regs, bx),
                                 READ_KERN(regs, cx), ret);
        break;

    case 361 /* __NR_ia32_bind */:
        rc = sysret_bind(ctx, READ_KERN(regs, bx), ret);
        break;

    case 362 /* __NR_ia32_connect */:
        rc = sysret_connect(ctx, READ_KERN(regs, bx), ret);
        break;

    case 102: /* __NR_ia32_socketcall */
        if (SYS_CONNECT == READ_KERN(regs, bx)) {
            int *userfd = (int *)READ_KERN(regs, cx);
            int sockfd = (int)LOAD_USER(*userfd);
            rc = sysret_connect(ctx, sockfd, ret);
        } else if (SYS_BIND == READ_KERN(regs, bx)) {
            int *userfd = (int *)READ_KERN(regs, cx);
            int sockfd = (int)LOAD_USER(*userfd);
            rc = sysret_bind(ctx, sockfd, ret);
        } else if (SYS_ACCEPT == READ_KERN(regs, bx) ||
                   SYS_ACCEPT4 == READ_KERN(regs, bx)) {
            rc = sysret_accept(ctx, ret);
        } else if (ret >= 20 && (SYS_RECV == READ_KERN(regs, bx) ||
                                 SYS_RECVFROM == READ_KERN(regs, bx) ||
                                 SYS_RECVMSG == READ_KERN(regs, bx))) {
            /* now process dns request */
            int32_t ua[2];
            if (bpf_probe_read_user(ua, sizeof(ua), (void *)READ_KERN(regs, cx)))
                break;
            if (SYS_RECVMSG == READ_KERN(regs, bx))
                sysret_recvmsg(ctx, (int)ua[0], (unsigned long)ua[1], ret);
            else
                sysret_recvdat(ctx, (int)ua[0], (char *)(long)ua[1], ret);
        }
        break;
    default:
        break;
    }

    privilege_escalation(ctx, (void *)bpf_get_current_task(), skip);

    return rc;
}

/*
 * syscall id definitions for x64
 */

#define NR_exit             (60)
#define NR_exit_group       (231)

#define NR_execve           (0x3b)
#define NR_execveat         (0x142)

#define NR_setsid           (0x70)
#define NR_setreuid         (0x71)
#define NR_setregid         (0x72)
#define NR_setresuid        (0x75)
#define NR_setresgid        (0x77)
#define NR_setuid           (0x69)
#define NR_setgid           (0x6a)
#define NR_setfsuid         (0x7a)
#define NR_setfsgid         (0x7b)

#define NR_ptrace           (0x65)

#define NR_mount            (165)
#define NR_prctl            (157)

#define NR_init_module      (0xaf) /* 175 */
#define NR_finit_module     (0x139) /* 313 */

#define NR_rename           (0x52)
#define NR_renameat         (0x108)
#define NR_renameat2        (0x13c)

#define NR_link             (0x56)
#define NR_symlink          (0x58)
#define NR_linkat           (0x109)
#define NR_symlinkat        (0x10a)

#define NR_memfd_create     (0x13f) /* introduced by 3.17 */

/*
 * socket related
 */
#define NR_connect          (0x2a)
#define NR_accept           (0x2b)
#define NR_accept4          (0x120)
#define NR_bind             (0x31)

#define NR_recvfrom         (0x2d)
#define NR_recvmsg          (0x2f)
#define NR_recvmmsg         (0x12b)

#elif defined(__TARGET_ARCH_arm64)

static inline int syscall_get_nr(struct pt_regs *regs)
{
    return LOAD_KERN(regs->syscallno);
}

// kernel ref: arch/arm64/include/asm/compat.h
#define TIF_32BIT		22	/* 32bit process */
static __noinline int in_compat_task(void)
{
    struct thread_info *ti = (void *)bpf_get_current_task();
    u32 flags;

    flags = READ_KERN(ti, flags);
    return !!(flags & (1U << TIF_32BIT));
}

static __noinline int is_compat_exec(int syscallid)
{
    return (syscallid == 11 || syscallid == 387);

    /*
     * exec related: context of execved task
     * 11:  __NR_a32_execve
     * 387:  __NR_a32_execveat
     */
}

static __noinline int compat_sysret_exit(struct bpf_raw_tracepoint_args *ctx)
{
    struct pt_regs *regs = (struct pt_regs *)ctx->args[0];
    int rc = 0, ret, id, skip = 0;

    /* get return code of current syscall */
    ret = ctx->args[1];

    /* query syscall id */
    id = syscall_get_nr(regs);

    /* try constructing new cache for current task */
    if (id != 1 && id != 248) {
        if (!find_current_tid())
            construct_tid((void *)bpf_get_current_task(), 0);
    }

    switch (id) {

    /*
     * exec related: context of execved task
     */
    case 11: /* execve */
    case 387: /* execveat */
        break;

    case 70: /* setreuid16 */
    case 203: /* setreuid */
        skip = 1 | (1 << 2) | (1 << 6);
        break;
    case 71: /* setregid16 */
    case 204: /* setregid */
        skip = 2 | (1 << 3) | (1 << 7);
        break;
    case 164: /* setresuid16 */
    case 147: /* setresuid */
        skip = 1 | (1 << 2) | (1 << 4) | (1 << 6);
        break;
    case 170: /* setresgid16 */
    case 149: /* setresgid */
        skip = 2 | (1 << 3) | (1 << 5) | (1 << 7);
        break;
    case 23: /* setuid16 */
    case 213: /* setuid */
        skip = 1;
        break;
    case 46: /* setgid16 */
    case 214: /* setgid */
        skip = 2;
        break;
    case 138: /* setfsuid16 */
    case 215: /* setfsuid */
        skip = 1 << 6;
        break;
    case 139: /* setfsgid16 */
    case 216: /* setfsgid */
        skip = 1 << 7;
        break;

    case 26: /* ptrace: PTRACE_POKETEXT and PTRACE_POKEDATA */
        rc = sysret_ptrace(ctx, SC_REGS_PARM1(regs), SC_REGS_PARM2(regs),
                           (void *)SC_REGS_PARM3(regs), ret);
        break;

    case 52: /* mount */
    {
        struct mount_parms mount;
        mount.dev = (void *)SC_REGS_PARM1(regs);
        mount.dir = (void *)SC_REGS_PARM2(regs);
        mount.type = (void *)SC_REGS_PARM3(regs);
        mount.data = (void *)SC_REGS_PARM5(regs);
        mount.flags = SC_REGS_PARM4(regs);
        rc = sysret_mount(ctx, &mount, ret);
        break;
    }

    case 66: /* setsid */
        rc = sysret_setsid(ctx, ret);
        break;

    case 128: /* init_module */
    case 379: /* finit_module */
        break;

    case 172: /* prctl */
        rc = sysret_prctl(ctx, SC_REGS_PARM1(regs),
                        (char *)SC_REGS_PARM2(regs));
        break;

    case 385: /* memfd_create */
        rc = sysret_memfd_create(ctx, (char *)SC_REGS_PARM1(regs),
                                 SC_REGS_PARM2(regs), ret);
        break;

    case 282: /* bind */
        rc = sysret_bind(ctx, SC_REGS_PARM1(regs), ret);
        break;

    case 283: /* connect */
        rc = sysret_connect(ctx, SC_REGS_PARM1(regs), ret);
        break;

    case 285: /* accept */
    case 366: /* accept4 */
        rc = sysret_accept(ctx, ret);
        break;

    case 291: /* recv */
    case 292: /* recvfrom */
        rc = sysret_recvdat(ctx, SC_REGS_PARM1(regs), (char *)SC_REGS_PARM2(regs), ret);
        break;
    case 297: /* recvmsg */
        rc = sysret_recvmsg(ctx, SC_REGS_PARM1(regs), SC_REGS_PARM2(regs), ret);
        break;
    case 365: /* recvmmsg */
        break;

#if 0
    case 102: /* socketcall ? */
        if (SYS_CONNECT == SC_REGS_PARM1(regs)) {
            int *userfd = (int *)SC_REGS_PARM2(regs);
            int sockfd = (int)LOAD_USER(*userfd);
            rc = sysret_connect(ctx, sockfd, ret);
        } else if (SYS_BIND == SC_REGS_PARM1(regs)) {
            int *userfd = (int *)SC_REGS_PARM2(regs);
            int sockfd = (int)LOAD_USER(*userfd);
            rc = sysret_bind(ctx, sockfd, ret);
        } else if (SYS_ACCEPT == SC_REGS_PARM1(regs) ||
                   SYS_ACCEPT4 == SC_REGS_PARM1(regs)) {
            rc = sysret_accept(ctx, ret);
        } else if (ret >= 20 && (SYS_RECV == SC_REGS_PARM1(regs) ||
                                 SYS_RECVFROM == SC_REGS_PARM1(regs) ||
                                 SYS_RECVMSG == SC_REGS_PARM1(regs))) {
            /* now process dns request */
            int32_t ua[2];
            if (bpf_probe_read_user(ua, sizeof(ua), (void *)SC_REGS_PARM2(regs)))
                break;
            if (SYS_RECVMSG == SC_REGS_PARM1(regs))
                sysret_recvmsg(ctx, (int)ua[0], (unsigned long)ua[1], ret);
            else
                sysret_recvdat(ctx, (int)ua[0], (char *)(long)ua[1], ret);
        }
        break;
#endif

    default:
        break;
    }

    privilege_escalation(ctx, (void *)bpf_get_current_task(), skip);

    return rc;
}

/*
 * syscall id definitions for aarch64
 */

#define NR_exit             (93)
#define NR_exit_group       (94)

#define NR_execve           (221)
#define NR_execveat         (281)

#define NR_setsid           (157)
#define NR_setreuid         (145)
#define NR_setregid         (143)
#define NR_setresuid        (147)
#define NR_setresgid        (149)
#define NR_setuid           (146)
#define NR_setgid           (144)
#define NR_setfsuid         (151)
#define NR_setfsgid         (152)

#define NR_ptrace           (117)

#define NR_mount            (40)
#define NR_prctl            (167)

#define NR_init_module      (105)
#define NR_finit_module     (273)

#define NR_renameat         (38)
#define NR_renameat2        (276)

#define NR_linkat           (37)
#define NR_symlinkat        (36)

#define NR_memfd_create     (279)

/*
 * socket related
 */
#define NR_connect          (203)
#define NR_accept           (202)
#define NR_accept4          (242)
#define NR_bind             (200)

#define NR_recvfrom         (207)
#define NR_recvmsg          (212)
#define NR_recvmmsg         (243)

#elif defined(__TARGET_ARCH_riscv)

static inline int syscall_get_nr(struct pt_regs *regs)
{
    return LOAD_KERN(regs->a7);
}

static __noinline int in_compat_task(void)
{
    return 0;
}

static __noinline int compat_sysret_exit(struct bpf_raw_tracepoint_args *ctx)
{
    return 0;
}

/*
 * syscall id definitions for riscv64
 */

#define NR_exit             ()
#define NR_exit_group       ()

#define NR_execve           ()
#define NR_execveat         ()

#define NR_setsid           ()
#define NR_setreuid         ()
#define NR_setregid         ()
#define NR_setresuid        ()
#define NR_setresgid        ()
#define NR_setuid           ()
#define NR_setgid           ()
#define NR_setfsuid         ()
#define NR_setfsgid         ()

#define NR_ptrace           ()

#define NR_mount            ()
#define NR_prctl            ()

#define NR_init_module      ()
#define NR_finit_module     ()

#define NR_renameat         ()
#define NR_renameat2        ()

#define NR_linkat           ()
#define NR_symlinkat        ()

#define NR_memfd_create     ()

/*
 * socket related
 */
#define NR_connect          ()
#define NR_accept           ()
#define NR_accept4          ()
#define NR_bind             ()

#define NR_recvfrom         ()
#define NR_compat_recvfrom  ()
#define NR_recvmsg          ()
#define NR_recvmmsg         ()

#endif

/* general syscall exit handling for x64/aarch64/riscv64 */
static __noinline int sysret_exit(struct bpf_raw_tracepoint_args *ctx)
{
    struct pt_regs *regs = (struct pt_regs *)ctx->args[0];
    int rc = 0, ret, id, skip = 0;

    /* get return code of current syscall */
    ret = ctx->args[1];

    /* query syscall id */
    id = syscall_get_nr(regs);

    /* try constructing new cache for current task */
    if (id != NR_exit && id != NR_exit_group) {
        if (!find_current_tid())
            construct_tid((void *)bpf_get_current_task(), 0);

    }

    switch (id) {

    /*
     * exec related: context of execved task
     */
    case NR_execve:
    case NR_execveat:
        break;

    case NR_setreuid:
        skip = 1 | (1 << 2) | (1 << 6);
        break;
    case NR_setregid:
        skip = 2 | (1 << 3) | (1 << 7);
        break;
    case NR_setresuid:
        skip = 1 | (1 << 2) | (1 << 4) | (1 << 6);
        break;
    case NR_setresgid:
        skip = 2 | (1 << 3) | (1 << 5) | (1 << 7);
        break;
    case NR_setuid:
        skip = 1;
        break;
    case NR_setgid:
        skip = 2;
        break;
    case NR_setfsuid:
        skip = 1 << 6;
        break;
    case NR_setfsgid:
        skip = 1 << 7;
        break;

    case NR_ptrace: /* PTRACE_POKETEXT and PTRACE_POKEDATA */
        rc = sysret_ptrace(ctx, SC_REGS_PARM1(regs), SC_REGS_PARM2(regs),
                           (void *)SC_REGS_PARM3(regs), ret);
        break;

    case NR_setsid:
        rc = sysret_setsid(ctx, ret);
        break;

    case NR_mount:
    {
        struct mount_parms mount;
        mount.dev = (void *)SC_REGS_PARM1(regs);
        mount.dir = (void *)SC_REGS_PARM2(regs);
        mount.type = (void *)SC_REGS_PARM3(regs);
        mount.data = (void *)SC_REGS_PARM5(regs);
        mount.flags = SC_REGS_PARM4(regs);
        rc = sysret_mount(ctx, &mount, ret);
        break;
    }

    case NR_prctl:
        rc = sysret_prctl(ctx, SC_REGS_PARM1(regs), (char *)SC_REGS_PARM2(regs));
        break;

    case NR_init_module:
    case NR_finit_module:
    break;

#if defined(NR_rename)
    case NR_rename:
#endif
    case NR_renameat: /* olddfd/oldname/newdfd/newname */
    case NR_renameat2: /* olddfd/oldname/newdfd/newname/flags */
        break;

#if 0
    case NR_link: /* oldname/newname */
    case NR_symlink: /* oldname/newname */
        break;
#endif

    case NR_linkat: /* olddfd/oldname/newdfd/newname */
    case NR_symlinkat: /* oldname/newdfd/newname */
        break;

    case NR_memfd_create: /* introduced by 3.17 */
        rc = sysret_memfd_create(ctx, (char *)SC_REGS_PARM1(regs),
                                 SC_REGS_PARM2(regs), ret);
        break;

    /*
     * socket related
     */
    case NR_connect: /* int sockfd/struct sockaddr *addr/socklen_t addrlen) */
        rc = sysret_connect(ctx, SC_REGS_PARM1(regs), ret);
        break;
    case NR_accept:
    case NR_accept4:
        rc = sysret_accept(ctx, ret);
        break;
    case NR_bind:
        rc = sysret_bind(ctx, SC_REGS_PARM1(regs), ret);
        break;

    case NR_recvfrom:
        rc = sysret_recvdat(ctx, SC_REGS_PARM1(regs), (char *)SC_REGS_PARM2(regs), ret);
        break;
    case NR_recvmsg:
        rc = sysret_recvmsg(ctx, SC_REGS_PARM1(regs), SC_REGS_PARM2(regs), ret);
        break;
    case NR_recvmmsg:
        break;

    default:
        break;
    }

    privilege_escalation(ctx, (void *)bpf_get_current_task(), skip);

    return rc;
}

/*
 * global hooking points
 *
 * use raw tracepoint if possible for best performance
 */

SEC("raw_tracepoint/sched_process_exec")
int tp__proc_exec(struct bpf_raw_tracepoint_args *ctx)
{
    pid_t pid = (pid_t)bpf_get_current_pid_tgid();
    pid_t tgid = (pid_t)(bpf_get_current_pid_tgid() >> 32);
    struct task_struct *task;
    struct proc_tid *tid;

    if (tgid != pid)
        return 0;

    /* kernel threads are to be bypassed */
    task = (struct task_struct *)bpf_get_current_task();
    unsigned int flags = READ_KERN(task, flags);
    if (flags & PF_KTHREAD)
        return 0;

    /* update tid members related with new execve */
    tid = bpf_map_lookup_elem(&g_tid_cache, &tgid);
    if (!tid)
        return 0;
    refresh_tid(task, tid);

    return 0;
}

SEC("raw_tracepoint/sched_process_fork")
int tp__proc_fork(struct bpf_raw_tracepoint_args *ctx)
{
    struct task_struct *task;
    __u32 tgid, pid;

    /* args[0]: self; args[1]: task */
    task = (struct task_struct *)READ_KERN(ctx, args[1]);

    /* kernel threads are to be bypassed */
    if (READ_KERN(task, flags) & PF_KTHREAD)
        return 0;

    pid = READ_KERN(task, pid);
    tgid= READ_KERN(task, tgid);
    if (tgid != pid)
        return 0;

    /* construct tid cache for this task */
    construct_tid(task, 1);

    return 0;
}

SEC("raw_tracepoint/sched_process_exit")
int tp__proc_exit(struct bpf_raw_tracepoint_args *ctx)
{
    __u32 pid = (__u32)bpf_get_current_pid_tgid();
    __u32 tgid = (__u32)(bpf_get_current_pid_tgid() >> 32);

    if (tgid != pid)
        return 0;

    // task exit event tracing
    // tid->exit_time = bpf_ktime_get_ns();
    // exit_code = READ_KERN(task, exit_code);
    // tid->sig = exit_code & 0xff;
    // tid->exit_code = exit_code >> 8;

    bpf_map_delete_elem(&g_tid_cache, &tgid);
    return 0;
}

SEC("raw_tracepoint/sys_exit")
int tp__compat_sys_exit(struct bpf_raw_tracepoint_args *ctx)
{
#if 0
    int ret = ctx->args[1];
    /* ignoring all failed syscalls */
    if (ctx->args[1])
        return 0;
#endif

    /* current process is 32bit */
    if (in_compat_task())
        compat_sysret_exit(ctx);

    return 0;
}

SEC("raw_tracepoint/sys_exit")
int tp__sys_exit(struct bpf_raw_tracepoint_args *ctx)
{
    /* current process is 64bit */
    if (!in_compat_task()) {
        /* do general handling for syscall-exit events */
        sysret_exit(ctx);
    }

    return 0;
}

SEC("raw_tracepoint/sys_exit")
int tp__sys_exec(struct bpf_raw_tracepoint_args *ctx)
{
    struct pt_regs *regs = (struct pt_regs *)ctx->args[0];
    int id, compat;

    /* query syscall id */
    id = syscall_get_nr(regs);
    compat = in_compat_task();

    if ((compat && is_compat_exec(id)) ||
        (!compat && (id == NR_execve || id == NR_execveat))) {
        sysret_exec(ctx, ctx->args[1]);
    }

    return 0;
}

static __noinline int query_s_id_by_dentry(char *s_id, struct dentry *de)
{
    char *id = READ_KERN(de, d_sb, s_id);
    int len = 0;
    if (id)
        len = bpf_probe_read_str(s_id, 32, id);
    else
        s_id[0] = 0;
    return len;
}

/*
 * file creation hooking
 */

struct var_create {
    struct sock *sk;
    char *path;
    char path_dat[SD_STR_MAX];
    char swap[PATH_NAME_LEN + 4];
    char s_id[32];
    struct smith_ip_addr ip;
    uint32_t sz_path;
    int pid;
};

static __noinline void show_create0(void *ctx, struct var_create *create);
static __noinline void show_create4(void *ctx, struct var_create *create);
static __noinline void show_create6(void *ctx, struct var_create *create);

/* int security_inode_create(struct inode *dir, struct dentry *dentry, umode_t mode) */
SEC("kprobe/security_inode_create")
int kp__inode_create(struct pt_regs *regs)
{
    struct var_create *create;
    struct sock *sk;
    struct task_struct *task;

    create = sd_get_local(sizeof(*create));
    if (!create)
        return 0;

    struct dentry *de = (void *)FC_REGS_PARM2(regs);
    if (!de)
        goto out;

    query_s_id_by_dentry(create->s_id, de);
    create->path = dentry_path(create->path_dat, create->swap, de,
                              &create->sz_path);

    /* enumerate fd to locate 1st socket connection */
    task = (struct task_struct *)bpf_get_current_task();
    sk = process_socket(task, &create->pid);
    if (sk)
        create->ip.sa_family = sock_family(sk);
    else
        create->ip.sa_family = 0;

    if (create->ip.sa_family == AF_INET6 /* ipv6 */)
        show_create6(regs, create);
    else if (create->ip.sa_family == AF_INET /* ipv4 */)
        show_create4(regs, create);
    else
        show_create0(regs, create);

out:
    sd_put_local(create);
    return 0;
}

static __noinline void show_create6(void *ctx, struct var_create *create)
{
    query_ipv6(create->sk, &create->ip.sip6, &create->ip.sport,
               &create->ip.dip6, &create->ip.dport);
    create6_print(ctx, create->path, create->sz_path,
                  &create->ip.dip6, create->ip.dport, &create->ip.sip6,
                  create->ip.sport, create->pid, create->s_id);
}

static __noinline void show_create4(void *ctx, struct var_create *create)
{
    query_ipv4(create->sk, &create->ip.sip4, &create->ip.sport,
               &create->ip.dip4, &create->ip.dport);
    create4_print(ctx, create->path, create->sz_path,
                  create->ip.dip4, create->ip.dport, create->ip.sip4,
                  create->ip.sport, create->pid, create->s_id);
}

static __noinline void show_create0(void *ctx, struct var_create *create)
{
    create0_print(ctx, create->path, create->sz_path, create->s_id);
}

/*
 * int security_inode_rename(
 *          struct inode *old_dir, struct dentry *old_dentry,
 *          struct inode *new_dir, struct dentry *new_dentry,
 *          unsigned int flags)
 */
SEC("kprobe/security_inode_rename")
int kp__inode_rename(struct pt_regs *regs)
{
    struct var_rename {
        char *old;
        char *new;
        char old_dat[SD_STR_MAX];
        char new_dat[SD_STR_MAX];
        char tmp[PATH_NAME_LEN + 4];
        char s_id[32];
    } *rename;
    uint32_t len1, len2;

    rename = sd_get_local(sizeof(*rename));
    if (!rename)
        return 0;

    struct dentry *de1 = (void *)FC_REGS_PARM2(regs);
    struct dentry *de2 = (void *)FC_REGS_PARM4(regs);
    if (!de1 || !de2)
        goto errorout;

    query_s_id_by_dentry(rename->s_id, de1);
    rename->old = dentry_path(rename->old_dat, rename->tmp, de1, &len1);
    rename->new = dentry_path(rename->new_dat, rename->tmp, de2, &len2);
    rename_print(regs, rename->old, len1, rename->new, len2, rename->s_id);

errorout:
    sd_put_local(rename);
    return 0;
}

/*
 * int security_inode_link(
 *          struct dentry *old_dentry, struct inode *dir,
 *          struct dentry *new_dentry)
 */
SEC("kprobe/security_inode_link")
int kp__inode_link(struct pt_regs *regs)
{
    struct var_link {
        char *old;
        char *new;
        char old_dat[SD_STR_MAX];
        char new_dat[SD_STR_MAX];
        char tmp[PATH_NAME_LEN + 4];
        char s_id[32];
    } *link;
    uint32_t len1, len2;

    link = sd_get_local(sizeof(*link));
    if (!link)
        return 0;

    struct dentry *de1 = (void *)FC_REGS_PARM1(regs);
    struct dentry *de2 = (void *)FC_REGS_PARM3(regs);
    if (!de1 || !de2)
        goto errorout;

    query_s_id_by_dentry(link->s_id, de1);
    link->old = dentry_path(link->old_dat, link->tmp, de1, &len1);
    link->new = dentry_path(link->new_dat, link->tmp, de2, &len2);
    link_print(regs, link->old, len1, link->new, len2, link->s_id);

errorout:
    sd_put_local(link);
    return 0;
}

/*
 * int call_usermodehelper_exec(
 *          struct subprocess_info *sub_info,
 *          int wait)
 */
SEC("kprobe/call_usermodehelper_exec")
int kp__umh_exec(struct pt_regs *regs)
{
    struct var_umh_exec {
        char path[PATH_NAME_LEN];
        char args[SD_STR_MAX];
        char swap[SD_STR_MAX];
        int path_len;
        int args_len;
    } *umh = NULL;
    struct subprocess_info *si;
    char *args, **argv;
    unsigned int len = 0;
    int i, rc;

    umh = sd_get_local(sizeof(*umh));
    if (!umh)
        goto out;
    si = (void *)FC_REGS_PARM1(regs);
    if (!si)
        goto out;
    args = (void *)READ_KERN(si, path);
    if (args)
        rc = bpf_probe_read_str(umh->path, PATH_NAME_LEN, args);
    else
        rc = 0;
    umh->path_len = rc > 0 ? rc : 0;

    /* read argv[0] */
    argv = (char **)READ_KERN(si, argv);
    if (!argv)
        goto out;

#if LOOPS_UNROLL
#   pragma unroll
#endif
    for (i = 0; i < CMD_ARGS_MAX; i++) {
        args = (char *)LOAD_KERN(argv[i]);
        if (!args)
            break;
        rc = bpf_probe_read_str(umh->swap, SD_STR_MASK, args);
        if (rc <= 0)
            break;
        rc = append_string(umh->args, len, rc, SD_STR_MAX, umh->swap);
        if (!rc)
            break;
        len += rc;
    }
    umh->args_len = len;
    call_usermodehelper_exec_print(regs, umh->path, umh->path_len, umh->args,
                                   umh->args_len, FC_REGS_PARM2(regs));

out:
    if (umh)
        sd_put_local(umh);
    return 0;
}

/*
 * int do_init_module(struct module *mod)
 */
SEC("kprobe/do_init_module")
int kp__init_module(struct pt_regs *regs)
{
    struct var_module {
        char *pwd;
        char pwd_dat[SD_STR_MAX];
        char tmp[PATH_NAME_LEN + 4];
        char mod[NODE_NAME_LEN];
        char *name;
        uint32_t pwd_len;
        uint32_t mod_len;
    } *module;
    int rc;

    struct task_struct *task = (void *)bpf_get_current_task();
    module = sd_get_local(sizeof(*module));
    if (!task || !module)
        return 0;

    struct module *mod = (void *)FC_REGS_PARM1(regs);
    if (!mod)
        goto out;

    struct path pwd = READ_KERN(task, fs, pwd);

    /* build path for current location (pwd) */
    module->pwd = d_path(module->pwd_dat, module->tmp, &pwd, &module->pwd_len);

    /* build module name string */
    module->name = (void *)READ_KERN(mod, name);
    if (!module->name)
        goto out;
    rc = bpf_probe_read_str(module->mod, NODE_NAME_LEN, module->name);
    module->mod_len = rc > 0 ? rc : 0;

    init_module_print(regs, module->mod, module->mod_len, module->pwd,
                      module->pwd_len);

out:
    sd_put_local(module);
    return 0;
}

/*
 * int commit_creds(struct cred *new)
 */
SEC("kprobe/commit_creds")
int kp__commit_creds(struct pt_regs *regs)
{
    struct task_struct *task = (void *)bpf_get_current_task();
    struct cred *cred = (void *)FC_REGS_PARM1(regs);
    int uid1, euid1, uid2, euid2;

    uid1 = READ_KERN(task, real_cred, uid.val);
    euid1 = READ_KERN(task, real_cred, euid.val);
    uid2 = READ_KERN(cred, uid.val);
    euid2 = READ_KERN(cred, euid.val);
    if (uid1 != 0 && euid1 != 0 && (!uid2 || !euid2))
        commit_creds_print(regs, uid1, euid1);
    return 0;
}

#if 0
/*
 * int do_execve_common(const char *filename,
 *				struct user_arg_ptr argv,
 *				struct user_arg_ptr envp)
 */
SEC("kretprobe/do_execveat_common.isra.0")
int kr__execve(struct pt_regs *regs)
{
    return sysret_exec(regs, RC_REGS(regs));
}
#endif

#if 0
SEC("tc")
int load_global(struct __sk_buff *skb)
{
    struct sd_event_point *sdp;
    int i;

    for (i = 0; i < 10; i++) {
        sdp = &g_sd_events[i];
        bpf_printk("event: %2.2d format: %d eid: %d\n",
                    i + 1, sdp->fmt, sdp->eid);
    }
    return 0 /* TC_ACT_OK */;
}
#endif

char LICENSE[] SEC("license") = "GPL";

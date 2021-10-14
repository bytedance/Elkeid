// SPDX-License-Identifier: GPL-2.0

/*
 * barrier support defintions
 */

#ifndef WRITE_ONCE
#define WRITE_ONCE(x, val) *(volatile typeof(x) *)&(x) = (val)
#endif

#ifndef READ_ONCE
#define READ_ONCE(x) *(volatile typeof(x) *)&(x)
#endif


/*
 * debuggibng nessage logging
 */

#define D_ERR                       (1UL << 31)
#define D_TRACE                     (1UL << 30)
#define D_INFO                      (1UL <<  1)
#define D_FUNC                      (1UL)

extern uint32_t                     g_rs_dbg;


#ifdef __KERNEL__
#define RSPRINT                     printk
#else
#define RSPRINT                     printf
#endif

#define RSDEBUG(dl, fmt...)                                             \
    do {                                                                \
        if ((dl) & g_rs_dbg) {                                          \
            RSPRINT(fmt);                                               \
        }                                                               \
    } while(0) 
#define RSERROR(fmt...)             RSDEBUG(D_ERR, fmt)

/*
 * function execution logging ...
 */
#define ENTRY()                                                         \
    do {                                                                \
        RSPRINT("%s:%d %s: called.\n", __FILE__, __LINE__, __func__);   \
    } while(0)

#define GOTO(x)                                                         \
    do {                                                                \
        int _rc = (x);                                                  \
        RSPRINT("%s:%d %s: g: %d\n", __FILE__, __LINE__, __func__, _rc);\
        goto errorout;                                                  \
    } while(0)

#define RETURN(x)                                                       \
    do {                                                                \
        int _rc = (int)(long)(x);                                       \
        RSPRINT("%s:%d %s: r: %d\n", __FILE__, __LINE__, __func__, _rc);\
        return __rc;                                                    \
    } while(0)

#define EXIT()                                                          \
    do {                                                                \
        RSPRINT("%s:%d %s: exit.\n", __FILE__, __LINE__, __func__);     \
    } while(0)

/*
 * system-related definitions
 */

#define RS_NR_CPUS                  (256)

#ifdef __KERNEL__

#define RS_BUG(x)                   BUG_ON(x)
#define RS_CHK(x)                   do {                                            \
                                        if (unlikely(x))                            \
                                            rs_reset_core(rs, rs_cpu_id());         \
                                    } while(0)
#define rs_get_cpu()                get_cpu()
#define rs_put_cpu()                put_cpu()
#if LINUX_VERSION_CODE > KERNEL_VERSION(4, 9, 0)
#define rs_memcpy                   __memcpy
#define rs_memset                   __memset
#else
#define rs_memcpy                   memcpy
#define rs_memset                   memset
#endif
#define rs_cpu_id()                 ((__u32)smp_processor_id() & ((RS_NR_CPUS) - 1))

/*
 * page_size() from linux/mm.h
 */
#ifndef page_size
/* Returns the number of bytes in this potentially compound page. */
static inline unsigned long rs_page_size(struct page *page)
{
	return PAGE_SIZE;
}
#else
#define rs_page_size page_size
#endif

static inline int rs_query_irql(void)
{
    unsigned long pc = preempt_count();
    int bit;

    if (!(pc & (NMI_MASK | HARDIRQ_MASK | SOFTIRQ_OFFSET)))
        return 0;
    else
        bit = pc & NMI_MASK ? 3 :
              pc & HARDIRQ_MASK ? 2 : 1;
    return bit;
}

#else /* !__KERNEL__ */

#define RS_BUG(x)                   do {if (x) __builtin_trap();} while(0)
#define RS_CHK(x)                   do {                                                    \
                                        if (x) {                                            \
                                            printf("slot core corrupted, re-trying ...\n"); \
                                            goto errorout;                                  \
                                        }                                                   \
                                    } while(0)
#define BUG()                       do {__builtin_trap();} while(0)
#define dump_stack()                do {__builtin_trap();} while(0)                       
#define rs_get_cpu()                do {} while(0)
#define rs_put_cpu()                do {} while(0)
#define rs_memcpy                   memcpy
#define rs_memset                   memset
#define rs_cpu_id()                 (0)
#define rs_get_seconds()            (0)
#define ALIGN(v, a)                 (((v) + (a) - 1) & ~((a) - 1))
#define IS_ERR(x)                   ((unsigned long)(void *)(long)(x) >= (unsigned long)-4095)

#endif /* !__KERNEL__ */

/*
 * structures for slot record
 */

struct slot_record {
    uint32_t    sr_state;   /* must be 1st in head, sequence + state */
    uint32_t    sr_len:16;  /* real data size, up to (4K - 16) */
    uint32_t    sr_irq:4;   /* irq level: NMI=3/IRQ=2/SOFTIRQ=1/NORMAL=0 */
    uint32_t    sr_flags:4; /* flags: buffer is wrapped or not */
    uint32_t    sr_magic:8; /* must be 'R' */
    uint32_t    sr_time;    /* seconds from ring_slot.rs_dawning */
    uint32_t    sr_pid;     /* caller process id */
};

#define SLOT_RECLEN_MASK    (16 - 1)
#define SLOT_RECLEN_UNIT    (16)

#define SLOT_LEN2REC(l)     ALIGN((l) + sizeof(struct slot_record), SLOT_RECLEN_UNIT)

#define SLOT_RECORD_MAGIC           'R'     /* magic id */
#define SLOT_RECORD_FLAG_WRAPPED    0x01    /* data buffer wrapped in middle */

/* record state descriptor */
enum record_state {
	sr_state_missing   = -1,      /* seq no mismatch (pseudo state) */
	sr_state_reserved  = 0x0,     /* reserved, being used by writer */
	sr_state_committed = 0x1,     /* committed by writer, to be read or discarded */
	sr_state_consuming = 0x2,     /* committed by writer, to be read or discarded */
	sr_state_reusable  = 0x3,     /* to be discarded, not yet used by writer */
    sr_state_mask = 0x7
};

#define SR_STATE(s) ((s) &  sr_state_mask)
#define SR_SEQNO(s) ((s) & ~sr_state_mask)

/*
 * common structure used by kernel producer and user consumer
 */

struct slot_work {
    void               *sw_slot;        /* percpu mmap zone for slot records */

    uint64_t            sw_start;       /* slot start offset in mmap zone */
    uint32_t            sw_realsz;      /* sw_size + PAGE_SIZE */
    uint32_t            sw_size;        /* slot buffer size, power of 2 */
    uint32_t            sw_mask;        /* (sw_size - 1) */
    uint32_t            sw_cpuid;       /* cpu id */

    /*
     * number of resets (unrecoverable errors: memory corrupted by agent)
     */
    uint32_t            sw_resets;


    uint32_t           *sw_ents;        /* pointers to slot_core */
    uint32_t           *sw_used;
    uint32_t           *sw_data;
    uint32_t           *sw_head;
    uint32_t           *sw_tail;
    uint32_t           *sw_waits;
    uint32_t           *sw_flags;
    uint32_t           *sw_npros;
    uint32_t           *sw_ncons;
    uint32_t           *sw_ndrop;
    uint32_t           *sw_ndisc;
    uint64_t           *sw_cpros;
    uint64_t           *sw_ccons;
    uint64_t           *sw_cdrop;
    uint64_t           *sw_cdisc;
    uint32_t           *sw_maxsz;
    uint32_t           *sw_nexcd;

};

#define CORE_POS2REC(sw, o)   ((void *)((sw)->sw_slot) + ((o) & (sw)->sw_mask))
#define CORE_MMAP_BASE(rs)    ALIGN((rs)->rs_head.rh_cpus_mmap + \
                                    (rs)->rs_head.rh_cpus_size, 1UL << 20)
#define CORE_MMAP_START(rs, sw, cpu) \
          (CORE_MMAP_BASE(rs) + (cpu) * ALIGN((sw)->sw_realsz, 1UL << 20))


#ifdef __KERNEL__

/*
 * core slot definitions for kernel
 */

struct slot_core {

    /*
     * total record entries stored in this slot
     */
    uint32_t    sc_ents ____cacheline_aligned_in_smp;

    /*
     * total occupied length, a record can overlap
     * sc_used = (sc_tail > sc_head) ? (sc_tail - sc_head) :
     *           (sc_tail + sc_size - sc_head)
     */
    uint32_t    sc_used ____cacheline_aligned_in_smp;

    /*
     * total (committed) message length
     */
    uint32_t    sc_data ____cacheline_aligned_in_smp;

    /*
     * head pointer for consumer to read from
     * value arrange is  0 - (2^32 - 1), can exceed sp_size
     */
    uint32_t    sc_head ____cacheline_aligned_in_smp;

    /*
     * taiil pointer for producer to append to
     * value arrange is  0 - (2^32 - 1), can exceed sp_size
     */
    uint32_t    sc_tail ____cacheline_aligned_in_smp;
    
    /*
     * records produced
     */
    uint32_t    sc_npros ____cacheline_aligned_in_smp;

    /*
     * records consumed
     */
    uint32_t    sc_ncons ____cacheline_aligned_in_smp;

    /*
     * records dropped due to slow-consuming (not appendped at all)
     */
    uint32_t    sc_ndrop ____cacheline_aligned_in_smp;

    /*
     * records discarded due to overwriting (appended, not yet consumed)
     */
    uint32_t    sc_ndisc ____cacheline_aligned_in_smp;

    /*
     * flags: like consumer sleep or not
     */
    uint32_t    sc_flags ____cacheline_aligned_in_smp;

    /*
     * flag to indict whether user process sleeps for new records
     */
    uint32_t    sc_waits ____cacheline_aligned_in_smp;

    /*
     * records dropped due to SLOT_RECORD_MAX exceeding
     */
    uint32_t    sc_nexcd ____cacheline_aligned_in_smp;

    /*
     * max size in bytes of user's message payload
     */
    uint32_t    sc_maxsz ____cacheline_aligned_in_smp;

    /*
     * messages stats in bytes
     */
    uint64_t    sc_cpros ____cacheline_aligned_in_smp;
    uint64_t    sc_ccons ____cacheline_aligned_in_smp;
    uint64_t    sc_cdrop ____cacheline_aligned_in_smp;
    uint64_t    sc_cdisc ____cacheline_aligned_in_smp;
};

struct ring_core {
    uint64_t            rc_cpus_map[(RS_NR_CPUS + 63) >> 6]; /* mask bitmap */
    uint32_t            rc_cpus_num;    /* num_possible_cpus() */
    uint32_t            rc_waits;       /* user's waiting */
};

struct ring_mmap {
    struct ring_core    rm_cpus ____cacheline_aligned_in_smp;
    struct slot_core    rm_cores[RS_NR_CPUS] ____cacheline_aligned_in_smp;
};

#define RING_MMAP_BASE(c) PAGE_ALIGN(sizeof(struct ring_head) + sizeof(struct comm_mmap) + \
                                     sizeof(struct comm_work) * (c))
#define RING_MMAP_SIZE PAGE_ALIGN(sizeof(struct ring_mmap))

struct ring_krn {
                                        /* rk_mmap must be the 1st member */
    struct ring_mmap       *rk_mmap;    /* mmap zone, to be shared via mmap */
    struct file            *rk_filp;    /* anonymous memory-mapped file */
    struct proc_dir_entry  *rk_proc;    /* proc entry of HIDS-EntPoint */
    struct task_struct     *rk_task;    /* tast struct of HIDS agent */
    spinlock_t              rk_lock;    /* to sync the handlings of CPU events */
    struct mutex            rk_mutex;   /* mutex to sync filp fd_install */
    struct slot_work        rk_works[RS_NR_CPUS] ____cacheline_aligned_in_smp;
};

#define rs_works            rs_kern.rk_works
#define rs_mmap             rs_kern.rk_mmap

#else /* !__KERNEL__ */

struct ring_usr {
    void                   *ru_mmap;
    struct slot_work        ru_works[RS_NR_CPUS];
    uint32_t                ru_core_id;
};

#define rs_works            rs_user.ru_works
#define rs_mmap             rs_user.ru_mmap
#define rs_core_id          rs_user.ru_core_id

#endif /* __KERNEL__ */

/*
 * structures for communication of offset values
 */

/* offset values of ring_mmap elements */
struct comm_mmap {
    uint32_t            cm_cpus_map;   /* offset from rh_cpus_mmap */
    uint32_t            cm_cpus_num;
    uint32_t            cm_waits;
    uint32_t            cm_eflags;
    uint32_t            cm_cores;
 } __attribute__ ((aligned (8)));

/* offset values of slot_work elements */
struct comm_work {
    uint64_t            cw_start;       /* actual values */
    uint32_t            cw_realsz;
    uint32_t            cw_size;
    uint32_t            cw_mask;
    uint32_t            cw_cpuid;

    uint32_t            cw_ents;        /* offset from cw_start */
    uint32_t            cw_used;
    uint32_t            cw_data;
    uint32_t            cw_head;
    uint32_t            cw_tail;
    uint32_t            cw_waits;
    uint32_t            cw_flags;
    uint32_t            cw_npros;
    uint32_t            cw_ncons;
    uint32_t            cw_ndrop;
    uint32_t            cw_ndisc;
    uint32_t            cw_cpros;
    uint32_t            cw_ccons;
    uint32_t            cw_cdrop;
    uint32_t            cw_cdisc;
    uint32_t            cw_nexcd;
    uint32_t            cw_maxsz;
} __attribute__ ((aligned (8)));

/*
 * common head of ring_slot
 */
struct ring_head {
    uint32_t            rh_magic;       /* magic identifier: 'SRDB' */
    uint32_t            rh_size;        /* size of this structure */
    uint32_t            rh_flags:24;    /* flag bits: not used yet */
    uint32_t            rh_mode:8;      /* flexible or fixed width */

    uint32_t            rh_mmap_fd;     /* anonyumous mmap file */
    uint32_t            rh_cpus_num;    /* actual cpu numbers */
    uint32_t            rh_cpus_max;    /* max cpus could be supoorted, NR_CPUS */
    uint32_t            rh_cpus_mmap;   /* RING_MMAP_BASE: offset in mem-mapped file */
    uint32_t            rh_cpus_size;   /* RING_MMAP_SIZE */
    uint32_t            rh_core_mmap;   /* offset in mmap file, percpu mmap zone */
    uint32_t            rh_core_zone;   /* 1M-aligned zone size */
    uint32_t            rh_core_size;   /* real memory size */
    uint32_t            rh_core_mask;   /* mask of logic slot size */

    uint64_t            rh_dawning;     /* timestamp base: seconds from UTC time
                                           ktime_get_real_seconds() or get_seconds() */
} __attribute__ ((aligned (8)));

#define RING_MODE_FLEX   (0x00)
#define RING_MODE_FIXED  (0x01)

struct ring_slot {

    /*
     * Shared zone (head):
     * 
     * initialized by kernel, readonly to user mode
     */
    struct ring_head    rs_head;

    /*
     * Common zone (mmap): 
     * 
     * mantained by kernel and user respectively, different values for each
     */
    void               *rs_cpus_map;
    uint32_t           *rs_cpus_num;    /* online cpu numbers, last online cpu */
    uint32_t           *rs_waits;       /* user process's waiting for new messages */
    uint32_t           *rs_eflags;      /* extra flags, shared between kernel and user */

    /*
     * Private zone (work):
     * 
     * specific members to kernel & user modes
     */

#ifdef __KERNEL__
    /* kernel mode */
    struct ring_krn     rs_kern;
    wait_queue_head_t   rs_waitq;
#else
    /* user mode */
    struct ring_usr     rs_user;
#endif
};

#define RING_SLOT_MAGIC (0x53524442)  /* 'SRDB' */
#define RS_IS_VALID_RING(rs)  ((rs) && (RING_SLOT_MAGIC == (rs)->rs_head.rh_magic))

struct ring_info {
    struct ring_slot   *ri_ring;
    struct slot_work   *ri_work;
    struct slot_record *ri_record;
    void               *ri_data;
    uint32_t            ri_start;
    uint32_t            ri_size;
    uint16_t            ri_cpu;
    uint16_t            ri_wrapped:1;
    uint16_t            ri_reserved:15;
};


/*
 * CPU-local atomic support routines ...
 */
#if defined(CONFIG_ARM64) && defined(__KERNEL__) &&                         \
    ((__GNUC__ >= 10) || (__GNUC__ == 9 && __GNUC_MINOR__ > 3) ||           \
     (__GNUC__ == 9 && __GNUC_MINOR__ == 3 && __GNUC_PATCHLEVEL__ >= 1))
/*
 * ARMv8.1 LSE (Large System Extension) out-of-line atomics
 *   GCC 9.3.1+: optinal with -moutline-atomics or -mno-outline-atomics
 *   GCC 10.1+:  out-of-line atomics are enabled by default
 * References:
 *   https://lists.linaro.org/pipermail/cross-distro/2020-June/000937.html
 *   https://en.opensuse.org/ARM_architecture_support
 */
#define rs_local_inc(a)             atomic_inc_return((atomic_t *)a)
#define rs_local_dec(a)             atomic_dec_return((atomic_t *)a)
#define rs_local_add(a, v)          atomic_add_return(v, (atomic_t *)a)
#define rs_local_add64(a, v)        atomic64_add_return((u64)(v), (atomic64_t *)a)
#define rs_local_sub(a, v)          atomic_sub_return(v, (atomic_t *)a)
#define rs_local_cmpxchg(a, o, v)   atomic_cmpxchg((atomic_t *)a, o, v)
#elif (__GNUC__ > 4) || (__GNUC__ == 4 && __GNUC_MINOR__ > 1) ||            \
      (__GNUC__ == 4 && __GNUC_MINOR__ == 1 && __GNUC_PATCHLEVEL__ >= 2)
#define rs_local_inc(a)             __sync_add_and_fetch(a, 1)
#define rs_local_dec(a)             __sync_sub_and_fetch(a, 1)
#define rs_local_add(a, v)          __sync_add_and_fetch(a, v)
#define rs_local_add64(a, v)        __sync_add_and_fetch(a, v)
#define rs_local_sub(a, v)          __sync_sub_and_fetch(a, v)
#define rs_local_cmpxchg(a, o, v)   __sync_val_compare_and_swap(a, o, v)
#else
#error "gcc version too low: should be 4.1.2 or newer"
#endif

/*
 * common inline routines for ringslot
 */

static inline int rs_is_ring_flex(struct ring_slot *rs)
{
    return (RING_MODE_FLEX == rs->rs_head.rh_mode);
}

/* to be called by consumer */
static inline int rs_is_slot_empty(struct slot_work *sw)
{
    return (READ_ONCE(*sw->sw_tail) == READ_ONCE(*sw->sw_head));
}

/* to be called by producer */
static inline int rs_is_slot_full(struct slot_work *sw)
{
     return (READ_ONCE(*sw->sw_tail) >=
             READ_ONCE(*sw->sw_head) + sw->sw_size);
}

static inline void rs_show_slot(char *tag, struct slot_work *sw)
{
#ifdef DBG
    RSERROR("%s: work (cpu %d/%d): head=%u tail=%u ents=%u used=%u "
            "data=%u npros=%u ncons=%u dropped=%u discarded=%u\n", 
            tag ? tag : "|->", rs_cpu_id(), sw->sw_cpuid - 1,
            READ_ONCE(*sw->sw_head), READ_ONCE(*sw->sw_tail),
            READ_ONCE(*sw->sw_ents), READ_ONCE(*sw->sw_used),
            READ_ONCE(*sw->sw_data), READ_ONCE(*sw->sw_npros),
            READ_ONCE(*sw->sw_ncons), READ_ONCE(*sw->sw_dropped),
            READ_ONCE(*sw->sw_discarded));
#endif
    return;
    tag = tag;
    sw = sw;
}

static inline void rs_show_record(char *tag, struct slot_record *sr)
{
#ifdef DBG
    RSERROR("%s record: state=%u seq=%u len=%u magic=%c\n", 
            tag ? tag : "|->", SR_STATE(sr->sr_state),
            SR_SEQNO(sr->sr_state), sr->sr_len, sr->sr_magic);
#endif
    return;
    tag = tag;
    sr = sr;
}

/*
 * proc entry for kernel & user modes communication
 */
#ifdef __KERNEL__
# define RS_EP_NODE    "elkeid-endpoint"
#else
# define RS_EP_NODE    "/proc/elkeid-endpoint"
#endif

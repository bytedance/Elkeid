// SPDX-License-Identifier: GPL-2.0

#include "ring.h"
#include "slot.h"

/*
 * globals
 */
struct ring_slot g_rs_ring;
uint32_t g_rs_dbg = D_ERR;

/*
 * ring poll routines
 */
static inline int rs_poll_ring(struct ring_slot *rs)
{
    off_t    off = rs->rs_head.rh_cpus_mmap;
    uint32_t wait = 0;

    off += (off_t)((void *)rs->rs_waits - rs->rs_mmap);
    return pread(rs->rs_head.rh_mmap_fd, &wait, 4, off);
}

/*
 * ringslot support routines
 */

static inline void rs_fini_work_ring(struct ring_slot *rs)
{
    int i;

    for (i = 0; i < (int)rs->rs_head.rh_cpus_num; i++) {
        if (rs->rs_user.ru_works[i].sw_slot)
            munmap(rs->rs_user.ru_works[i].sw_slot,
                   rs->rs_user.ru_works[i].sw_realsz);
        rs->rs_user.ru_works[i].sw_slot = NULL;
    }
    RSDEBUG(D_INFO, "rs_fini_work_ring: slot works cleaned.\n");
}

static inline int rs_verify_mmap(void *ptr, int len)
{
    uint64_t v = 0;
    uint32_t i;
    RSDEBUG(D_INFO, "rs_verify_mmap: verifying %p (%d bytes)\n", ptr, len);
    for (i = 0; i < len / sizeof(uint64_t); i++) {
        v += READ_ONCE(*((uint64_t *)ptr + i));
    }
    RSDEBUG(D_INFO, "rs_verify_mmap: %p (%d bytes) verified.\n", ptr, len);

    return 0;
}

static inline int rs_init_work_ring(struct ring_slot *rs, struct ring_head *comm)
{
    struct comm_mmap *cmap = (struct comm_mmap *)(comm + 1);
    struct comm_work *work = (struct comm_work *)(cmap + 1);
    uint32_t i;

    for (i = 0; i < comm->rh_cpus_num; i++) {
        void *base;
 
        /* map percpu slot to user space */
        base = mmap(0, work[i].cw_realsz, PROT_READ | PROT_WRITE,
                    MAP_SHARED, comm->rh_mmap_fd, work[i].cw_start);
        if (MAP_FAILED == base) {
            RSDEBUG(D_ERR, "rs_init_work_slot: failed to mmap slot for cpu %d with err %d.\n",
                           work[i].cw_cpuid, errno);
            return -ENOMEM;
        }
        rs_verify_mmap(base, work[i].cw_realsz);

        /* initialize slow_work */
        rs->rs_user.ru_works[i].sw_cpuid = work[i].cw_cpuid;
        rs->rs_user.ru_works[i].sw_start = work[i].cw_start;
        rs->rs_user.ru_works[i].sw_realsz = work[i].cw_realsz;
        rs->rs_user.ru_works[i].sw_size = work[i].cw_size;
        rs->rs_user.ru_works[i].sw_mask = work[i].cw_mask;

        /* initialize slot buffer: dont touch it's content */
        rs->rs_user.ru_works[i].sw_slot = base;

        /* initialize slot_work pointers */
        rs->rs_user.ru_works[i].sw_ents = rs->rs_mmap + work[i].cw_ents;
        rs->rs_user.ru_works[i].sw_used = rs->rs_mmap + work[i].cw_used;
        rs->rs_user.ru_works[i].sw_data = rs->rs_mmap + work[i].cw_data;
        rs->rs_user.ru_works[i].sw_head = rs->rs_mmap + work[i].cw_head;
        rs->rs_user.ru_works[i].sw_tail = rs->rs_mmap + work[i].cw_tail;
        rs->rs_user.ru_works[i].sw_waits = rs->rs_mmap + work[i].cw_waits;
        rs->rs_user.ru_works[i].sw_flags = rs->rs_mmap + work[i].cw_flags;
        rs->rs_user.ru_works[i].sw_npros = rs->rs_mmap + work[i].cw_npros;
        rs->rs_user.ru_works[i].sw_ncons = rs->rs_mmap + work[i].cw_ncons;
        rs->rs_user.ru_works[i].sw_ndrop = rs->rs_mmap + work[i].cw_ndrop;
        rs->rs_user.ru_works[i].sw_ndisc = rs->rs_mmap + work[i].cw_ndisc;
        rs->rs_user.ru_works[i].sw_cpros = rs->rs_mmap + work[i].cw_cpros;
        rs->rs_user.ru_works[i].sw_ccons = rs->rs_mmap + work[i].cw_ccons;
        rs->rs_user.ru_works[i].sw_cdrop = rs->rs_mmap + work[i].cw_cdrop;
        rs->rs_user.ru_works[i].sw_cdisc = rs->rs_mmap + work[i].cw_cdisc;
        rs->rs_user.ru_works[i].sw_nexcd = rs->rs_mmap + work[i].cw_nexcd;
        rs->rs_user.ru_works[i].sw_maxsz = rs->rs_mmap + work[i].cw_maxsz;

        RSDEBUG(D_INFO, "rs_init_work_slot: slot work inited for cpu %d.\n",
                        work[i].cw_cpuid);
    }
 
    return 0;
}

static inline void rs_fini_head_ring(struct ring_slot *rs)
{
    if (rs->rs_mmap)
        munmap(rs->rs_mmap, rs->rs_head.rh_cpus_size);
    rs->rs_mmap = NULL;
    RSDEBUG(D_INFO, "rs_fini_head_ring: ring mmap zone cleaned.\n");
    if ((int)rs->rs_head.rh_mmap_fd >= 0)
        close(rs->rs_head.rh_mmap_fd);
    rs->rs_head.rh_mmap_fd = -ENOENT;
    RSDEBUG(D_INFO, "rs_fini_head_ring: anonymous mmap file closed.\n");
    memset(rs, 0, sizeof(struct ring_slot));
}

static inline int rs_init_head_ring(struct ring_slot *rs, struct ring_head *head)
{
    struct comm_mmap *cmap = (struct comm_mmap *)(head + 1);
    void *base;

    /* mmap ring_mmap to user space */
    base = mmap(0, head->rh_cpus_size, PROT_READ | PROT_WRITE,
                MAP_SHARED, head->rh_mmap_fd, head->rh_cpus_mmap);
    if (MAP_FAILED == base) {
        RSDEBUG(D_ERR, "rs_init_head_ring: failed to map ring with err %d\n", errno);
        return -ENOMEM;
    }
    rs_verify_mmap(base, head->rh_cpus_size);

    /* initialize ring_mmap */
    rs->rs_user.ru_mmap = base;
    rs->rs_cpus_map = base + cmap->cm_cpus_map;
    rs->rs_cpus_num = base + cmap->cm_cpus_num;
    rs->rs_waits = base + cmap->cm_waits;
    rs->rs_eflags = base + cmap->cm_eflags;
    RSDEBUG(D_INFO, "rs_init_head_ring: succeeded.\n");
    return 0;
}

static inline void *rs_query_comm(struct ring_slot *rs)
{
    void *comm = NULL, *ptr;
    uint32_t len;
    size_t rc;

    len = rs->rs_head.rh_cpus_mmap;
    if (len <= 0)
        goto errorout;
    comm = malloc(len);
    if (!comm)
        goto errorout;
    rc = read(rs->rs_head.rh_mmap_fd, comm, len);
    if (rc < sizeof(struct ring_head) + sizeof(struct comm_mmap) + 
             sizeof(struct comm_work) * rs->rs_head.rh_cpus_num) {
        RSDEBUG(D_ERR, "rs_query_common: wrong length returned %ld\n", rc);
        goto errorout;
    }
    ptr = realloc(comm, rc);
    if (ptr)
        return ptr;
    return comm;

errorout:
    if (comm)
        free(comm);
    return NULL;
}

static inline int rs_query_head(struct ring_head *rh)
{
    size_t rc = 0;
    
    int fd = open(RS_EP_NODE, O_RDONLY);
    if (fd < 0) {
        RSDEBUG(D_ERR, "rs_query_head: failed to open %s\n", RS_EP_NODE);
        goto errorout;
    }

    rc = read(fd, rh, sizeof(*rh));
    if (rc < sizeof(rh)) {
        RSDEBUG(D_ERR, "rs_query_head: failed to read %s\n", RS_EP_NODE);
        rc = 0;
    }
    RSDEBUG(D_INFO, "rs_query_head: got %ld bytes.\n", rc);
errorout:
    if (fd >=0)
        close(fd);
    return (int)rc;
}

static inline int rs_init_ring_slot(struct ring_slot *rs)
{
    struct ring_head *comm = NULL;
    int rc;

    rc = rs_query_head(&rs->rs_head);
    if (!rc)
        return -EPERM;

    RSDEBUG(D_INFO, "rs_init_ring_slot: head query done.\n");
    if ((int)rs->rs_head.rh_mmap_fd < 0) {
        if ((int)rs->rs_head.rh_mmap_fd == -ENOENT) {
            RSERROR("rs_init_ring_slot: only 1 consumer permitted.\n");
        } else {
            RSERROR("rs_init_ring_slot: invalid mmap fd.\n");
        }
        return -ENOENT;
    }

    RSDEBUG(D_INFO, "rs_init_ring_slot: got mmap fd:%d\n", rs->rs_head.rh_mmap_fd);
    comm = rs_query_comm(rs);
    if (!comm)
        return -ENOMEM;
    if (memcmp(&rs->rs_head, comm, sizeof(struct ring_head))) {
        RSDEBUG(D_ERR, "rs_init_ring_slot: content mistach !\n");
        rc = -EINVAL;
        goto cleanup_comm;
    }
    RSDEBUG(D_INFO, "rs_init_ring_slot: comm query done.\n");

    rc = rs_init_head_ring(rs, comm);
    if (rc)
        goto cleanup_comm;
    RSDEBUG(D_INFO, "rs_init_ring_slot: head ring inited.\n");

    rc = rs_init_work_ring(rs, comm);
    if (rc)
        goto cleanup_work;
    RSDEBUG(D_INFO, "rs_init_ring_slot: work ring inited.\n");

    return 0;

cleanup_work:
    rs_fini_work_ring(rs);
    rs_fini_head_ring(rs);

cleanup_comm:
    if (comm)
        free(comm);
    return rc;
}

static inline void rs_fini_ring_slot(struct ring_slot *rs)
{
    rs_fini_work_ring(rs);
    rs_fini_head_ring(rs);
}

/*
 * routines for consumer (both kernel and user modes are supported)
 */

static inline void *rs_retriev_head(struct ring_info *ri)
{
    struct ring_slot *rs = ri->ri_ring;
    struct slot_work *sw = NULL;
    struct slot_record *sr = NULL;
    uint32_t s1, s2, head, tries = 0;

    /* no grabbing cpu here to be kept identical to user mode */

    /* query slot_work binding to current cpu */
    ri->ri_work = sw = &rs->rs_works[ri->ri_cpu];

    do {
        /* jump out if slot is already empty */
        if (rs_is_slot_empty(sw))
            break;

        head = READ_ONCE(*sw->sw_head);
        RS_CHK(head & SLOT_RECLEN_MASK);
        sr = CORE_POS2REC(sw, head);

        /* RETV:A: make sure local head updated */
        // smp_rmb();
        __sync_synchronize();

        /* do 2nd checking if slot is empty */
        if (rs_is_slot_empty(sw))
            break;

        /*
         * possible ABA issue:
         *
         * head updated by discard_slot:DSCD:F then filled. lucily content
         * is text only, impossible to be identical to the value of state
         * 
         * another solution, change head/tail to 24-bits, due to powerpc's
         * limit of atomic_t implementation. but atomic routines are to be
         * replace by local_t related routines.
         */
        /* RETV:B: */ 
        s1 = head | sr_state_committed;
        s2 = head | sr_state_consuming;
        if (rs_local_cmpxchg(&sr->sr_state, s1, s2) == s1) {
            /* debugging only */
            if (head != READ_ONCE(*sw->sw_head)) {
                dump_stack();
                break;
            }
            RS_CHK(head != READ_ONCE(*sw->sw_head));

            /* RETV:C: */
            ri->ri_start = head;
            ri->ri_record = sr;
            ri->ri_size = SLOT_LEN2REC(sr->sr_len);
            ri->ri_data = CORE_POS2REC(sw, head + sizeof(*sr));
            return ri->ri_data;
        } else if (++tries > 6) {
#if 0
            if ((READ_ONCE(sr->sr_state) & 0xFFFFFFF0) != head &&
                ((READ_ONCE(sr->sr_state) & 15) == sr_state_committed ||
                 (READ_ONCE(sr->sr_state) & 15) == sr_state_consuming))
                printf("head: %x state: %x sw: %x/%x used:%x/%x\n",
                        head,
                        READ_ONCE(sr->sr_state),
                        READ_ONCE(*sw->sw_head),
                        READ_ONCE(*sw->sw_tail),
                        READ_ONCE(*sw->sw_used),
                        READ_ONCE(*sw->sw_data)
                        );
#endif
            break;
        }
    } while(!ri->ri_data);

errorout:
    return NULL;
}

static inline void rs_commit_head(struct ring_info *ri)
{
    struct slot_work *sw = ri->ri_work;
    struct slot_record *sr = ri->ri_record;
    uint32_t head, next, s1, s2, len = sr->sr_len;

    head = ri->ri_start;
    next = head + ri->ri_size;
    RS_CHK(next & SLOT_RECLEN_MASK);
    RS_CHK(head != READ_ONCE(*sw->sw_head));

    /* RETV:E:  */
    /* change state to resuable */
    s1 = head | sr_state_consuming;
    s2 = head | sr_state_reusable;
    if (rs_local_cmpxchg(&sr->sr_state, s1, s2) != s1) {
        /* possible timeout: record as already reverted */
        return;
    }

    /* RETV:F: make sure the record to be reset */
    //kernel: smp_wmb();
    __sync_synchronize();

    /* RETV:G: try to release the record sapce to it's slot */
    if (rs_local_cmpxchg(sw->sw_head, head, next) == head) {
        /* RETV:H: record consumed, so update slow_work */
        WRITE_ONCE(*sw->sw_used, *sw->sw_tail - *sw->sw_head);
        rs_local_sub(sw->sw_data, next - head);
        rs_local_inc(sw->sw_ncons);
        rs_local_add(sw->sw_ccons, len);
        rs_local_dec(sw->sw_ents);
        rs_show_slot("retriev", sw);
    } else {
        /* BUG: shouldn't be here, since we'v locked the record */
        BUG();
    }

errorout:
    return;
}

static inline int rs_read_record(struct ring_info *ri, void *dat, int len)
{
    struct slot_work *sw = ri->ri_work;
    struct slot_record *sr = ri->ri_record;
    void *buf = ri->ri_data;

    RS_CHK(buf < sw->sw_slot || buf >= sw->sw_slot + sw->sw_size);
    if (len  > sr->sr_len)
        len = sr->sr_len;
    if (buf + len > sw->sw_slot + sw->sw_size) {
        int bytes = sw->sw_slot + sw->sw_size - buf;
        if (bytes)
            rs_memcpy(dat, buf, bytes);
        rs_memcpy(dat + bytes, sw->sw_slot, len - bytes);
    } else {
        rs_memcpy(dat, buf, len);
    }
    return len;

errorout:
    return 0;
}

static int rs_read_slot(struct ring_slot *rs, void *msg, int len, int cpu)
{
    struct ring_info ri = {0};
    int rc = 0;

    ri.ri_ring = rs;
    ri.ri_cpu = cpu;
    if (rs_retriev_head(&ri)) {
        rc = rs_read_record(&ri, msg, len);
        rs_commit_head(&ri);
    }

    return rc;
}


/*
 * ring slot support routine to be exported 
 */

static inline int rs_query_cores(void)
{
    return g_rs_ring.rs_head.rh_cpus_num;
}

int rs_init_ring(void)
{
    return rs_init_ring_slot(&g_rs_ring);
}

void rs_fini_ring(void)
{
    rs_fini_ring_slot(&g_rs_ring);
}

/*
 * WARNING: caller can be blocked
 */
int rs_read_ring(char *msg, int len, int (*cb)(int *), int *ctx)
{
    struct ring_slot *rs = &g_rs_ring;
    int rc = 0, i;

    /* required length is valid or not ? */
    if (len <= 0)
        return rc;
    /* msg and callback can NOT be NULL */
    if (!msg || !cb)
        return rc;

    do {
        for (i = 0; !cb(ctx) && i < rs_query_cores(); i++) {
            int cpu = rs->rs_core_id % rs_query_cores();
            rc = rs_read_slot(rs, msg, len, cpu);
            /* switch to next core ASAP in case i's hungry */
            rs->rs_core_id = (cpu + 1) % rs_query_cores();
            if (rc)
                return rc;
        }

        /* now wait and poll since all rings are empty */
        if (i >= rs_query_cores()) {
            RSDEBUG(D_INFO, "waiting for incoming messages ...\n");
            rs_poll_ring(rs);
            RSDEBUG(D_INFO, "got new messages, do processing ...\n");
        }
    } while(!cb(ctx) && !rc);

    return rc;
}

/*
 * statatics support routines
 */

int rs_is_elapsed(struct timeval *tv, long cycle)
{
    struct timeval now;

    gettimeofday(&now, NULL);
    return ((int64_t)now.tv_sec * 1000000UL + now.tv_usec >= 
            (int64_t)tv->tv_sec * 1000000UL + tv->tv_usec + cycle);
}

void rs_query_stat_ring(struct ring_stat *stat)
{
    uint32_t i;

    memset(stat, 0, sizeof(*stat));
    gettimeofday(&stat->tv, NULL);
    for (i = 0; i < g_rs_ring.rs_head.rh_cpus_num; i++) {
        struct slot_work *sw = &g_rs_ring.rs_works[i];
        stat->npros = stat->npros + READ_ONCE(*sw->sw_npros);
        stat->ncons = stat->ncons + READ_ONCE(*sw->sw_ncons);
        stat->ndrop = stat->ndrop + READ_ONCE(*sw->sw_ndrop);
        stat->ndisc = stat->ndisc + READ_ONCE(*sw->sw_ndisc);
        stat->cpros = stat->cpros + READ_ONCE(*sw->sw_cpros);
        stat->ccons = stat->ccons + READ_ONCE(*sw->sw_ccons);
        stat->cdrop = stat->cdrop + READ_ONCE(*sw->sw_cdrop);
        stat->cdisc = stat->cdisc + READ_ONCE(*sw->sw_cdisc);
        stat->nexcd = stat->nexcd + READ_ONCE(*sw->sw_nexcd);
        if (stat->maxsz < READ_ONCE(*sw->sw_maxsz))
            stat->maxsz = READ_ONCE(*sw->sw_maxsz);
    }
}

void rs_show_stat_ring(struct ring_stat *s, struct ring_stat *l, struct ring_stat *n)
{
    double interval, elapsed, i1, i2;
    char  *u1, *u2;

    if (n->npros - l->npros > 1024UL * 1024 * 1024) {
        u1 = "G";
        i1 = 1024.0 * 1024 * 1024;
    } else if (n->npros - l->npros > 1024 * 1024) {
        u1 = "M";
        i1 = 1024.0 * 1024;
    } else if (n->npros - l->npros > 2 * 1024) {
        u1 = "K";
        i1 = 1024.0;
    } else {
        u1 = "n";
        i1 = 1.0;
    }

    if (n->cpros - l->cpros > 1024UL * 1024 * 1024) {
        u2 = "GB";
        i2 = 1024.0 * 1024 * 1024;
    } else if (n->cpros - l->cpros > 1024 * 1024) {
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
        printf("\nCPU cores: %d  \tInterval: %.1fs  \t\tElapsed: %.1fs\t\tExtra-large payload: %u/%u\n",
                g_rs_ring.rs_head.rh_cpus_num, interval, elapsed, n->nexcd, n->maxsz);
    } else {
        printf("\nCPU cores: %d  \tElapsed: %.1f (seconds)\t\tExtra-large payload: %u/%u\n",
                g_rs_ring.rs_head.rh_cpus_num, elapsed, n->nexcd, n->maxsz);
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

    if ((double)(n->npros - l->npros) > interval * 1024UL * 1024 * 1024) {
        u1 = "G";
        i1 = 1024.0 * 1024 * 1024;
    } else if ((double)(n->npros - l->npros) > interval * 1024 * 1024) {
        u1 = "M";
        i1 = 1024.0 * 1024;
    } else if ((double)(n->npros - l->npros) > interval * 2 * 1024) {
        u1 = "K";
        i1 = 1024.0;
    } else {
        u1 = "n";
        i1 = 1.0;
    }

    if ((double)(n->cpros - l->cpros) > interval * 1024UL * 1024 * 1024) {
        u2 = "GB";
        i2 = 1024.0 * 1024 * 1024;
    } else if ((double)(n->cpros - l->cpros) > interval * 1024 * 1024) {
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

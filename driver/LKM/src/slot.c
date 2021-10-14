// SPDX-License-Identifier: GPL-2.0

#include "ring.h"
#include "slot.h"

static inline uint32_t rs_reset_core(struct ring_slot *rs, int cpu)
{
    unsigned long   irq;
    uint32_t        rc;

    /* disable interrupts (preemption & scheduling) */
    local_irq_save(irq);

    /* reset slot_core */
    if (cpu == rs_cpu_id())
        memset(&rs->rs_mmap->rm_cores[cpu], 0, sizeof(struct slot_core));
    rc = rs_local_inc(&rs->rs_kern.rk_works[cpu].sw_resets);

    local_irq_restore(irq);

    return rc;
}

/*
 * common inline routines for ringslot
 */
static inline void rs_init_record(struct ring_slot *rs, struct slot_work *sw,
                                  struct slot_record *sr, uint32_t start,
                                  uint32_t size)
{
    /* init record header */
    WRITE_ONCE(sr->sr_state, start | sr_state_reserved);
    sr->sr_time = rs_get_seconds() - rs->rs_head.rh_dawning;
    sr->sr_len = size;
    sr->sr_magic = SLOT_RECORD_MAGIC;
    sr->sr_flags = 0;
    sr->sr_irq = rs_query_irql();
    sr->sr_pid = current->pid;
    if (sizeof(*sr) + size + (start & sw->sw_mask) > sw->sw_size)
        sr->sr_flags |= SLOT_RECORD_FLAG_WRAPPED;

    RS_CHK(start & sr_state_mask);
}

static inline void rs_clear_record(struct slot_work *sw, void *data, int len)
{
    if (unlikely(data + len > sw->sw_slot + sw->sw_size)) {
        int bytes = (int)(sw->sw_slot + sw->sw_size - data);
        if (bytes)
            rs_memset(data, 0, bytes);
        rs_memset(sw->sw_slot, 0, len - bytes);
    } else {
        rs_memset(data, 0, len);
    }
}

/*
 * routines for kernel producer
 */

static inline int rs_discard_slot(struct ring_slot *rs, struct slot_work *sw)
{
    struct slot_record *sr;
    uint32_t head, next, len;
    int rc = 0;

#if 0
    /* avoid discarding in context of irq/softirq */
    if (rs_query_irql())
        return rc;
#endif

    /*
     * TODO: detailed consideration & explanation of all the possible races
     * against rs_discard_slot re-entry and rs_retriev_head & rs_commit_head
     */

retry:

    /* DSCD:A: slot is empty: something seems wrong if so */
    if (rs_is_slot_empty(sw))
        return rc;

    /* DSCD:B: locating current head record */
    head = READ_ONCE(*sw->sw_head);
    RS_CHK(head & SLOT_RECLEN_MASK);
    sr = (struct slot_record *)CORE_POS2REC(sw, head);
    len = sr->sr_len;
    /* seems this record was just consumed */
    if (unlikely(SLOT_RECORD_MAGIC != sr->sr_magic || !len || len > SLOT_RECLEN_MAX)) {
        rs_show_record("discard", sr);
        return rc;
    }
    next = head + SLOT_LEN2REC(len);
    RS_CHK(next - head >  SLOT_LEN2REC(SLOT_RECLEN_MAX));

    /* do 2nd checking: after local head updated */
    if (rs_is_slot_empty(sw))
        return rc;

    /* mark this record as reusable if applicable */
    if (likely((head | sr_state_committed) == READ_ONCE(sr->sr_state))) {
        uint32_t s1 = head|sr_state_committed, s2 = head|sr_state_reusable;
        /* DSCD:C: change state: committed -> resuable */
        if (rs_local_cmpxchg(&sr->sr_state, s1, s2) == s1) {
            /* DSCD:E: now revoke the reusable record from slot head */
            /* make sure record was reset bofore updating head */
            smp_wmb();
            RS_CHK(head != READ_ONCE(*sw->sw_head));
            RS_CHK((head | sr_state_reusable) != READ_ONCE(sr->sr_state));
            RS_CHK(SLOT_RECORD_MAGIC != sr->sr_magic);
            /* DSCD:F: update head to next, leaving record as usable */
            if (rs_local_cmpxchg(sw->sw_head, head, next) == head) {
                WRITE_ONCE(*sw->sw_used, *sw->sw_tail - *sw->sw_head);
                rs_local_sub(sw->sw_data, next - head);
                rc++; 
                rs_local_dec(sw->sw_ents);
                rs_local_inc(sw->sw_ndisc);
                rs_local_add64(sw->sw_cdisc, len);
                rs_show_slot("discard", sw);
            } else {
                BUG();
            }
        }
    } else if (unlikely((head | sr_state_consuming) == READ_ONCE(sr->sr_state))) {
        /* the user mode consumer likely quit unexpectedly: 10s timeout */
        if (rs_get_seconds() > rs->rs_head.rh_dawning + sr->sr_time + 10) {
            uint32_t s1 = head|sr_state_consuming, s2 = head|sr_state_committed;
            if (SLOT_RECORD_MAGIC == sr->sr_magic && !sr->sr_len) {
                if (rs_local_cmpxchg(&sr->sr_state, s1, s2) == s1) {
                    RSERROR("rs_discard_slot: consuming record reverted.\n");
                    goto retry;
                }
            }
        }
    }

    return rc;
}

static inline int rs_is_slot_ample(struct slot_work *sw, uint32_t size, uint32_t tail)
{
    if (size > SLOT_RECLEN_MAX + sizeof(struct slot_record))
        return 0;

    return ((uint32_t)(tail - READ_ONCE(*sw->sw_head) + size) <= sw->sw_size);
}

static inline void *rs_reserve_tail(struct ring_info *ri, int len)
{
    struct ring_slot *rs = ri->ri_ring;
    struct slot_work *sw = NULL;
    struct slot_record *sr = NULL;
    uint32_t tail, next;

    /* grab cpu to avoid preemption & scheduling */
    rs_get_cpu();

    /* query slot_work binding to current cpu */
    ri->ri_cpu = rs_cpu_id();
    ri->ri_work = sw = &rs->rs_works[ri->ri_cpu];
    ri->ri_size = ALIGN(len + sizeof(struct slot_record), SLOT_RECLEN_UNIT);
    rs_local_inc(sw->sw_npros);
    rs_local_add64(sw->sw_cpros, len);

    do {
        /*
         * RESV:A: must read tail first, before RESV:C
         * 
         * in case of re-entrance, tail will be updted anyway, so
         * RESV:C will fail, then will re-try to fetch latest tail
         */
        tail = READ_ONCE(*sw->sw_tail);
        RS_CHK(tail & SLOT_RECLEN_MASK);
        next = tail + ri->ri_size;

        /* RESV:B: make sure local tail to be updated before RESV:D */
        smp_rmb();

        /* RESV:C: */
        if (likely(rs_is_slot_ample(sw, ri->ri_size, tail))) {
            /* RESV:D: try to reserve space from the slot */
            if (rs_local_cmpxchg(sw->sw_tail, tail, next) == tail) {
                WRITE_ONCE(*sw->sw_used, *sw->sw_tail - *sw->sw_head);
                /* record reserved: we're now owner of the record */
                /* now fill record header, it's safe to write */
                sr = CORE_POS2REC(sw, tail);
                rs_init_record(rs, sw, sr, tail, len);
                ri->ri_record = sr;
                ri->ri_data = CORE_POS2REC(sw, tail + sizeof(*sr));
#if 0
                /* disabled: in concern of performance & cpu usage */
                rs_clear_record(sw, ri->ri_data, ri->ri_size - 
                                sizeof(struct slot_record));
#endif
                return ri->ri_data;
            }        
        } else {
            /* just quit if it's exceeding maximum record size */
            if (ri->ri_size > SLOT_RECORD_MAX) {
                if (len > READ_ONCE(*sw->sw_maxsz))
                    WRITE_ONCE(*sw->sw_maxsz, len);
                rs_local_inc(sw->sw_nexcd);
                break;
            /* try to discard header records for overwriting */
            } else if (rs_discard_slot(rs, sw)) {
                /* the oldest record discarded, so continue */
            } else {
                /* give it another try */
                if (!rs_is_slot_ample(sw, ri->ri_size,
                                      READ_ONCE(*sw->sw_tail)))
                    break;
            }
        }
    } while (!sr);

    rs_local_inc(sw->sw_ndrop);
    rs_local_add64(sw->sw_cdrop, len);
    rs_put_cpu();
    return sr;
}

static inline void rs_commit_tail(struct ring_info *ri)
{
    struct slot_work *sw = ri->ri_work;
    struct slot_record *sr = ri->ri_record;

    uint32_t state = READ_ONCE(sr->sr_state);
    state |= sr_state_committed;

    /* RESV:E: make sure all writings to record have finished */
    smp_wmb();

    /* RESV:F: it's safe to mark record ready for consuming */
    WRITE_ONCE(sr->sr_state, state);

    /* update statistic numbers */
    rs_local_add(sw->sw_data, ri->ri_size);
    rs_local_inc(sw->sw_ents);
    rs_show_slot("reserve", sw);

    rs_put_cpu();
    return;
}

int rs_write_record(struct ring_info *ri, void *dat, int len)
{
    struct ring_slot *rs = ri->ri_ring;
    struct slot_work *sw = ri->ri_work;
    struct slot_record *sr = ri->ri_record;
    void *buf = ri->ri_data;

    if (unlikely(((void *)sr < sw->sw_slot) ||
                 ((void *)sr >= sw->sw_slot + sw->sw_size))) {
        dump_stack();
    }

    RS_CHK( ((void *)sr < sw->sw_slot) ||
            ((void *)sr >= sw->sw_slot + sw->sw_size) );
    if (len + sizeof(*sr) > SLOT_LEN2REC(sr->sr_len))
        len = SLOT_LEN2REC(sr->sr_len) - sizeof(*sr);
    if (unlikely(buf + len > sw->sw_slot + sw->sw_size)) {
        int bytes = (int)(sw->sw_slot + sw->sw_size - buf);
        if (bytes)
            rs_memcpy(buf, dat, bytes);
        rs_memcpy(sw->sw_slot, dat + bytes, len - bytes);
        RS_CHK(0 == (sr->sr_flags & SLOT_RECORD_FLAG_WRAPPED));
    } else {
        rs_memcpy(buf, dat, len);
    }
    return len;
}

int rs_write_slot(struct ring_slot *rs, void *msg, int len)
{
    struct ring_info ri = {0};
    int rc = 0, res = len;

    /* using max record as len for fiexed mode */
    if (!rs_is_ring_flex(rs)) {
        res = SLOT_RECLEN_MAX;
        if (len > res - 1)
            len = res - 1;
    }

    /* trying to allocate space from ringslot */
    ri.ri_ring = rs;
    if (likely(rs_reserve_tail(&ri, res))) {
        rc = rs_write_record(&ri, msg, len);
        rs_commit_tail(&ri);
    }

    return rc;
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

    /* grabbing cpu to aboid unexpected abort */
    rs_get_cpu();

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
        smp_rmb();

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
            break;
        }
    } while(!ri->ri_data);

    rs_put_cpu();
    return NULL;
}

static inline void rs_commit_head(struct ring_info *ri)
{
    struct ring_slot *rs = ri->ri_ring;
    struct slot_work *sw = ri->ri_work;
    struct slot_record *sr = ri->ri_record;
    uint32_t head, next, len = sr->sr_len;

    head = ri->ri_start;
    next = head + ri->ri_size;
    RS_CHK(next & SLOT_RECLEN_MASK);
    RS_CHK(head != READ_ONCE(*sw->sw_head));

    /* RETV:E:  */
    /* change state to resuable */
    WRITE_ONCE(sr->sr_state, head | sr_state_reusable);
 
     /* RETV:F: make sure the record to be reset */
    smp_wmb();

    /* RETV:G: try to release the record sapce to it's slot */
    if (rs_local_cmpxchg(sw->sw_head, head, next) == head) {
        /* RETV:H: record consumed, so update slow_work */
        WRITE_ONCE(*sw->sw_used, *sw->sw_tail - *sw->sw_head);
        rs_local_sub(sw->sw_data, next - head);
        rs_local_inc(sw->sw_ncons);
        rs_local_dec(sw->sw_ents);
        rs_local_add64(sw->sw_ccons, len);
        rs_show_slot("retriev", sw);
    } else {
        /* BUG: shouldn't be here, since we'v locked the record */
        BUG();
    }

    rs_put_cpu();
    return;
}

int rs_read_record(struct ring_info *ri, void *dat, int len)
{
    struct ring_slot *rs = ri->ri_ring;
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
        RS_CHK(0 == (sr->sr_flags & SLOT_RECORD_FLAG_WRAPPED));
    } else {
        rs_memcpy(dat, buf, len);
    }
    return len;
}

int rs_read_slot(struct ring_slot *rs, void *msg, int len, int cpu)
{
    struct ring_info ri = {0};
    int rc = 0;

    ri.ri_ring = rs;
    ri.ri_cpu = (uint32_t)cpu & ((RS_NR_CPUS) - 1);
    if (rs_retriev_head(&ri)) {
        rc = rs_read_record(&ri, msg, len);
        rs_commit_head(&ri);
    }

    return rc;
}

static int rs_compute_format(struct ring_slot *rs, const char *fmt, va_list args)
{
    va_list va;
    struct slot_work *sw;
    void *text;
    int rc = 0;

    va_copy(va, args);
    /* grab cpu to avoid preemption & scheduling */
    rs_get_cpu();

    /* query slot_work binding to current cpu */
    sw = &rs->rs_works[rs_cpu_id()];
    if (unlikely(!sw->sw_slot))
        goto errorout;
    text = sw->sw_slot + sw->sw_size + SLOT_RECORD_MAX;
    rc = vscnprintf(text, SLOT_RECLEN_MAX - 1, fmt, va);
    if (likely(rc))
        rc++;

errorout:
    rs_put_cpu();
    va_end(va);
    return rc;
}

static inline void rs_process_overflow(struct slot_work *sw, void *data, int rc)
{
    int wr = (int)(sw->sw_slot + sw->sw_size - data);

    if (likely(rc < wr)) {
        ((char *)data)[rc] = 0;
    } else if (rc > wr) {
        rs_memcpy(sw->sw_slot, sw->sw_slot + sw->sw_size, rc - wr);
        ((char *)sw->sw_slot)[rc - wr] = 0;
    }
}

int rs_vsprint_slot(struct ring_slot *rs, const char *fmt, va_list args)
{
    struct ring_info ri = {0};
    int rc = 0, len;

    /* computing the length of output string */
    if (rs_is_ring_flex(rs))
        len = rs_compute_format(rs, fmt, args);
    else
        len = SLOT_RECLEN_MAX;
    if (unlikely(!len))
        goto errorout;

    /* trying to reprint to */
    ri.ri_ring = rs;
    if (likely(rs_reserve_tail(&ri, len))) {
        len = ri.ri_size - sizeof(struct slot_record);
        rc = vscnprintf(ri.ri_data, len, fmt, args);
        rs_process_overflow(ri.ri_work, ri.ri_data, rc);
        rs_commit_tail(&ri);
    }

errorout:
	return rc;
}

/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_TRACE_RING_BUFFER_H_
#define _LINUX_TRACE_RING_BUFFER_H_

#ifdef __KERNEL__

#include <linux/types.h>
#include <linux/version.h>
#include <linux/spinlock.h>
#include <linux/mutex.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <asm/local.h>

/*
 * Workaround for ringbuffer back-porting
 */

#ifndef __GFP_RETRY_MAYFAIL
#define __GFP_RETRY_MAYFAIL		(0)
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 33)
#define __ARCH_SPIN_LOCK_UNLOCKED __RAW_SPIN_LOCK_UNLOCKED
#define arch_spinlock_t raw_spinlock_t
#define arch_spin_lock  __raw_spin_lock
#define arch_spin_unlock __raw_spin_unlock
#define raw_spin_trylock __raw_spin_trylock
#define raw_spin_lock  __raw_spin_lock
#define raw_spin_unlock __raw_spin_unlock
#define raw_spin_lock_init(x) ((x)->slock = 0)
#define raw_spin_lock_irq __raw_spin_lock
#define raw_spin_unlock_irq __raw_spin_unlock
#define raw_spin_lock_irqsave(l, f) do {(f) = 0; __raw_spin_lock(l);} while(0)
#define raw_spin_unlock_irqrestore(l, f) do {__raw_spin_unlock(l);} while(0)
#endif

struct tb_ring;
struct tb_iter;

/*
 * Don't refer to this struct directly, use functions below.
 */
struct tb_event {
	u32		type_len:5, time_delta:27;

	u32		array[];
};

/**
 * enum tb_type - internal ring buffer types
 *
 * @TB_TYPEPADDING:	Left over page padding or discarded event
 *				 If time_delta is 0:
 *				  array is ignored
 *				  size is variable depending on how much
 *				  padding is needed
 *				 If time_delta is non zero:
 *				  array[0] holds the actual length
 *				  size = 4 + length (bytes)
 *
 * @TB_TYPETIME_EXTEND:	Extend the time delta
 *				 array[0] = time delta (28 .. 59)
 *				 size = 8 bytes
 *
 * @TB_TYPETIME_STAMP:	Absolute timestamp
 *				 Same format as TIME_EXTEND except that the
 *				 value is an absolute timestamp, not a delta
 *				 event.time_delta contains bottom 27 bits
 *				 array[0] = top (28 .. 59) bits
 *				 size = 8 bytes
 *
 * <= @TB_TYPEDATA_TYPE_LEN_MAX:
 *				Data record
 *				 If type_len is zero:
 *				  array[0] holds the actual length
 *				  array[1..(length+3)/4] holds data
 *				  size = 4 + length (bytes)
 *				 else
 *				  length = type_len << 2
 *				  array[0..(length+3)/4-1] holds data
 *				  size = 4 + length (bytes)
 */
enum tb_type {
	TB_TYPEDATA_TYPE_LEN_MAX = 28,
	TB_TYPEPADDING,
	TB_TYPETIME_EXTEND,
	TB_TYPETIME_STAMP,
};

enum tb_flags {
	TB_FL_OVERWRITE		= 1 << 0,
};

#define TB_RING_ALL_CPUS -1

/*
 * size is in bytes for each per CPU buffer.
 */
struct tb_ring *
__tb_alloc(unsigned long size, unsigned flags, struct lock_class_key *key);

/*
 * Because the ring buffer is generic, if other users of the ring buffer get
 * traced by ftrace, it can produce lockdep warnings. We need to keep each
 * ring buffer's lock class separate.
 */
#define tb_alloc(size, flags)			\
({							\
	static struct lock_class_key __key;		\
	__tb_alloc((size), (flags), &__key);	\
})

int tb_wait(struct tb_ring *ring, int cpu, int full);
void tb_free(struct tb_ring *ring);

struct tb_event *
tb_peek(struct tb_ring *ring, int cpu, u64 *ts,
		 unsigned long *lost_events);
struct tb_event *
tb_consume(struct tb_ring *ring, int cpu, u64 *ts,
		    unsigned long *lost_events);

unsigned tb_event_size(struct tb_event *event);
void *tb_event_data(struct tb_event *event);
unsigned tb_event_data_length(struct tb_event *event);
u64 tb_event_timestamp(struct tb_ring *ring,
				 struct tb_event *event);

struct tb_event *tb_lock_reserve(struct tb_ring *ring,
						   unsigned long length);
int tb_unlock_commit(struct tb_ring *ring,
			      struct tb_event *event);
int tb_write(struct tb_ring *ring,
		      unsigned long length, void *data);

/*
 * tb_discard_commit will remove an event that has not
 *   been committed yet. If this is used, then tb_unlock_commit
 *   must not be called on the discarded event. This function
 *   will try to remove the event from the ring buffer completely
 *   if another event has not been written after it.
 *
 * Example use:
 *
 *  if (some_condition)
 *    tb_discard_commit(buffer, event);
 *  else
 *    tb_unlock_commit(buffer, event);
 */
void tb_discard_commit(struct tb_ring *ring,
				struct tb_event *event);


bool tb_empty(struct tb_ring *ring);
bool tb_empty_cpu(struct tb_ring *ring, int cpu);

void tb_record_disable(struct tb_ring *ring);
void tb_record_enable(struct tb_ring *ring);
void tb_record_off(struct tb_ring *ring);
void tb_record_on(struct tb_ring *ring);
bool tb_record_is_on(struct tb_ring *ring);
bool tb_record_is_set_on(struct tb_ring *ring);
void tb_record_disable_cpu(struct tb_ring *ring, int cpu);
void tb_record_enable_cpu(struct tb_ring *ring, int cpu);

u64 tb_oldest_event_ts(struct tb_ring *ring, int cpu);
unsigned long tb_bytes_cpu(struct tb_ring *ring, int cpu);
unsigned long tb_entries(struct tb_ring *ring);
unsigned long tb_overruns(struct tb_ring *ring);
unsigned long tb_entries_cpu(struct tb_ring *ring, int cpu);
unsigned long tb_overrun_cpu(struct tb_ring *ring, int cpu);
unsigned long tb_commit_overrun_cpu(struct tb_ring *ring, int cpu);
unsigned long tb_dropped_events_cpu(struct tb_ring *ring, int cpu);
unsigned long tb_read_events_cpu(struct tb_ring *ring, int cpu);

unsigned long tb_size(struct tb_ring *ring, int cpu);
size_t tb_nr_pages(struct tb_ring *ring, int cpu);
size_t tb_nr_dirty_pages(struct tb_ring *ring, int cpu);

void tb_change_overwrite(struct tb_ring *ring, int val);

struct tb_iter *
tb_read_prepare(struct tb_ring *ring, int cpu, gfp_t flags);
void tb_read_prepare_sync(void);
void tb_read_start(struct tb_iter *iter);
void tb_read_finish(struct tb_iter *iter);

u64 tb_time_stamp(struct tb_ring *ring);
void tb_set_time_stamp_abs(struct tb_ring *ring, bool abs);
bool tb_time_stamp_abs(struct tb_ring *ring);

struct tb_stat;
void tb_stat(struct tb_ring *ring, struct tb_stat *stat);

#else /* !__KERNEL__ */

#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <errno.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <signal.h>
#include <time.h>
#include <sys/time.h>
#include <sys/types.h>

#define u64 uint64_t
#define u32 uint32_t

#endif /* __KERNEL__ */

/*
 * common defintions for both kernel and user modes
 */

struct tb_stat {
	u32				num_cpu_rings;		/* num of valid cpu_rings */
	u32				overwritable:1;		/* flag: overwritable */
	u32				flags:31;

	u64				produced_events;	/* total produced events */
	u64				rejected_events;	/* number of rejected events */
	u64				discarded_events;	/* events dicarded by producer */
	u64				dropped_events;		/* number of dropped events */
	u64				overwritten_events;	/* number of overwritten events */
	u64				consumed_events;	/* consumed by user */

	u64				produced_size;		/* sum of all below sizes */
	u64				rejected_size;		/* too large to fit BUF_SIZE */
	u64				discarded_size;		/* manually abandoned by producer */
	u64				dropped_size; 		/* discarded due to rb is full (non overwritable) */
	u64				overwritten_size;	/* overwritten if rb is full (overwritable)*/
	u64				consumed_size;		/* read by consumer */
	u32				max_event_size;		/* max event size */
};

#endif /* _LINUX_TRACE_RING_BUFFER_H_ */

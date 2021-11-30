// SPDX-License-Identifier: GPL-2.0
/*
 * Generic ring buffer
 *
 * Copyright (C) 2008 Steven Rostedt <srostedt@redhat.com>
 */
#include <linux/types.h>
#include <linux/version.h>
#include <linux/spinlock.h>
#include <linux/security.h>
#include <linux/uaccess.h>
#include <linux/hardirq.h>
#include <linux/module.h>
#include <linux/percpu.h>
#include <linux/mutex.h>
#include <linux/delay.h>
#include <linux/slab.h>
#include <linux/init.h>
#include <linux/hash.h>
#include <linux/list.h>
#include <linux/cpu.h>
#include <linux/oom.h>
#include <linux/kernel.h>

#include "../include/trace_buffer.h"

/* kernel has READ_ONCE defined since 3.18.13 */
#ifndef READ_ONCE
#define READ_ONCE(var) (*((volatile typeof(var) *)(&(var))))
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 35)
/* sched_clock not export for kernels below 2.6.35 */
#define tb_sched_clock	(((u64)jiffies - INITIAL_JIFFIES) * (NSEC_PER_SEC / HZ))
#else
extern u64 sched_clock(void);
#define tb_sched_clock sched_clock()
#endif

static u64 tb_clock_local(void)
{
	u64 clock;

	/*
	 * sched_clock() is an architecture implemented, fast, scalable,
	 * lockless clock. It is not guaranteed to be coherent across
	 * CPUs, nor across CPU idle events.
	 */
	preempt_disable_notrace();
	clock = tb_sched_clock;
	preempt_enable_notrace();

	return clock;
}

static void tb_update_pages_handler(struct work_struct *work);

/*
 * The ring buffer is made up of a list of pages. A separate list of pages is
 * allocated for each CPU. A writer may only write to a buffer that is
 * associated with the CPU it is currently executing on.  A reader may read
 * from any per cpu buffer.
 *
 * The reader is special. For each per cpu buffer, the reader has its own
 * reader page. When a reader has read the entire reader page, this reader
 * page is swapped with another page in the ring buffer.
 *
 * Now, as long as the writer is off the reader page, the reader can do what
 * ever it wants with that page. The writer will never write to that page
 * again (as long as it is out of the ring buffer).
 *
 * Here's some silly ASCII art.
 *
 *   +------+
 *   |reader|          RING BUFFER
 *   |page  |
 *   +------+        +---+   +---+   +---+
 *                   |   |-->|   |-->|   |
 *                   +---+   +---+   +---+
 *                     ^               |
 *                     |               |
 *                     +---------------+
 *
 *
 *   +------+
 *   |reader|          RING BUFFER
 *   |page  |------------------v
 *   +------+        +---+   +---+   +---+
 *                   |   |-->|   |-->|   |
 *                   +---+   +---+   +---+
 *                     ^               |
 *                     |               |
 *                     +---------------+
 *
 *
 *   +------+
 *   |reader|          RING BUFFER
 *   |page  |------------------v
 *   +------+        +---+   +---+   +---+
 *      ^            |   |-->|   |-->|   |
 *      |            +---+   +---+   +---+
 *      |                              |
 *      |                              |
 *      +------------------------------+
 *
 *
 *   +------+
 *   |buffer|          RING BUFFER
 *   |page  |------------------v
 *   +------+        +---+   +---+   +---+
 *      ^            |   |   |   |-->|   |
 *      |   New      +---+   +---+   +---+
 *      |  Reader------^               |
 *      |   page                       |
 *      +------------------------------+
 *
 *
 * After we make this swap, the reader can hand this page off to the splice
 * code and be done with it. It can even allocate a new page if it needs to
 * and swap that into the ring buffer.
 *
 * We will be using cmpxchg soon to make all this lockless.
 *
 */

/* Used for individual buffers (after the counter) */
#define RB_BUFFER_OFF		(1 << 20)

#define BUF_PAGE_HDR_SIZE offsetof(struct buffer_data_page, data)

#define RB_EVNT_HDR_SIZE (offsetof(struct tb_event, array))
#define RB_ALIGNMENT		4U
#define RB_MAX_SMALL_DATA	(RB_ALIGNMENT * TB_TYPEDATA_TYPE_LEN_MAX)
#define RB_EVNT_MIN_SIZE	8U	/* two 32bit words */

#ifndef CONFIG_HAVE_64BIT_ALIGNED_ACCESS
# define RB_FORCE_8BYTE_ALIGNMENT	0
# define RB_ARCH_ALIGNMENT		RB_ALIGNMENT
#else
# define RB_FORCE_8BYTE_ALIGNMENT	1
# define RB_ARCH_ALIGNMENT		8U
#endif

#define RB_ALIGN_DATA		__aligned(RB_ARCH_ALIGNMENT)

/* define TB_TYPEDATA for 'case TB_TYPEDATA:' */
#define TB_TYPEDATA 0 ... TB_TYPEDATA_TYPE_LEN_MAX

enum {
	RB_LEN_TIME_EXTEND = 8,
	RB_LEN_TIME_STAMP =  8,
};

#define skip_time_extend(event) \
	((struct tb_event *)((char *)event + RB_LEN_TIME_EXTEND))

#define extended_time(event) \
	(event->type_len >= TB_TYPETIME_EXTEND)

static inline int tb_null_event(struct tb_event *event)
{
	return event->type_len == TB_TYPEPADDING && !event->time_delta;
}

static void tb_event_set_padding(struct tb_event *event)
{
	/* padding has a NULL time_delta */
	event->type_len = TB_TYPEPADDING;
	event->time_delta = 0;
}

unsigned tb_event_data_length(struct tb_event *event)
{
	unsigned length;

	if (event->type_len)
		length = event->type_len * RB_ALIGNMENT;
	else
		length = event->array[0];
	return length + RB_EVNT_HDR_SIZE;
}

/*
 * Return the length of the given event. Will return
 * the length of the time extend if the event is a
 * time extend.
 */
inline unsigned tb_event_length(struct tb_event *event)
{
	switch (event->type_len) {
	case TB_TYPEPADDING:
		if (tb_null_event(event))
			/* undefined */
			return -1;
		return  event->array[0] + RB_EVNT_HDR_SIZE;

	case TB_TYPETIME_EXTEND:
		return RB_LEN_TIME_EXTEND;

	case TB_TYPETIME_STAMP:
		return RB_LEN_TIME_STAMP;

	case TB_TYPEDATA:
		return tb_event_data_length(event);
	default:
		WARN_ON_ONCE(1);
	}
	/* not hit */
	return 0;
}

/*
 * Return total length of time extend and data,
 *   or just the event length for all other events.
 */
static inline unsigned
tb_event_ts_length(struct tb_event *event)
{
	unsigned len = 0;

	if (extended_time(event)) {
		/* time extends include the data event after it */
		len = RB_LEN_TIME_EXTEND;
		event = skip_time_extend(event);
	}
	return len + tb_event_length(event);
}

/**
 * tb_event_size - return the length of the event
 * @event: the event to get the length of
 *
 * Returns the size of the data load of a data event.
 * If the event is something other than a data event, it
 * returns the size of the event itself. With the exception
 * of a TIME EXTEND, where it still returns the size of the
 * data load of the data event after it.
 */
unsigned tb_event_size(struct tb_event *event)
{
	unsigned length;

	if (extended_time(event))
		event = skip_time_extend(event);

	length = tb_event_length(event);
	if (event->type_len > TB_TYPEDATA_TYPE_LEN_MAX)
		return length;
	length -= RB_EVNT_HDR_SIZE;
	if (length > RB_MAX_SMALL_DATA + sizeof(event->array[0]))
                length -= sizeof(event->array[0]);
	return length;
}

/* inline for ring buffer fast paths */
static __always_inline void *
tb_event_data_start(struct tb_event *event)
{
	if (extended_time(event))
		event = skip_time_extend(event);
	WARN_ON_ONCE(event->type_len > TB_TYPEDATA_TYPE_LEN_MAX);
	/* If length is in len field, then array[0] has the data */
	if (event->type_len)
		return (void *)&event->array[0];
	/* Otherwise length is in array[0] and array[1] has the data */
	return (void *)&event->array[1];
}

/**
 * tb_event_data - return the data of the event
 * @event: the event to get the data from
 */
void *tb_event_data(struct tb_event *event)
{
	return tb_event_data_start(event);
}

#define for_each_buffer_cpu(buffer, cpu)		\
	for_each_cpu(cpu, buffer->cpumask)

#define for_each_online_buffer_cpu(buffer, cpu)		\
	for_each_cpu_and(cpu, buffer->cpumask, cpu_online_mask)

#define TS_SHIFT	27
#define TS_MASK		((1ULL << TS_SHIFT) - 1)
#define TS_DELTA_TEST	(~TS_MASK)

static u64 tb_event_time_stamp(struct tb_event *event)
{
	u64 ts;

	ts = event->array[0];
	ts <<= TS_SHIFT;
	ts += event->time_delta;

	return ts;
}

/* Flag when events were overwritten */
#define RB_MISSED_EVENTS	(1 << 31)
/* Missed count stored at end */
#define RB_MISSED_STORED	(1 << 30)

struct buffer_data_page {
	u64		 time_stamp;	/* page time stamp */
	local_t		 commit;	/* write committed index */
	unsigned char	 data[] RB_ALIGN_DATA;	/* data of buffer page */
};

/*
 * Note, the buffer_page list must be first. The buffer pages
 * are allocated in cache lines, which means that each buffer
 * page will be at the beginning of a cache line, and thus
 * the least significant bits will be zero. We use this to
 * add flags in the list struct pointers, to make the ring buffer
 * lockless.
 */
struct buffer_page {
	struct list_head list;		/* list of buffer pages */
	local_t		 write;		/* index for next write */
	unsigned	 read;		/* index for next read */
	local_t		 entries;	/* entries on this page */
	unsigned long	 real_end;	/* real end of data */
	struct buffer_data_page *page;	/* Actual data page */
};

/*
 * The buffer page counters, write and entries, must be reset
 * atomically when crossing page boundaries. To synchronize this
 * update, two counters are inserted into the number. One is
 * the actual counter for the write position or count on the page.
 *
 * The other is a counter of updaters. Before an update happens
 * the update partition of the counter is incremented. This will
 * allow the updater to update the counter atomically.
 *
 * The counter is 20 bits, and the state data is 12.
 */
#define RB_WRITE_MASK		0xfffff
#define RB_WRITE_INTCNT		(1 << 20)

static void tb_init_page(struct buffer_data_page *bpage)
{
	local_set(&bpage->commit, 0);
}

/*
 * Also stolen from mm/slob.c. Thanks to Mathieu Desnoyers for pointing
 * this issue out.
 */
static void free_buffer_page(struct buffer_page *bpage)
{
	free_page((unsigned long)bpage->page);
	kfree(bpage);
}

/*
 * We need to fit the time_stamp delta into 27 bits.
 */
static inline int test_time_stamp(u64 delta)
{
	if (delta & TS_DELTA_TEST)
		return 1;
	return 0;
}

#define BUF_PAGE_SIZE (PAGE_SIZE - BUF_PAGE_HDR_SIZE)

/* Max payload is BUF_PAGE_SIZE - header (8bytes) */
#define BUF_MAX_DATA_SIZE (BUF_PAGE_SIZE - (sizeof(u32) * 2))

struct tb_irq_work {
	void (*wakeup)(struct tb_irq_work *);
	wait_queue_head_t		waiters;
	wait_queue_head_t		full_waiters;
	bool				waiters_pending;
	bool				full_waiters_pending;
	bool				wakeup_full;
};

/*
 * Structure to hold event state and handle nested events.
 */
struct tb_event_info {
	u64			ts;
	u64			delta;
	u64			before;
	u64			after;
	unsigned long		length;
	unsigned long		data;
	struct buffer_page	*tail_page;
	int			add_timestamp;
};

/*
 * Used for the add_timestamp
 *  NONE
 *  EXTEND - wants a time extend
 *  ABSOLUTE - the buffer requests all events to have absolute time stamps
 *  FORCE - force a full time stamp.
 */
enum {
	RB_ADD_STAMP_NONE		= 0,
	RB_ADD_STAMP_EXTEND		= BIT(1),
	RB_ADD_STAMP_ABSOLUTE		= BIT(2),
	RB_ADD_STAMP_FORCE		= BIT(3)
};
/*
 * Used for which event context the event is in.
 *  TRANSITION = 0
 *  NMI     = 1
 *  IRQ     = 2
 *  SOFTIRQ = 3
 *  NORMAL  = 4
 *
 * See tb_recursive_lock() comment below for more details.
 */
enum {
	RB_CTX_TRANSITION,
	RB_CTX_NMI,
	RB_CTX_IRQ,
	RB_CTX_SOFTIRQ,
	RB_CTX_NORMAL,
	RB_CTX_MAX
};

#if BITS_PER_LONG == 32
#define RB_TIME_32
#endif

/* To test on 64 bit machines */
//#define RB_TIME_32

#ifdef RB_TIME_32
#include <asm/local.h>
struct tb_time_struct {
	local_t		cnt;
	local_t		top;
	local_t		bottom;
};
#else
struct tb_time_struct {
	local_t	time;
};
#endif
typedef struct tb_time_struct tb_time_t;

#define MAX_NEST	5

/*
 * head_page == tail_page && head == tail then buffer is empty.
 */
struct tb_per_cpu {
	int				cpu;
	atomic_t			record_disabled;
	atomic_t			resize_disabled;
	struct tb_ring	*buffer;
	raw_spinlock_t			reader_lock;	/* serialize readers */
	arch_spinlock_t			lock;
	struct lock_class_key		lock_key;
	struct buffer_data_page		*free_page;
	unsigned long			nr_pages;
	unsigned int			current_context;
	struct list_head		*pages;
	struct buffer_page		*head_page;	/* read from head */
	struct buffer_page		*tail_page;	/* write to tail */
	struct buffer_page		*commit_page;	/* committed pages */
	struct buffer_page		*reader_page;
	unsigned long			lost_events;
	unsigned long			last_overrun;
	unsigned long			nest;
	local_t			entries_bytes;
	local_t			entries;
	local_t			overrun;
	local_t			commit_overrun;
	local_t			produced_events;
	local_t			consumed_events;
	local_t			rejected_events;
	local_t			dropped_events;
	local_t			discarded_events;
	local_t			committing;
	local_t			commits;
	local_t			pages_touched;
	local_t			pages_read;
	long				last_pages_touch;
	size_t				shortest_full;
	unsigned long			read;
	unsigned long			read_bytes;
	tb_time_t			write_stamp;
	tb_time_t			before_stamp;
	u64				event_stamp[MAX_NEST];
	u64				read_stamp;
	/* ring buffer pages to update, > 0 to add, < 0 to remove */
	long				nr_pages_to_update;
	struct list_head		new_pages; /* new pages to add */
	struct work_struct		update_pages_work;
	struct completion		update_done;

	struct tb_irq_work		irq_work;

	u64				produced_size;	/* = sum of all below sizes */
	u64				rejected_size;	/* too large to fit BUF_SIZE */
	u64				dropped_size; /* manually abandoned by producer*/
	u64				discarded_size;	/* discarded if rb is full (non overwritable) */
	u64				overwritten_size; /* overwritten if rb is full (overwritable)*/
	u64				consumed_size;	/* read by consumer */
	u32				max_event_size;
};

struct tb_ring {
	unsigned			flags;
	int				cpus;
	atomic_t			record_disabled;
	cpumask_var_t			cpumask;

	struct lock_class_key		*reader_lock_key;

	struct mutex			mutex;

	struct tb_per_cpu	**buffers;

	struct hlist_node		node;
	u64				(*clock)(void);

	struct tb_irq_work		irq_work;
	bool				time_stamp_abs;

	unsigned long		nr_pages;
};

struct tb_iter {
	struct tb_per_cpu	*cpu_ring;
	unsigned long			head;
	unsigned long			next_event;
	struct buffer_page		*head_page;
	struct buffer_page		*cache_reader_page;
	unsigned long			cache_read;
	u64				read_stamp;
	u64				page_stamp;
	struct tb_event	*event;
	int				missed_events;
};

#ifdef RB_TIME_32

/*
 * On 32 bit machines, local64_t is very expensive. As the ring
 * buffer doesn't need all the features of a true 64 bit atomic,
 * on 32 bit, it uses these functions (64 still uses local64_t).
 *
 * For the ring buffer, 64 bit required operations for the time is
 * the following:
 *
 *  - Only need 59 bits (uses 60 to make it even).
 *  - Reads may fail if it interrupted a modification of the time stamp.
 *      It will succeed if it did not interrupt another write even if
 *      the read itself is interrupted by a write.
 *      It returns whether it was successful or not.
 *
 *  - Writes always succeed and will overwrite other writes and writes
 *      that were done by events interrupting the current write.
 *
 *  - A write followed by a read of the same time stamp will always succeed,
 *      but may not contain the same value.
 *
 *  - A cmpxchg will fail if it interrupted another write or cmpxchg.
 *      Other than that, it acts like a normal cmpxchg.
 *
 * The 60 bit time stamp is broken up by 30 bits in a top and bottom half
 *  (bottom being the least significant 30 bits of the 60 bit time stamp).
 *
 * The two most significant bits of each half holds a 2 bit counter (0-3).
 * Each update will increment this counter by one.
 * When reading the top and bottom, if the two counter bits match then the
 *  top and bottom together make a valid 60 bit number.
 */
#define RB_TIME_SHIFT	30
#define RB_TIME_VAL_MASK ((1 << RB_TIME_SHIFT) - 1)

static inline int tb_time_cnt(unsigned long val)
{
	return (val >> RB_TIME_SHIFT) & 3;
}

static inline u64 tb_time_val(unsigned long top, unsigned long bottom)
{
	u64 val;

	val = top & RB_TIME_VAL_MASK;
	val <<= RB_TIME_SHIFT;
	val |= bottom & RB_TIME_VAL_MASK;

	return val;
}

static inline bool __tb_time_read(tb_time_t *t, u64 *ret, unsigned long *cnt)
{
	unsigned long top, bottom;
	unsigned long c;

	/*
	 * If the read is interrupted by a write, then the cnt will
	 * be different. Loop until both top and bottom have been read
	 * without interruption.
	 */
	do {
		c = local_read(&t->cnt);
		top = local_read(&t->top);
		bottom = local_read(&t->bottom);
	} while (c != local_read(&t->cnt));

	*cnt = tb_time_cnt(top);

	/* If top and bottom counts don't match, this interrupted a write */
	if (*cnt != tb_time_cnt(bottom))
		return false;

	*ret = tb_time_val(top, bottom);
	return true;
}

static bool tb_time_read(tb_time_t *t, u64 *ret)
{
	unsigned long cnt;

	return __tb_time_read(t, ret, &cnt);
}

static inline unsigned long tb_time_val_cnt(unsigned long val, unsigned long cnt)
{
	return (val & RB_TIME_VAL_MASK) | ((cnt & 3) << RB_TIME_SHIFT);
}

static inline void tb_time_split(u64 val, unsigned long *top, unsigned long *bottom)
{
	*top = (unsigned long)((val >> RB_TIME_SHIFT) & RB_TIME_VAL_MASK);
	*bottom = (unsigned long)(val & RB_TIME_VAL_MASK);
}

static inline void tb_time_val_set(local_t *t, unsigned long val, unsigned long cnt)
{
	val = tb_time_val_cnt(val, cnt);
	local_set(t, val);
}

static void tb_time_set(tb_time_t *t, u64 val)
{
	unsigned long cnt, top, bottom;

	tb_time_split(val, &top, &bottom);

	/* Writes always succeed with a valid number even if it gets interrupted. */
	do {
		cnt = local_inc_return(&t->cnt);
		tb_time_val_set(&t->top, top, cnt);
		tb_time_val_set(&t->bottom, bottom, cnt);
	} while (cnt != local_read(&t->cnt));
}

static inline bool
tb_time_read_cmpxchg(local_t *l, unsigned long expect, unsigned long set)
{
	unsigned long ret;

	ret = local_cmpxchg(l, expect, set);
	return ret == expect;
}

static int tb_time_cmpxchg(tb_time_t *t, u64 expect, u64 set)
{
	unsigned long cnt, top, bottom;
	unsigned long cnt2, top2, bottom2;
	u64 val;

	/* The cmpxchg always fails if it interrupted an update */
	 if (!__tb_time_read(t, &val, &cnt2))
		 return false;

	 if (val != expect)
		 return false;

	 cnt = local_read(&t->cnt);
	 if ((cnt & 3) != cnt2)
		 return false;

	 cnt2 = cnt + 1;

	 tb_time_split(val, &top, &bottom);
	 top = tb_time_val_cnt(top, cnt);
	 bottom = tb_time_val_cnt(bottom, cnt);

	 tb_time_split(set, &top2, &bottom2);
	 top2 = tb_time_val_cnt(top2, cnt2);
	 bottom2 = tb_time_val_cnt(bottom2, cnt2);

	if (!tb_time_read_cmpxchg(&t->cnt, cnt, cnt2))
		return false;
	if (!tb_time_read_cmpxchg(&t->top, top, top2))
		return false;
	if (!tb_time_read_cmpxchg(&t->bottom, bottom, bottom2))
		return false;
	return true;
}

#else /* 64 bits */

static inline bool tb_time_read(tb_time_t *t, u64 *ret)
{
	*ret = local_read(&t->time);
	return true;
}
static void tb_time_set(tb_time_t *t, u64 val)
{
	local_set(&t->time, val);
}

static bool tb_time_cmpxchg(tb_time_t *t, u64 expect, u64 set)
{
	u64 val;
	val = local_cmpxchg(&t->time, expect, set);
	return val == expect;
}
#endif

/*
 * Enable this to make sure that the event passed to
 * tb_event_time_stamp() is not committed and also
 * is on the buffer that it passed in.
 */
// #define RB_VERIFY_EVENT
#ifdef RB_VERIFY_EVENT
static struct list_head *tb_list_head(struct list_head *list);
static void verify_event(struct tb_per_cpu *cpu_ring,
			 void *event)
{
	struct buffer_page *page = cpu_ring->commit_page;
	struct buffer_page *tail_page = READ_ONCE(cpu_ring->tail_page);
	struct list_head *next;
	long commit, write;
	unsigned long addr = (unsigned long)event;
	bool done = false;
	int stop = 0;

	/* Make sure the event exists and is not committed yet */
	do {
		if (page == tail_page || WARN_ON_ONCE(stop++ > 100))
			done = true;
		commit = local_read(&page->page->commit);
		write = local_read(&page->write);
		if (addr >= (unsigned long)&page->page->data[commit] &&
		    addr < (unsigned long)&page->page->data[write])
			return;

		next = tb_list_head(page->list.next);
		page = list_entry(next, struct buffer_page, list);
	} while (!done);
	WARN_ON_ONCE(1);
}
#else
static inline void verify_event(struct tb_per_cpu *cpu_ring,
			 void *event)
{
}
#endif

/**
 * tb_event_timestamp - return the event's current time stamp
 * @buffer: The buffer that the event is on
 * @event: the event to get the time stamp of
 *
 * Note, this must be called after @event is reserved, and before it is
 * committed to the ring buffer. And must be called from the same
 * context where the event was reserved (normal, softirq, irq, etc).
 *
 * Returns the time stamp associated with the current event.
 * If the event has an extended time stamp, then that is used as
 * the time stamp to return.
 * In the highly unlikely case that the event was nested more than
 * the max nesting, then the write_stamp of the buffer is returned,
 * otherwise  current time is returned, but that really neither of
 * the last two cases should ever happen.
 */
u64 tb_event_timestamp(struct tb_ring *buffer,
				 struct tb_event *event)
{
	struct tb_per_cpu *cpu_ring = buffer->buffers[smp_processor_id()];
	unsigned int nest;
	u64 ts;

	/* If the event includes an absolute time, then just use that */
	if (event->type_len == TB_TYPETIME_STAMP)
		return tb_event_time_stamp(event);

	nest = local_read(&cpu_ring->committing);
	verify_event(cpu_ring, event);
	if (WARN_ON_ONCE(!nest))
		goto fail;

	/* Read the current saved nesting level time stamp */
	if (likely(--nest < MAX_NEST))
		return cpu_ring->event_stamp[nest];

	/* Shouldn't happen, warn if it does */
	WARN_ONCE(1, "nest (%d) greater than max", nest);

 fail:
	/* Can only fail on 32 bit */
	if (!tb_time_read(&cpu_ring->write_stamp, &ts))
		/* Screw it, just read the current time */
		ts = tb_clock_local();

	return ts;
}

/**
 * tb_nr_pages - get the number of buffer pages in the ring buffer
 * @buffer: The ring_buffer to get the number of pages from
 * @cpu: The cpu of the ring_buffer to get the number of pages from
 *
 * Returns the number of pages used by a per_cpu buffer of the ring buffer.
 */
size_t tb_nr_pages(struct tb_ring *buffer, int cpu)
{
	return buffer->buffers[cpu]->nr_pages;
}

/**
 * tb_nr_pages_dirty - get the number of used pages in the ring buffer
 * @buffer: The ring_buffer to get the number of pages from
 * @cpu: The cpu of the ring_buffer to get the number of pages from
 *
 * Returns the number of pages that have content in the ring buffer.
 */
size_t tb_nr_dirty_pages(struct tb_ring *buffer, int cpu)
{
	size_t read;
	size_t cnt;

	read = local_read(&buffer->buffers[cpu]->pages_read);
	cnt = local_read(&buffer->buffers[cpu]->pages_touched);
	/* The reader can read an empty page, but not more than that */
	if (cnt < read) {
		WARN_ON_ONCE(read > cnt + 1);
		return 0;
	}

	return cnt - read;
}

/*
 * tb_wake_up_waiters - wake up tasks waiting for ring buffer input
 *
 * Schedules a delayed work to wake up any task that is blocked on the
 * ring buffer waiters queue.
 */
void tb_wake_up_waiters(struct tb_irq_work *work)
{
	wake_up_all(&work->waiters);
	if (work->wakeup_full) {
		work->wakeup_full = false;
		wake_up_all(&work->full_waiters);
	}
}

/**
 * tb_wait - wait for input to the ring buffer
 * @buffer: buffer to wait on
 * @cpu: the cpu buffer to wait on
 * @full: wait until the percentage of pages are available, if @cpu != TB_RING_ALL_CPUS
 *
 * If @cpu == TB_RING_ALL_CPUS then the task will wake up as soon
 * as data is added to any of the @buffer's cpu buffers. Otherwise
 * it will wait for data to be added to a specific cpu buffer.
 */
int tb_wait(struct tb_ring *buffer, int cpu, int full)
{
	struct tb_per_cpu *cpu_ring = NULL;
	DEFINE_WAIT(wait);
	struct tb_irq_work *work;
	int ret = 0;

	/*
	 * Depending on what the caller is waiting for, either any
	 * data in any cpu buffer, or a specific buffer, put the
	 * caller on the appropriate wait queue.
	 */
	if (cpu == TB_RING_ALL_CPUS) {
		work = &buffer->irq_work;
		/* Full only makes sense on per cpu reads */
		full = 0;
	} else {
		if (!cpumask_test_cpu(cpu, buffer->cpumask))
			return -ENODEV;
		cpu_ring = buffer->buffers[cpu];
		work = &cpu_ring->irq_work;
	}

	while (true) {
		if (full)
			prepare_to_wait(&work->full_waiters, &wait, TASK_INTERRUPTIBLE);
		else
			prepare_to_wait(&work->waiters, &wait, TASK_INTERRUPTIBLE);

		/*
		 * The events can happen in critical sections where
		 * checking a work queue can cause deadlocks.
		 * After adding a task to the queue, this flag is set
		 * only to notify events to try to wake up the queue
		 * using irq_work.
		 *
		 * We don't clear it even if the buffer is no longer
		 * empty. The flag only causes the next event to run
		 * irq_work to do the work queue wake up. The worse
		 * that can happen if we race with !tb_empty() is that
		 * an event will cause an irq_work to try to wake up
		 * an empty queue.
		 *
		 * There's no reason to protect this flag either, as
		 * the work queue and irq_work logic will do the necessary
		 * synchronization for the wake ups. The only thing
		 * that is necessary is that the wake up happens after
		 * a task has been queued. It's OK for spurious wake ups.
		 */
		if (full)
			work->full_waiters_pending = true;
		else
			work->waiters_pending = true;

		if (signal_pending(current)) {
			ret = -EINTR;
			break;
		}

		if (cpu == TB_RING_ALL_CPUS && !tb_empty(buffer))
			break;

		if (cpu != TB_RING_ALL_CPUS &&
		    !tb_empty_cpu(buffer, cpu)) {
			unsigned long flags;
			bool pagebusy;
			size_t nr_pages;
			size_t dirty;

			if (!full)
				break;

			raw_spin_lock_irqsave(&cpu_ring->reader_lock, flags);
			pagebusy = cpu_ring->reader_page == cpu_ring->commit_page;
			nr_pages = cpu_ring->nr_pages;
			dirty = tb_nr_dirty_pages(buffer, cpu);
			if (!cpu_ring->shortest_full ||
			    cpu_ring->shortest_full < full)
				cpu_ring->shortest_full = full;
			raw_spin_unlock_irqrestore(&cpu_ring->reader_lock, flags);
			if (!pagebusy &&
			    (!nr_pages || (dirty * 100) > full * nr_pages))
				break;
		}

		schedule();
	}

	if (full)
		finish_wait(&work->full_waiters, &wait);
	else
		finish_wait(&work->waiters, &wait);

	return ret;
}

/* buffer may be either ring_buffer or tb_per_cpu */
#define RB_WARN_ON(b, cond)						\
	({								\
		int _____ret = unlikely(cond);				\
		if (_____ret) {						\
			if (__same_type(*(b), struct tb_per_cpu)) { \
				struct tb_per_cpu *__b =	\
					(void *)b;			\
				atomic_inc(&__b->buffer->record_disabled); \
			} else						\
				atomic_inc(&b->record_disabled);	\
			WARN_ON(1);					\
		}							\
		_____ret;						\
	})

u64 tb_time_stamp(struct tb_ring *buffer)
{
	u64 time;

	preempt_disable_notrace();
	time = tb_clock_local();
	preempt_enable_notrace();

	return time;
}

static void tb_normalize_time_stamp(struct tb_ring *buffer,
				      int cpu, u64 *ts)
{
}

/*
 * Making the ring buffer lockless makes things tricky.
 * Although writes only happen on the CPU that they are on,
 * and they only need to worry about interrupts. Reads can
 * happen on any CPU.
 *
 * The reader page is always off the ring buffer, but when the
 * reader finishes with a page, it needs to swap its page with
 * a new one from the buffer. The reader needs to take from
 * the head (writes go to the tail). But if a writer is in overwrite
 * mode and wraps, it must push the head page forward.
 *
 * Here lies the problem.
 *
 * The reader must be careful to replace only the head page, and
 * not another one. As described at the top of the file in the
 * ASCII art, the reader sets its old page to point to the next
 * page after head. It then sets the page after head to point to
 * the old reader page. But if the writer moves the head page
 * during this operation, the reader could end up with the tail.
 *
 * We use cmpxchg to help prevent this race. We also do something
 * special with the page before head. We set the LSB to 1.
 *
 * When the writer must push the page forward, it will clear the
 * bit that points to the head page, move the head, and then set
 * the bit that points to the new head page.
 *
 * We also don't want an interrupt coming in and moving the head
 * page on another writer. Thus we use the second LSB to catch
 * that too. Thus:
 *
 * head->list->prev->next        bit 1          bit 0
 *                              -------        -------
 * Normal page                     0              0
 * Points to head page             0              1
 * New head page                   1              0
 *
 * Note we can not trust the prev pointer of the head page, because:
 *
 * +----+       +-----+        +-----+
 * |    |------>|  T  |---X--->|  N  |
 * |    |<------|     |        |     |
 * +----+       +-----+        +-----+
 *   ^                           ^ |
 *   |          +-----+          | |
 *   +----------|  R  |----------+ |
 *              |     |<-----------+
 *              +-----+
 *
 * Key:  ---X-->  HEAD flag set in pointer
 *         T      Tail page
 *         R      Reader page
 *         N      Next page
 *
 * (see __tb_reserve_next() to see where this happens)
 *
 *  What the above shows is that the reader just swapped out
 *  the reader page with a page in the buffer, but before it
 *  could make the new header point back to the new page added
 *  it was preempted by a writer. The writer moved forward onto
 *  the new page added by the reader and is about to move forward
 *  again.
 *
 *  You can see, it is legitimate for the previous pointer of
 *  the head (or any page) not to point back to itself. But only
 *  temporarily.
 */

#define RB_PAGE_NORMAL		0UL
#define RB_PAGE_HEAD		1UL
#define RB_PAGE_UPDATE		2UL


#define RB_FLAG_MASK		3UL

/* PAGE_MOVED is not part of the mask */
#define RB_PAGE_MOVED		4UL

/*
 * tb_list_head - remove any bit
 */
static struct list_head *tb_list_head(struct list_head *list)
{
	unsigned long val = (unsigned long)list;

	return (struct list_head *)(val & ~RB_FLAG_MASK);
}

/*
 * tb_is_head_page - test if the given page is the head page
 *
 * Because the reader may move the head_page pointer, we can
 * not trust what the head page is (it may be pointing to
 * the reader page). But if the next page is a header page,
 * its flags will be non zero.
 */
static inline int
tb_is_head_page(struct buffer_page *page, struct list_head *list)
{
	unsigned long val;

	val = (unsigned long)list->next;

	if ((val & ~RB_FLAG_MASK) != (unsigned long)&page->list)
		return RB_PAGE_MOVED;

	return val & RB_FLAG_MASK;
}

/*
 * tb_is_reader_page
 *
 * The unique thing about the reader page, is that, if the
 * writer is ever on it, the previous pointer never points
 * back to the reader page.
 */
static bool tb_is_reader_page(struct buffer_page *page)
{
	struct list_head *list = page->list.prev;

	return tb_list_head(list->next) != &page->list;
}

/*
 * tb_set_list_to_head - set a list_head to be pointing to head.
 */
static void tb_set_list_to_head(struct list_head *list)
{
	unsigned long *ptr;

	ptr = (unsigned long *)&list->next;
	*ptr |= RB_PAGE_HEAD;
	*ptr &= ~RB_PAGE_UPDATE;
}

/*
 * tb_head_page_activate - sets up head page
 */
static void tb_head_page_activate(struct tb_per_cpu *cpu_ring)
{
	struct buffer_page *head;

	head = cpu_ring->head_page;
	if (!head)
		return;

	/*
	 * Set the previous list pointer to have the HEAD flag.
	 */
	tb_set_list_to_head(head->list.prev);
}

static void tb_list_head_clear(struct list_head *list)
{
	unsigned long *ptr = (unsigned long *)&list->next;

	*ptr &= ~RB_FLAG_MASK;
}

/*
 * tb_head_page_deactivate - clears head page ptr (for free list)
 */
static void
tb_head_page_deactivate(struct tb_per_cpu *cpu_ring)
{
	struct list_head *hd;

	/* Go through the whole list and clear any pointers found. */
	tb_list_head_clear(cpu_ring->pages);

	list_for_each(hd, cpu_ring->pages)
		tb_list_head_clear(hd);
}

static int tb_head_page_set(struct tb_per_cpu *cpu_ring,
			    struct buffer_page *head,
			    struct buffer_page *prev,
			    int old_flag, int new_flag)
{
	struct list_head *list;
	unsigned long val = (unsigned long)&head->list;
	unsigned long ret;

	list = &prev->list;

	val &= ~RB_FLAG_MASK;

	ret = cmpxchg((unsigned long *)&list->next,
		      val | old_flag, val | new_flag);

	/* check if the reader took the page */
	if ((ret & ~RB_FLAG_MASK) != val)
		return RB_PAGE_MOVED;

	return ret & RB_FLAG_MASK;
}

static int tb_head_page_set_update(struct tb_per_cpu *cpu_ring,
				   struct buffer_page *head,
				   struct buffer_page *prev,
				   int old_flag)
{
	return tb_head_page_set(cpu_ring, head, prev,
				old_flag, RB_PAGE_UPDATE);
}

static int tb_head_page_set_head(struct tb_per_cpu *cpu_ring,
				 struct buffer_page *head,
				 struct buffer_page *prev,
				 int old_flag)
{
	return tb_head_page_set(cpu_ring, head, prev,
				old_flag, RB_PAGE_HEAD);
}

static int tb_head_page_set_normal(struct tb_per_cpu *cpu_ring,
				   struct buffer_page *head,
				   struct buffer_page *prev,
				   int old_flag)
{
	return tb_head_page_set(cpu_ring, head, prev,
				old_flag, RB_PAGE_NORMAL);
}

static inline void tb_inc_page(struct buffer_page **bpage)
{
	struct list_head *p = tb_list_head((*bpage)->list.next);

	*bpage = list_entry(p, struct buffer_page, list);
}

static struct buffer_page *
tb_set_head_page(struct tb_per_cpu *cpu_ring)
{
	struct buffer_page *head;
	struct buffer_page *page;
	struct list_head *list;
	int i;

	if (RB_WARN_ON(cpu_ring, !cpu_ring->head_page))
		return NULL;

	/* sanity check */
	list = cpu_ring->pages;
	if (RB_WARN_ON(cpu_ring, tb_list_head(list->prev->next) != list))
		return NULL;

	page = head = cpu_ring->head_page;
	/*
	 * It is possible that the writer moves the header behind
	 * where we started, and we miss in one loop.
	 * A second loop should grab the header, but we'll do
	 * three loops just because I'm paranoid.
	 */
	for (i = 0; i < 3; i++) {
		do {
			if (tb_is_head_page(page, page->list.prev)) {
				cpu_ring->head_page = page;
				return page;
			}
			tb_inc_page(&page);
		} while (page != head);
	}

	RB_WARN_ON(cpu_ring, 1);

	return NULL;
}

static int tb_head_page_replace(struct buffer_page *old,
				struct buffer_page *new)
{
	unsigned long *ptr = (unsigned long *)&old->list.prev->next;
	unsigned long val;
	unsigned long ret;

	val = *ptr & ~RB_FLAG_MASK;
	val |= RB_PAGE_HEAD;

	ret = cmpxchg(ptr, val, (unsigned long)&new->list);

	return ret == val;
}

/*
 * tb_tail_page_update - move the tail page forward
 */
static void tb_tail_page_update(struct tb_per_cpu *cpu_ring,
			       struct buffer_page *tail_page,
			       struct buffer_page *next_page)
{
	unsigned long old_entries;
	unsigned long old_write;

	/*
	 * The tail page now needs to be moved forward.
	 *
	 * We need to reset the tail page, but without messing
	 * with possible erasing of data brought in by interrupts
	 * that have moved the tail page and are currently on it.
	 *
	 * We add a counter to the write field to denote this.
	 */
	old_write = local_add_return(RB_WRITE_INTCNT, &next_page->write);
	old_entries = local_add_return(RB_WRITE_INTCNT, &next_page->entries);

	local_inc(&cpu_ring->pages_touched);
	/*
	 * Just make sure we have seen our old_write and synchronize
	 * with any interrupts that come in.
	 */
	barrier();

	/*
	 * If the tail page is still the same as what we think
	 * it is, then it is up to us to update the tail
	 * pointer.
	 */
	if (tail_page == READ_ONCE(cpu_ring->tail_page)) {
		/* Zero the write counter */
		unsigned long val = old_write & ~RB_WRITE_MASK;
		unsigned long eval = old_entries & ~RB_WRITE_MASK;

		/*
		 * This will only succeed if an interrupt did
		 * not come in and change it. In which case, we
		 * do not want to modify it.
		 *
		 * We add (void) to let the compiler know that we do not care
		 * about the return value of these functions. We use the
		 * cmpxchg to only update if an interrupt did not already
		 * do it for us. If the cmpxchg fails, we don't care.
		 */
		(void)local_cmpxchg(&next_page->write, old_write, val);
		(void)local_cmpxchg(&next_page->entries, old_entries, eval);

		/*
		 * No need to worry about races with clearing out the commit.
		 * it only can increment when a commit takes place. But that
		 * only happens in the outer most nested commit.
		 */
		local_set(&next_page->page->commit, 0);

		/* Again, either we update tail_page or an interrupt does */
		(void)cmpxchg(&cpu_ring->tail_page, tail_page, next_page);
	}
}

static int tb_check_bpage(struct tb_per_cpu *cpu_ring,
			  struct buffer_page *bpage)
{
	unsigned long val = (unsigned long)bpage;

	if (RB_WARN_ON(cpu_ring, val & RB_FLAG_MASK))
		return 1;

	return 0;
}

/**
 * tb_check_list - make sure a pointer to a list has the last bits zero
 */
static int tb_check_list(struct tb_per_cpu *cpu_ring,
			 struct list_head *list)
{
	if (RB_WARN_ON(cpu_ring, tb_list_head(list->prev) != list->prev))
		return 1;
	if (RB_WARN_ON(cpu_ring, tb_list_head(list->next) != list->next))
		return 1;
	return 0;
}

/**
 * tb_check_pages - integrity check of buffer pages
 * @cpu_ring: CPU buffer with pages to test
 *
 * As a safety measure we check to make sure the data pages have not
 * been corrupted.
 */
static int tb_check_pages(struct tb_per_cpu *cpu_ring)
{
	struct list_head *head = cpu_ring->pages;
	struct buffer_page *bpage, *tmp;

	/* Reset the head page if it exists */
	if (cpu_ring->head_page)
		tb_set_head_page(cpu_ring);

	tb_head_page_deactivate(cpu_ring);

	if (RB_WARN_ON(cpu_ring, head->next->prev != head))
		return -1;
	if (RB_WARN_ON(cpu_ring, head->prev->next != head))
		return -1;

	if (tb_check_list(cpu_ring, head))
		return -1;

	list_for_each_entry_safe(bpage, tmp, head, list) {
		if (RB_WARN_ON(cpu_ring,
			       bpage->list.next->prev != &bpage->list))
			return -1;
		if (RB_WARN_ON(cpu_ring,
			       bpage->list.prev->next != &bpage->list))
			return -1;
		if (tb_check_list(cpu_ring, &bpage->list))
			return -1;
	}

	tb_head_page_activate(cpu_ring);

	return 0;
}

static int __tb_allocate_pages(struct tb_per_cpu *cpu_ring,
		long nr_pages, struct list_head *pages)
{
	struct buffer_page *bpage, *tmp;
	bool user_thread = current->mm != NULL;
	gfp_t mflags;
	long i;

	/*
	 * __GFP_RETRY_MAYFAIL flag makes sure that the allocation fails
	 * gracefully without invoking oom-killer and the system is not
	 * destabilized.
	 */
	mflags = GFP_KERNEL | __GFP_RETRY_MAYFAIL;

	/*
	 * If a user thread allocates too much, and si_mem_available()
	 * reports there's enough memory, even though there is not.
	 * Make sure the OOM killer kills this thread. This can happen
	 * even with RETRY_MAYFAIL because another task may be doing
	 * an allocation after this task has taken all memory.
	 * This is the task the OOM killer needs to take out during this
	 * loop, even if it was triggered by an allocation somewhere else.
	 */
#if LINUX_VERSION_CODE >=  KERNEL_VERSION(3, 8, 0)
	if (user_thread)
		set_current_oom_origin();
#endif

	for (i = 0; i < nr_pages; i++) {
		struct page *page;

		bpage = kzalloc_node(ALIGN(sizeof(*bpage), cache_line_size()),
				    mflags, cpu_to_node(cpu_ring->cpu));
		if (!bpage)
			goto free_pages;

		tb_check_bpage(cpu_ring, bpage);

		list_add(&bpage->list, pages);

		page = alloc_pages_node(cpu_to_node(cpu_ring->cpu), mflags, 0);
		if (!page)
			goto free_pages;
		bpage->page = page_address(page);
		tb_init_page(bpage->page);

		if (user_thread && fatal_signal_pending(current))
			goto free_pages;
	}

#if LINUX_VERSION_CODE >=  KERNEL_VERSION(3, 8, 0)
	if (user_thread)
		clear_current_oom_origin();
#endif

	return 0;

free_pages:
	list_for_each_entry_safe(bpage, tmp, pages, list) {
		list_del_init(&bpage->list);
		free_buffer_page(bpage);
	}

#if LINUX_VERSION_CODE >=  KERNEL_VERSION(3, 8, 0)
	if (user_thread)
		clear_current_oom_origin();
#endif
	return -ENOMEM;
}

static int tb_allocate_pages(struct tb_per_cpu *cpu_ring,
			     unsigned long nr_pages)
{
	LIST_HEAD(pages);

	WARN_ON(!nr_pages);

	if (__tb_allocate_pages(cpu_ring, nr_pages, &pages))
		return -ENOMEM;

	/*
	 * The ring buffer page list is a circular list that does not
	 * start and end with a list head. All page list items point to
	 * other pages.
	 */
	cpu_ring->pages = pages.next;
	list_del(&pages);

	cpu_ring->nr_pages = nr_pages;

	tb_check_pages(cpu_ring);

	return 0;
}

static struct tb_per_cpu *
tb_allocate_cpu_ring(struct tb_ring *buffer, long nr_pages, int cpu)
{
	struct tb_per_cpu *cpu_ring;
	struct buffer_page *bpage;
	struct page *page;
	int ret;

	cpu_ring = kzalloc_node(ALIGN(sizeof(*cpu_ring), cache_line_size()),
				  GFP_KERNEL, cpu_to_node(cpu));
	if (!cpu_ring)
		return NULL;

	cpu_ring->cpu = cpu;
	cpu_ring->buffer = buffer;
	raw_spin_lock_init(&cpu_ring->reader_lock);
	lockdep_set_class(&cpu_ring->reader_lock, buffer->reader_lock_key);
	cpu_ring->lock = (arch_spinlock_t)__ARCH_SPIN_LOCK_UNLOCKED;
	INIT_WORK(&cpu_ring->update_pages_work, tb_update_pages_handler);
	init_completion(&cpu_ring->update_done);
	cpu_ring->irq_work.wakeup = tb_wake_up_waiters;
	init_waitqueue_head(&cpu_ring->irq_work.waiters);
	init_waitqueue_head(&cpu_ring->irq_work.full_waiters);

	bpage = kzalloc_node(ALIGN(sizeof(*bpage), cache_line_size()),
			    GFP_KERNEL, cpu_to_node(cpu));
	if (!bpage)
		goto fail_free_buffer;

	tb_check_bpage(cpu_ring, bpage);

	cpu_ring->reader_page = bpage;
	page = alloc_pages_node(cpu_to_node(cpu), GFP_KERNEL, 0);
	if (!page)
		goto fail_free_reader;
	bpage->page = page_address(page);
	tb_init_page(bpage->page);

	INIT_LIST_HEAD(&cpu_ring->reader_page->list);
	INIT_LIST_HEAD(&cpu_ring->new_pages);

	ret = tb_allocate_pages(cpu_ring, nr_pages);
	if (ret < 0)
		goto fail_free_reader;

	cpu_ring->head_page
		= list_entry(cpu_ring->pages, struct buffer_page, list);
	cpu_ring->tail_page = cpu_ring->commit_page = cpu_ring->head_page;

	tb_head_page_activate(cpu_ring);

	return cpu_ring;

 fail_free_reader:
	free_buffer_page(cpu_ring->reader_page);

 fail_free_buffer:
	kfree(cpu_ring);
	return NULL;
}

static void tb_free_cpu_ring(struct tb_per_cpu *cpu_ring)
{
	struct list_head *head = cpu_ring->pages;
	struct buffer_page *bpage, *tmp;

	free_buffer_page(cpu_ring->reader_page);

	tb_head_page_deactivate(cpu_ring);

	if (head) {
		list_for_each_entry_safe(bpage, tmp, head, list) {
			list_del_init(&bpage->list);
			free_buffer_page(bpage);
		}
		bpage = list_entry(head, struct buffer_page, list);
		free_buffer_page(bpage);
	}

	kfree(cpu_ring);
}

/*
 * We only allocate new buffers, never free them if the CPU goes down.
 * If we were to free the buffer, then the user would lose any trace that was in
 * the buffer.
 */
static int tb_cpu_prepare(unsigned int cpu, struct hlist_node *node)
{
	struct tb_ring *buffer;

	buffer = container_of(node, struct tb_ring, node);
	if (cpumask_test_cpu(cpu, buffer->cpumask))
		return 0;

	buffer->buffers[cpu] =
		tb_allocate_cpu_ring(buffer, buffer->nr_pages, cpu);
	if (!buffer->buffers[cpu]) {
		WARN(1, "failed to allocate ring buffer on CPU %u\n",
		     cpu);
		return -ENOMEM;
	}
	smp_wmb();
	cpumask_set_cpu(cpu, buffer->cpumask);
	return 0;
}

/**
 * __tb_alloc - allocate a new ring_buffer
 * @size: the size in bytes per cpu that is needed.
 * @flags: attributes to set for the ring buffer.
 * @key: ring buffer reader_lock_key.
 *
 * Currently the only flag that is available is the TB_FL_OVERWRITE
 * flag. This flag means that the buffer will overwrite old data
 * when the buffer wraps. If this flag is not set, the buffer will
 * drop data when the tail hits the head.
 */
struct tb_ring *__tb_alloc(unsigned long size, unsigned flags,
					struct lock_class_key *key)
{
	struct tb_ring *buffer;
	long nr_pages;
	int bsize;
	int cpu;
	int ret;

	/* keep it in its own cache line */
	buffer = kzalloc(ALIGN(sizeof(*buffer), cache_line_size()),
			 GFP_KERNEL);
	if (!buffer)
		return NULL;

	if (!zalloc_cpumask_var(&buffer->cpumask, GFP_KERNEL))
		goto fail_free_buffer;

	buffer->flags = flags;
	buffer->clock = tb_clock_local;
	buffer->reader_lock_key = key;

	buffer->irq_work.wakeup = tb_wake_up_waiters;
	init_waitqueue_head(&buffer->irq_work.waiters);

	/* need at least two pages */
	nr_pages = DIV_ROUND_UP(size, BUF_PAGE_SIZE);
	if (nr_pages < 2)
		nr_pages = 2;
	buffer->nr_pages = nr_pages;

	buffer->cpus = nr_cpu_ids;
	bsize = sizeof(void *) * nr_cpu_ids;
	buffer->buffers = kzalloc(ALIGN(bsize, cache_line_size()),
				  GFP_KERNEL);
	if (!buffer->buffers)
		goto fail_free_cpumask;

	/* WARNING: We don't support cpu hotplug */
	for_each_present_cpu(cpu) {
		ret = tb_cpu_prepare(cpu, &buffer->node);
		if (ret < 0)
			goto fail_free_buffers;
	}
	mutex_init(&buffer->mutex);

	return buffer;

 fail_free_buffers:
	for_each_buffer_cpu(buffer, cpu) {
		if (buffer->buffers[cpu])
			tb_free_cpu_ring(buffer->buffers[cpu]);
	}
	kfree(buffer->buffers);

 fail_free_cpumask:
	free_cpumask_var(buffer->cpumask);

 fail_free_buffer:
	kfree(buffer);
	return NULL;
}

/**
 * tb_free - free a ring buffer.
 * @buffer: the buffer to free.
 */
void tb_free(struct tb_ring *buffer)
{
	int cpu;

	for_each_buffer_cpu(buffer, cpu)
		tb_free_cpu_ring(buffer->buffers[cpu]);

	kfree(buffer->buffers);
	free_cpumask_var(buffer->cpumask);

	kfree(buffer);
}

void tb_set_time_stamp_abs(struct tb_ring *buffer, bool abs)
{
	buffer->time_stamp_abs = abs;
}

bool tb_time_stamp_abs(struct tb_ring *buffer)
{
	return buffer->time_stamp_abs;
}

static inline unsigned long tb_page_entries(struct buffer_page *bpage)
{
	return local_read(&bpage->entries) & RB_WRITE_MASK;
}

static inline unsigned long tb_page_write(struct buffer_page *bpage)
{
	return local_read(&bpage->write) & RB_WRITE_MASK;
}

static int
tb_remove_pages(struct tb_per_cpu *cpu_ring, unsigned long nr_pages)
{
	struct list_head *tail_page, *to_remove, *next_page;
	struct buffer_page *to_remove_page, *tmp_iter_page;
	struct buffer_page *last_page, *first_page;
	unsigned long nr_removed;
	unsigned long head_bit;
	int page_entries;

	head_bit = 0;

	raw_spin_lock_irq(&cpu_ring->reader_lock);
	atomic_inc(&cpu_ring->record_disabled);
	/*
	 * We don't race with the readers since we have acquired the reader
	 * lock. We also don't race with writers after disabling recording.
	 * This makes it easy to figure out the first and the last page to be
	 * removed from the list. We unlink all the pages in between including
	 * the first and last pages. This is done in a busy loop so that we
	 * lose the least number of traces.
	 * The pages are freed after we restart recording and unlock readers.
	 */
	tail_page = &cpu_ring->tail_page->list;

	/*
	 * tail page might be on reader page, we remove the next page
	 * from the ring buffer
	 */
	if (cpu_ring->tail_page == cpu_ring->reader_page)
		tail_page = tb_list_head(tail_page->next);
	to_remove = tail_page;

	/* start of pages to remove */
	first_page = list_entry(tb_list_head(to_remove->next),
				struct buffer_page, list);

	for (nr_removed = 0; nr_removed < nr_pages; nr_removed++) {
		to_remove = tb_list_head(to_remove)->next;
		head_bit |= (unsigned long)to_remove & RB_PAGE_HEAD;
	}

	next_page = tb_list_head(to_remove)->next;

	/*
	 * Now we remove all pages between tail_page and next_page.
	 * Make sure that we have head_bit value preserved for the
	 * next page
	 */
	tail_page->next = (struct list_head *)((unsigned long)next_page |
						head_bit);
	next_page = tb_list_head(next_page);
	next_page->prev = tail_page;

	/* make sure pages points to a valid page in the ring buffer */
	cpu_ring->pages = next_page;

	/* update head page */
	if (head_bit)
		cpu_ring->head_page = list_entry(next_page,
						struct buffer_page, list);

	/*
	 * change read pointer to make sure any read iterators reset
	 * themselves
	 */
	cpu_ring->read = 0;

	/* pages are removed, resume tracing and then free the pages */
	atomic_dec(&cpu_ring->record_disabled);
	raw_spin_unlock_irq(&cpu_ring->reader_lock);

	RB_WARN_ON(cpu_ring, list_empty(cpu_ring->pages));

	/* last buffer page to remove */
	last_page = list_entry(tb_list_head(to_remove), struct buffer_page,
				list);
	tmp_iter_page = first_page;

	do {
		cond_resched();

		to_remove_page = tmp_iter_page;
		tb_inc_page(&tmp_iter_page);

		/* update the counters */
		page_entries = tb_page_entries(to_remove_page);
		if (page_entries) {
			/*
			 * If something was added to this page, it was full
			 * since it is not the tail page. So we deduct the
			 * bytes consumed in ring buffer from here.
			 * Increment overrun to account for the lost events.
			 */
			local_add(page_entries, &cpu_ring->overrun);
			local_sub(BUF_PAGE_SIZE, &cpu_ring->entries_bytes);
		}

		/*
		 * We have already removed references to this list item, just
		 * free up the buffer_page and its page
		 */
		free_buffer_page(to_remove_page);
		nr_removed--;

	} while (to_remove_page != last_page);

	RB_WARN_ON(cpu_ring, nr_removed);

	return nr_removed == 0;
}

static int
tb_insert_pages(struct tb_per_cpu *cpu_ring)
{
	struct list_head *pages = &cpu_ring->new_pages;
	int retries, success;

	raw_spin_lock_irq(&cpu_ring->reader_lock);
	/*
	 * We are holding the reader lock, so the reader page won't be swapped
	 * in the ring buffer. Now we are racing with the writer trying to
	 * move head page and the tail page.
	 * We are going to adapt the reader page update process where:
	 * 1. We first splice the start and end of list of new pages between
	 *    the head page and its previous page.
	 * 2. We cmpxchg the prev_page->next to point from head page to the
	 *    start of new pages list.
	 * 3. Finally, we update the head->prev to the end of new list.
	 *
	 * We will try this process 10 times, to make sure that we don't keep
	 * spinning.
	 */
	retries = 10;
	success = 0;
	while (retries--) {
		struct list_head *head_page, *prev_page, *r;
		struct list_head *last_page, *first_page;
		struct list_head *head_page_with_bit;

		head_page = &tb_set_head_page(cpu_ring)->list;
		if (!head_page)
			break;
		prev_page = head_page->prev;

		first_page = pages->next;
		last_page  = pages->prev;

		head_page_with_bit = (struct list_head *)
				     ((unsigned long)head_page | RB_PAGE_HEAD);

		last_page->next = head_page_with_bit;
		first_page->prev = prev_page;

		r = cmpxchg(&prev_page->next, head_page_with_bit, first_page);

		if (r == head_page_with_bit) {
			/*
			 * yay, we replaced the page pointer to our new list,
			 * now, we just have to update to head page's prev
			 * pointer to point to end of list
			 */
			head_page->prev = last_page;
			success = 1;
			break;
		}
	}

	if (success)
		INIT_LIST_HEAD(pages);
	/*
	 * If we weren't successful in adding in new pages, warn and stop
	 * tracing
	 */
	RB_WARN_ON(cpu_ring, !success);
	raw_spin_unlock_irq(&cpu_ring->reader_lock);

	/* free pages if they weren't inserted */
	if (!success) {
		struct buffer_page *bpage, *tmp;
		list_for_each_entry_safe(bpage, tmp, &cpu_ring->new_pages,
					 list) {
			list_del_init(&bpage->list);
			free_buffer_page(bpage);
		}
	}
	return success;
}

static void tb_update_pages(struct tb_per_cpu *cpu_ring)
{
	int success;

	if (cpu_ring->nr_pages_to_update > 0)
		success = tb_insert_pages(cpu_ring);
	else
		success = tb_remove_pages(cpu_ring,
					-cpu_ring->nr_pages_to_update);

	if (success)
		cpu_ring->nr_pages += cpu_ring->nr_pages_to_update;
}

static void tb_update_pages_handler(struct work_struct *work)
{
	struct tb_per_cpu *cpu_ring = container_of(work,
			struct tb_per_cpu, update_pages_work);
	tb_update_pages(cpu_ring);
	complete(&cpu_ring->update_done);
}

void tb_change_overwrite(struct tb_ring *buffer, int val)
{
	mutex_lock(&buffer->mutex);
	if (val)
		buffer->flags |= TB_FL_OVERWRITE;
	else
		buffer->flags &= ~TB_FL_OVERWRITE;
	mutex_unlock(&buffer->mutex);
}

static __always_inline void *__tb_page_index(struct buffer_page *bpage, unsigned index)
{
	return bpage->page->data + index;
}

static __always_inline struct tb_event *
tb_reader_event(struct tb_per_cpu *cpu_ring)
{
	return __tb_page_index(cpu_ring->reader_page,
			       cpu_ring->reader_page->read);
}

static __always_inline unsigned tb_page_commit(struct buffer_page *bpage)
{
	return local_read(&bpage->page->commit);
}

/* Size is determined by what has been committed */
static __always_inline unsigned tb_page_size(struct buffer_page *bpage)
{
	return tb_page_commit(bpage);
}

static __always_inline unsigned
tb_commit_index(struct tb_per_cpu *cpu_ring)
{
	return tb_page_commit(cpu_ring->commit_page);
}

static __always_inline unsigned
tb_event_index(struct tb_event *event)
{
	unsigned long addr = (unsigned long)event;

	return (addr & ~PAGE_MASK) - BUF_PAGE_HDR_SIZE;
}

static __inline void tb_overrun_page(struct tb_per_cpu *cpu_ring,
									struct buffer_page *bpage)
{
	long entries, size;

	entries = tb_page_entries(bpage);
	local_add(entries, &cpu_ring->overrun);
	local_sub(BUF_PAGE_SIZE, &cpu_ring->entries_bytes);

	size = BUF_PAGE_SIZE - entries * sizeof(u32);
	if (size > 0)
		cpu_ring->overwritten_size += size;
}

/*
 * tb_handle_head_page - writer hit the head page
 *
 * Returns: +1 to retry page
 *           0 to continue
 *          -1 on error
 */
static int
tb_handle_head_page(struct tb_per_cpu *cpu_ring,
		    struct buffer_page *tail_page,
		    struct buffer_page *next_page)
{
	struct buffer_page *new_head;
	int type;
	int ret;

	/*
	 * The hard part is here. We need to move the head
	 * forward, and protect against both readers on
	 * other CPUs and writers coming in via interrupts.
	 */
	type = tb_head_page_set_update(cpu_ring, next_page, tail_page,
				       RB_PAGE_HEAD);

	/*
	 * type can be one of four:
	 *  NORMAL - an interrupt already moved it for us
	 *  HEAD   - we are the first to get here.
	 *  UPDATE - we are the interrupt interrupting
	 *           a current move.
	 *  MOVED  - a reader on another CPU moved the next
	 *           pointer to its reader page. Give up
	 *           and try again.
	 */

	switch (type) {
	case RB_PAGE_HEAD:
		/*
		 * We changed the head to UPDATE, thus
		 * it is our responsibility to update
		 * the counters.
		 */
		tb_overrun_page(cpu_ring, next_page);

		/*
		 * The entries will be zeroed out when we move the
		 * tail page.
		 */

		/* still more to do */
		break;

	case RB_PAGE_UPDATE:
		/*
		 * This is an interrupt that interrupt the
		 * previous update. Still more to do.
		 */
		break;
	case RB_PAGE_NORMAL:
		/*
		 * An interrupt came in before the update
		 * and processed this for us.
		 * Nothing left to do.
		 */
		return 1;
	case RB_PAGE_MOVED:
		/*
		 * The reader is on another CPU and just did
		 * a swap with our next_page.
		 * Try again.
		 */
		return 1;
	default:
		RB_WARN_ON(cpu_ring, 1); /* WTF??? */
		return -1;
	}

	/*
	 * Now that we are here, the old head pointer is
	 * set to UPDATE. This will keep the reader from
	 * swapping the head page with the reader page.
	 * The reader (on another CPU) will spin till
	 * we are finished.
	 *
	 * We just need to protect against interrupts
	 * doing the job. We will set the next pointer
	 * to HEAD. After that, we set the old pointer
	 * to NORMAL, but only if it was HEAD before.
	 * otherwise we are an interrupt, and only
	 * want the outer most commit to reset it.
	 */
	new_head = next_page;
	tb_inc_page(&new_head);

	ret = tb_head_page_set_head(cpu_ring, new_head, next_page,
				    RB_PAGE_NORMAL);

	/*
	 * Valid returns are:
	 *  HEAD   - an interrupt came in and already set it.
	 *  NORMAL - One of two things:
	 *            1) We really set it.
	 *            2) A bunch of interrupts came in and moved
	 *               the page forward again.
	 */
	switch (ret) {
	case RB_PAGE_HEAD:
	case RB_PAGE_NORMAL:
		/* OK */
		break;
	default:
		RB_WARN_ON(cpu_ring, 1);
		return -1;
	}

	/*
	 * It is possible that an interrupt came in,
	 * set the head up, then more interrupts came in
	 * and moved it again. When we get back here,
	 * the page would have been set to NORMAL but we
	 * just set it back to HEAD.
	 *
	 * How do you detect this? Well, if that happened
	 * the tail page would have moved.
	 */
	if (ret == RB_PAGE_NORMAL) {
		struct buffer_page *buffer_tail_page;

		buffer_tail_page = READ_ONCE(cpu_ring->tail_page);
		/*
		 * If the tail had moved passed next, then we need
		 * to reset the pointer.
		 */
		if (buffer_tail_page != tail_page &&
		    buffer_tail_page != next_page)
			tb_head_page_set_normal(cpu_ring, new_head,
						next_page,
						RB_PAGE_HEAD);
	}

	/*
	 * If this was the outer most commit (the one that
	 * changed the original pointer from HEAD to UPDATE),
	 * then it is up to us to reset it to NORMAL.
	 */
	if (type == RB_PAGE_HEAD) {
		ret = tb_head_page_set_normal(cpu_ring, next_page,
					      tail_page,
					      RB_PAGE_UPDATE);
		if (RB_WARN_ON(cpu_ring,
			       ret != RB_PAGE_UPDATE))
			return -1;
	}

	return 0;
}

static inline void
tb_reset_tail(struct tb_per_cpu *cpu_ring,
	      unsigned long tail, struct tb_event_info *info)
{
	struct buffer_page *tail_page = info->tail_page;
	struct tb_event *event;
	unsigned long length = info->length;

	/*
	 * Only the event that crossed the page boundary
	 * must fill the old tail_page with padding.
	 */
	if (tail >= BUF_PAGE_SIZE) {
		/*
		 * If the page was filled, then we still need
		 * to update the real_end. Reset it to zero
		 * and the reader will ignore it.
		 */
		if (tail == BUF_PAGE_SIZE)
			tail_page->real_end = 0;

		local_sub(length, &tail_page->write);
		return;
	}

	event = __tb_page_index(tail_page, tail);

	/* account for padding bytes */
	local_add(BUF_PAGE_SIZE - tail, &cpu_ring->entries_bytes);

	/*
	 * Save the original length to the meta data.
	 * This will be used by the reader to add lost event
	 * counter.
	 */
	tail_page->real_end = tail;

	/*
	 * If this event is bigger than the minimum size, then
	 * we need to be careful that we don't subtract the
	 * write counter enough to allow another writer to slip
	 * in on this page.
	 * We put in a discarded commit instead, to make sure
	 * that this space is not used again.
	 *
	 * If we are less than the minimum size, we don't need to
	 * worry about it.
	 */
	if (tail > (BUF_PAGE_SIZE - RB_EVNT_MIN_SIZE)) {
		/* No room for any events */

		/* Mark the rest of the page with padding */
		tb_event_set_padding(event);

		/* Set the write back to the previous setting */
		local_sub(length, &tail_page->write);
		return;
	}

	/* Put in a discarded event */
	event->array[0] = (BUF_PAGE_SIZE - tail) - RB_EVNT_HDR_SIZE;
	event->type_len = TB_TYPEPADDING;
	/* time delta must be non zero */
	event->time_delta = 1;

	/* Set write to end of buffer */
	length = (tail + length) - BUF_PAGE_SIZE;
	local_sub(length, &tail_page->write);
}

static inline void tb_end_commit(struct tb_per_cpu *cpu_ring);

/*
 * This is the slow path, force gcc not to inline it.
 */
static noinline struct tb_event *
tb_move_tail(struct tb_per_cpu *cpu_ring,
	     unsigned long tail, struct tb_event_info *info)
{
	struct buffer_page *tail_page = info->tail_page;
	struct buffer_page *commit_page = cpu_ring->commit_page;
	struct tb_ring *buffer = cpu_ring->buffer;
	struct buffer_page *next_page;
	int ret;

	next_page = tail_page;

	tb_inc_page(&next_page);

	/*
	 * If for some reason, we had an interrupt storm that made
	 * it all the way around the buffer, bail, and warn
	 * about it.
	 */
	if (unlikely(next_page == commit_page)) {
		local_inc(&cpu_ring->commit_overrun);
		goto out_reset;
	}

	/*
	 * This is where the fun begins!
	 *
	 * We are fighting against races between a reader that
	 * could be on another CPU trying to swap its reader
	 * page with the buffer head.
	 *
	 * We are also fighting against interrupts coming in and
	 * moving the head or tail on us as well.
	 *
	 * If the next page is the head page then we have filled
	 * the buffer, unless the commit page is still on the
	 * reader page.
	 */
	if (tb_is_head_page(next_page, &tail_page->list)) {

		/*
		 * If the commit is not on the reader page, then
		 * move the header page.
		 */
		if (!tb_is_reader_page(cpu_ring->commit_page)) {
			/*
			 * If we are not in overwrite mode,
			 * this is easy, just stop here.
			 */
			if (!(buffer->flags & TB_FL_OVERWRITE)) {
				local_inc(&cpu_ring->dropped_events);
				cpu_ring->dropped_size += info->data;
				goto out_reset;
			}

			ret = tb_handle_head_page(cpu_ring,
						  tail_page,
						  next_page);
			if (ret < 0)
				goto out_reset;
			if (ret)
				goto out_again;
		} else {
			/*
			 * We need to be careful here too. The
			 * commit page could still be on the reader
			 * page. We could have a small buffer, and
			 * have filled up the buffer with events
			 * from interrupts and such, and wrapped.
			 *
			 * Note, if the tail page is also on the
			 * reader_page, we let it move out.
			 */
			if (unlikely((cpu_ring->commit_page !=
				      cpu_ring->tail_page) &&
				     (cpu_ring->commit_page ==
				      cpu_ring->reader_page))) {
				local_inc(&cpu_ring->commit_overrun);
				goto out_reset;
			}
		}
	}

	tb_tail_page_update(cpu_ring, tail_page, next_page);

 out_again:

	tb_reset_tail(cpu_ring, tail, info);

	/* Commit what we have for now. */
	tb_end_commit(cpu_ring);
	/* tb_end_commit() decs committing */
	local_inc(&cpu_ring->committing);

	/* fail and let the caller try again */
	return ERR_PTR(-EAGAIN);

 out_reset:
	/* reset write */
	tb_reset_tail(cpu_ring, tail, info);

	return NULL;
}

/* Slow path */
static struct tb_event *
tb_add_time_stamp(struct tb_event *event, u64 delta, bool abs)
{
	if (abs)
		event->type_len = TB_TYPETIME_STAMP;
	else
		event->type_len = TB_TYPETIME_EXTEND;

	/* Not the first event on the page, or not delta? */
	if (abs || tb_event_index(event)) {
		event->time_delta = delta & TS_MASK;
		event->array[0] = delta >> TS_SHIFT;
	} else {
		/* nope, just zero it */
		event->time_delta = 0;
		event->array[0] = 0;
	}

	return skip_time_extend(event);
}

static void
tb_check_timestamp(struct tb_per_cpu *cpu_ring,
		   struct tb_event_info *info)
{
	u64 write_stamp;

	WARN_ONCE(1, "Delta way too big! %llu ts=%llu before=%llu after=%llu write stamp=%llu\n",
		  (unsigned long long)info->delta,
		  (unsigned long long)info->ts,
		  (unsigned long long)info->before,
		  (unsigned long long)info->after,
		  (unsigned long long)(tb_time_read(&cpu_ring->write_stamp, &write_stamp) ? write_stamp : 0));
}

static void tb_add_timestamp(struct tb_per_cpu *cpu_ring,
				      struct tb_event **event,
				      struct tb_event_info *info,
				      u64 *delta,
				      unsigned int *length)
{
	bool abs = info->add_timestamp &
		(RB_ADD_STAMP_FORCE | RB_ADD_STAMP_ABSOLUTE);

	if (unlikely(info->delta > (1ULL << 59))) {
		/* did the clock go backwards */
		if (info->before == info->after && info->before > info->ts) {
			/* not interrupted */
			static int once;

			/*
			 * This is possible with a recalibrating of the TSC.
			 * Do not produce a call stack, but just report it.
			 */
			if (!once) {
				once++;
				pr_info("Ring buffer clock went backwards: %llu -> %llu\n",
					info->before, info->ts);
			}
		} else
			tb_check_timestamp(cpu_ring, info);
		if (!abs)
			info->delta = 0;
	}
	*event = tb_add_time_stamp(*event, info->delta, abs);
	*length -= RB_LEN_TIME_EXTEND;
	*delta = 0;
}

/**
 * tb_update_event - update event type and data
 * @cpu_ring: The per cpu buffer of the @event
 * @event: the event to update
 * @info: The info to update the @event with (contains length and delta)
 *
 * Update the type and data fields of the @event. The length
 * is the actual size that is written to the ring buffer,
 * and with this, we can determine what to place into the
 * data field.
 */
static void
tb_update_event(struct tb_per_cpu *cpu_ring,
		struct tb_event *event,
		struct tb_event_info *info)
{
	unsigned length = info->length;
	u64 delta = info->delta;
	unsigned int nest = local_read(&cpu_ring->committing) - 1;

	if (!WARN_ON_ONCE(nest >= MAX_NEST))
		cpu_ring->event_stamp[nest] = info->ts;

	/*
	 * If we need to add a timestamp, then we
	 * add it to the start of the reserved space.
	 */
	if (unlikely(info->add_timestamp))
		tb_add_timestamp(cpu_ring, &event, info, &delta, &length);

	event->time_delta = delta;
	length -= RB_EVNT_HDR_SIZE;
	if (length > RB_MAX_SMALL_DATA || RB_FORCE_8BYTE_ALIGNMENT) {
		event->type_len = 0;
		event->array[0] = length;
	} else
		event->type_len = DIV_ROUND_UP(length, RB_ALIGNMENT);
}

static unsigned tb_calculate_event_length(unsigned length)
{
	struct tb_event event; /* Used only for sizeof array */

	/* zero length can cause confusions */
	if (!length)
		length++;

	if (length > RB_MAX_SMALL_DATA || RB_FORCE_8BYTE_ALIGNMENT)
		length += sizeof(event.array[0]);

	length += RB_EVNT_HDR_SIZE;
	length = ALIGN(length, RB_ARCH_ALIGNMENT);

	/*
	 * In case the time delta is larger than the 27 bits for it
	 * in the header, we need to add a timestamp. If another
	 * event comes in when trying to discard this one to increase
	 * the length, then the timestamp will be added in the allocated
	 * space of this event. If length is bigger than the size needed
	 * for the TIME_EXTEND, then padding has to be used. The events
	 * length must be either RB_LEN_TIME_EXTEND, or greater than or equal
	 * to RB_LEN_TIME_EXTEND + 8, as 8 is the minimum size for padding.
	 * As length is a multiple of 4, we only need to worry if it
	 * is 12 (RB_LEN_TIME_EXTEND + 4).
	 */
	if (length == RB_LEN_TIME_EXTEND + RB_ALIGNMENT)
		length += RB_ALIGNMENT;

	return length;
}

static u64 tb_time_delta(struct tb_event *event)
{
	switch (event->type_len) {
	case TB_TYPEPADDING:
		return 0;

	case TB_TYPETIME_EXTEND:
		return tb_event_time_stamp(event);

	case TB_TYPETIME_STAMP:
		return 0;

	case TB_TYPEDATA:
		return event->time_delta;
	default:
		return 0;
	}
}

static inline int
tb_try_to_discard(struct tb_per_cpu *cpu_ring,
		  struct tb_event *event)
{
	unsigned long new_index, old_index;
	struct buffer_page *bpage;
	unsigned long index;
	unsigned long addr;
	u64 write_stamp;
	u64 delta;

	new_index = tb_event_index(event);
	old_index = new_index + tb_event_ts_length(event);
	addr = (unsigned long)event;
	addr &= PAGE_MASK;

	bpage = READ_ONCE(cpu_ring->tail_page);

	delta = tb_time_delta(event);

	if (!tb_time_read(&cpu_ring->write_stamp, &write_stamp))
		return 0;

	/* Make sure the write stamp is read before testing the location */
	barrier();

	if (bpage->page == (void *)addr && tb_page_write(bpage) == old_index) {
		unsigned long write_mask =
			local_read(&bpage->write) & ~RB_WRITE_MASK;
		unsigned long event_length = tb_event_length(event);

		/* Something came in, can't discard */
		if (!tb_time_cmpxchg(&cpu_ring->write_stamp,
				       write_stamp, write_stamp - delta))
			return 0;

		/*
		 * It's possible that the event time delta is zero
		 * (has the same time stamp as the previous event)
		 * in which case write_stamp and before_stamp could
		 * be the same. In such a case, force before_stamp
		 * to be different than write_stamp. It doesn't
		 * matter what it is, as long as its different.
		 */
		if (!delta)
			tb_time_set(&cpu_ring->before_stamp, 0);

		/*
		 * If an event were to come in now, it would see that the
		 * write_stamp and the before_stamp are different, and assume
		 * that this event just added itself before updating
		 * the write stamp. The interrupting event will fix the
		 * write stamp for us, and use the before stamp as its delta.
		 */

		/*
		 * This is on the tail page. It is possible that
		 * a write could come in and move the tail page
		 * and write to the next page. That is fine
		 * because we just shorten what is on this page.
		 */
		old_index += write_mask;
		new_index += write_mask;
		index = local_cmpxchg(&bpage->write, old_index, new_index);
		if (index == old_index) {
			/* update counters */
			local_sub(event_length, &cpu_ring->entries_bytes);
			return 1;
		}
	}

	/* could not discard */
	return 0;
}

static void tb_start_commit(struct tb_per_cpu *cpu_ring)
{
	local_inc(&cpu_ring->committing);
	local_inc(&cpu_ring->commits);
}

static __always_inline void
tb_set_commit_to_write(struct tb_per_cpu *cpu_ring)
{
	unsigned long max_count;

	/*
	 * We only race with interrupts and NMIs on this CPU.
	 * If we own the commit event, then we can commit
	 * all others that interrupted us, since the interruptions
	 * are in stack format (they finish before they come
	 * back to us). This allows us to do a simple loop to
	 * assign the commit to the tail.
	 */
 again:
	max_count = cpu_ring->nr_pages * 100;

	while (cpu_ring->commit_page != READ_ONCE(cpu_ring->tail_page)) {
		if (RB_WARN_ON(cpu_ring, !(--max_count)))
			return;
		if (RB_WARN_ON(cpu_ring,
			       tb_is_reader_page(cpu_ring->tail_page)))
			return;
		local_set(&cpu_ring->commit_page->page->commit,
			  tb_page_write(cpu_ring->commit_page));
		tb_inc_page(&cpu_ring->commit_page);
		/* add barrier to keep gcc from optimizing too much */
		barrier();
	}
	while (tb_commit_index(cpu_ring) !=
	       tb_page_write(cpu_ring->commit_page)) {

		local_set(&cpu_ring->commit_page->page->commit,
			  tb_page_write(cpu_ring->commit_page));
		RB_WARN_ON(cpu_ring,
			   local_read(&cpu_ring->commit_page->page->commit) &
			   ~RB_WRITE_MASK);
		barrier();
	}

	/* again, keep gcc from optimizing */
	barrier();

	/*
	 * If an interrupt came in just after the first while loop
	 * and pushed the tail page forward, we will be left with
	 * a dangling commit that will never go forward.
	 */
	if (unlikely(cpu_ring->commit_page != READ_ONCE(cpu_ring->tail_page)))
		goto again;
}

static __always_inline void tb_end_commit(struct tb_per_cpu *cpu_ring)
{
	unsigned long commits;

	if (RB_WARN_ON(cpu_ring,
		       !local_read(&cpu_ring->committing)))
		return;

 again:
	commits = local_read(&cpu_ring->commits);
	/* synchronize with interrupts */
	barrier();
	if (local_read(&cpu_ring->committing) == 1)
		tb_set_commit_to_write(cpu_ring);

	local_dec(&cpu_ring->committing);

	/* synchronize with interrupts */
	barrier();

	/*
	 * Need to account for interrupts coming in between the
	 * updating of the commit page and the clearing of the
	 * committing counter.
	 */
	if (unlikely(local_read(&cpu_ring->commits) != commits) &&
	    !local_read(&cpu_ring->committing)) {
		local_inc(&cpu_ring->committing);
		goto again;
	}
}

static inline void tb_event_discard(struct tb_event *event)
{
	if (extended_time(event))
		event = skip_time_extend(event);

	/* array[0] holds the actual length for the discarded event */
	event->array[0] = tb_event_data_length(event) - RB_EVNT_HDR_SIZE;
	event->type_len = TB_TYPEPADDING;
	/* time delta must be non zero */
	if (!event->time_delta)
		event->time_delta = 1;
}

static void tb_commit(struct tb_per_cpu *cpu_ring,
		      struct tb_event *event)
{
	local_inc(&cpu_ring->entries);
	tb_end_commit(cpu_ring);
}

static __always_inline void
tb_wakeups(struct tb_ring *buffer, struct tb_per_cpu *cpu_ring)
{
	size_t nr_pages;
	size_t dirty;
	size_t full;

	if (buffer->irq_work.waiters_pending) {
		buffer->irq_work.waiters_pending = false;
		/* irq_work_queue() supplies it's own memory barriers */
		buffer->irq_work.wakeup(&buffer->irq_work);
	}

	if (cpu_ring->irq_work.waiters_pending) {
		cpu_ring->irq_work.waiters_pending = false;
		/* irq_work_queue() supplies it's own memory barriers */
		cpu_ring->irq_work.wakeup(&cpu_ring->irq_work);
	}

	if (cpu_ring->last_pages_touch == local_read(&cpu_ring->pages_touched))
		return;

	if (cpu_ring->reader_page == cpu_ring->commit_page)
		return;

	if (!cpu_ring->irq_work.full_waiters_pending)
		return;

	cpu_ring->last_pages_touch = local_read(&cpu_ring->pages_touched);

	full = cpu_ring->shortest_full;
	nr_pages = cpu_ring->nr_pages;
	dirty = tb_nr_dirty_pages(buffer, cpu_ring->cpu);
	if (full && nr_pages && (dirty * 100) <= full * nr_pages)
		return;

	cpu_ring->irq_work.wakeup_full = true;
	cpu_ring->irq_work.full_waiters_pending = false;
	/* irq_work_queue() supplies it's own memory barriers */
	cpu_ring->irq_work.wakeup(&cpu_ring->irq_work);
}

#ifdef CONFIG_RING_BUFFER_RECORD_RECURSION
# define do_tb_record_recursion()	\
	do_ftrace_record_recursion(_THIS_IP_, _RET_IP_)
#else
# define do_tb_record_recursion() do { } while (0)
#endif

/*
 * The lock and unlock are done within a preempt disable section.
 * The current_context per_cpu variable can only be modified
 * by the current task between lock and unlock. But it can
 * be modified more than once via an interrupt. To pass this
 * information from the lock to the unlock without having to
 * access the 'in_interrupt()' functions again (which do show
 * a bit of overhead in something as critical as function tracing,
 * we use a bitmask trick.
 *
 *  bit 1 =  NMI context
 *  bit 2 =  IRQ context
 *  bit 3 =  SoftIRQ context
 *  bit 4 =  normal context.
 *
 * This works because this is the order of contexts that can
 * preempt other contexts. A SoftIRQ never preempts an IRQ
 * context.
 *
 * When the context is determined, the corresponding bit is
 * checked and set (if it was set, then a recursion of that context
 * happened).
 *
 * On unlock, we need to clear this bit. To do so, just subtract
 * 1 from the current_context and AND it to itself.
 *
 * (binary)
 *  101 - 1 = 100
 *  101 & 100 = 100 (clearing bit zero)
 *
 *  1010 - 1 = 1001
 *  1010 & 1001 = 1000 (clearing bit 1)
 *
 * The least significant bit can be cleared this way, and it
 * just so happens that it is the same bit corresponding to
 * the current context.
 *
 * Now the TRANSITION bit breaks the above slightly. The TRANSITION bit
 * is set when a recursion is detected at the current context, and if
 * the TRANSITION bit is already set, it will fail the recursion.
 * This is needed because there's a lag between the changing of
 * interrupt context and updating the preempt count. In this case,
 * a false positive will be found. To handle this, one extra recursion
 * is allowed, and this is done by the TRANSITION bit. If the TRANSITION
 * bit is already set, then it is considered a recursion and the function
 * ends. Otherwise, the TRANSITION bit is set, and that bit is returned.
 *
 * On the tb_recursive_unlock(), the TRANSITION bit will be the first
 * to be cleared. Even if it wasn't the context that set it. That is,
 * if an interrupt comes in while NORMAL bit is set and the ring buffer
 * is called before preempt_count() is updated, since the check will
 * be on the NORMAL bit, the TRANSITION bit will then be set. If an
 * NMI then comes in, it will set the NMI bit, but when the NMI code
 * does the tb_recursive_unlock() it will clear the TRANSITION bit
 * and leave the NMI bit set. But this is fine, because the interrupt
 * code that set the TRANSITION bit will then clear the NMI bit when it
 * calls tb_recursive_unlock(). If another NMI comes in, it will
 * set the TRANSITION bit and continue.
 *
 * Note: The TRANSITION bit only handles a single transition between context.
 */

static __always_inline int
tb_recursive_lock(struct tb_per_cpu *cpu_ring)
{
	unsigned int val = cpu_ring->current_context;
	unsigned long pc = preempt_count();
	int bit;

	if (!(pc & (NMI_MASK | HARDIRQ_MASK | SOFTIRQ_OFFSET)))
		bit = RB_CTX_NORMAL;
	else
		bit = pc & NMI_MASK ? RB_CTX_NMI :
			pc & HARDIRQ_MASK ? RB_CTX_IRQ : RB_CTX_SOFTIRQ;

	if (unlikely(val & (1 << (bit + cpu_ring->nest)))) {
		/*
		 * It is possible that this was called by transitioning
		 * between interrupt context, and preempt_count() has not
		 * been updated yet. In this case, use the TRANSITION bit.
		 */
		bit = RB_CTX_TRANSITION;
		if (val & (1 << (bit + cpu_ring->nest))) {
			do_tb_record_recursion();
			return 1;
		}
	}

	val |= (1 << (bit + cpu_ring->nest));
	cpu_ring->current_context = val;

	return 0;
}

static __always_inline void
tb_recursive_unlock(struct tb_per_cpu *cpu_ring)
{
	cpu_ring->current_context &=
		cpu_ring->current_context - (1 << cpu_ring->nest);
}

/* The recursive locking above uses 5 bits */
#define NESTED_BITS 5

/**
 * tb_nest_start - Allow to trace while nested
 * @buffer: The ring buffer to modify
 *
 * The ring buffer has a safety mechanism to prevent recursion.
 * But there may be a case where a trace needs to be done while
 * tracing something else. In this case, calling this function
 * will allow this function to nest within a currently active
 * tb_lock_reserve().
 *
 * Call this function before calling another tb_lock_reserve() and
 * call tb_nest_end() after the nested tb_unlock_commit().
 */
void tb_nest_start(struct tb_ring *buffer)
{
	struct tb_per_cpu *cpu_ring;
	int cpu;

	/* Enabled by tb_nest_end() */
	preempt_disable_notrace();
	cpu = raw_smp_processor_id();
	cpu_ring = buffer->buffers[cpu];
	/* This is the shift value for the above recursive locking */
	cpu_ring->nest += NESTED_BITS;
}

/**
 * tb_nest_end - Allow to trace while nested
 * @buffer: The ring buffer to modify
 *
 * Must be called after tb_nest_start() and after the
 * tb_unlock_commit().
 */
void tb_nest_end(struct tb_ring *buffer)
{
	struct tb_per_cpu *cpu_ring;
	int cpu;

	/* disabled by tb_nest_start() */
	cpu = raw_smp_processor_id();
	cpu_ring = buffer->buffers[cpu];
	/* This is the shift value for the above recursive locking */
	cpu_ring->nest -= NESTED_BITS;
	preempt_enable_notrace();
}

/**
 * tb_unlock_commit - commit a reserved
 * @buffer: The buffer to commit to
 * @event: The event pointer to commit.
 *
 * This commits the data to the ring buffer, and releases any locks held.
 *
 * Must be paired with tb_lock_reserve.
 */
int tb_unlock_commit(struct tb_ring *buffer,
			      struct tb_event *event)
{
	struct tb_per_cpu *cpu_ring;
	int cpu = raw_smp_processor_id();

	cpu_ring = buffer->buffers[cpu];

	tb_commit(cpu_ring, event);

	tb_wakeups(buffer, cpu_ring);

	tb_recursive_unlock(cpu_ring);

	preempt_enable_notrace();

	return 0;
}

/* Special value to validate all deltas on a page. */
#define CHECK_FULL_PAGE		1L

#ifdef CONFIG_RING_BUFFER_VALIDATE_TIME_DELTAS
static void dump_buffer_page(struct buffer_data_page *bpage,
			     struct tb_event_info *info,
			     unsigned long tail)
{
	struct tb_event *event;
	u64 ts, delta;
	int e;

	ts = bpage->time_stamp;
	pr_info("  [%lld] PAGE TIME STAMP\n", ts);

	for (e = 0; e < tail; e += tb_event_length(event)) {

		event = (struct tb_event *)(bpage->data + e);

		switch (event->type_len) {

		case TB_TYPETIME_EXTEND:
			delta = tb_event_time_stamp(event);
			ts += delta;
			pr_info("  [%lld] delta:%lld TIME EXTEND\n", ts, delta);
			break;

		case TB_TYPETIME_STAMP:
			delta = tb_event_time_stamp(event);
			ts = delta;
			pr_info("  [%lld] absolute:%lld TIME STAMP\n", ts, delta);
			break;

		case TB_TYPEPADDING:
			ts += event->time_delta;
			pr_info("  [%lld] delta:%d PADDING\n", ts, event->time_delta);
			break;

		case TB_TYPEDATA:
			ts += event->time_delta;
			pr_info("  [%lld] delta:%d\n", ts, event->time_delta);
			break;

		default:
			break;
		}
	}
}

static DEFINE_PER_CPU(atomic_t, checking);
static atomic_t ts_dump;

/*
 * Check if the current event time stamp matches the deltas on
 * the buffer page.
 */
static void check_buffer(struct tb_per_cpu *cpu_ring,
			 struct tb_event_info *info,
			 unsigned long tail)
{
	struct tb_event *event;
	struct buffer_data_page *bpage;
	u64 ts, delta;
	bool full = false;
	int e;

	bpage = info->tail_page->page;

	if (tail == CHECK_FULL_PAGE) {
		full = true;
		tail = local_read(&bpage->commit);
	} else if (info->add_timestamp &
		   (RB_ADD_STAMP_FORCE | RB_ADD_STAMP_ABSOLUTE)) {
		/* Ignore events with absolute time stamps */
		return;
	}

	/*
	 * Do not check the first event (skip possible extends too).
	 * Also do not check if previous events have not been committed.
	 */
	if (tail <= 8 || tail > local_read(&bpage->commit))
		return;

	/*
	 * If this interrupted another event, 
	 */
	if (atomic_inc_return(this_cpu_ptr(&checking)) != 1)
		goto out;

	ts = bpage->time_stamp;

	for (e = 0; e < tail; e += tb_event_length(event)) {

		event = (struct tb_event *)(bpage->data + e);

		switch (event->type_len) {

		case TB_TYPETIME_EXTEND:
			delta = tb_event_time_stamp(event);
			ts += delta;
			break;

		case TB_TYPETIME_STAMP:
			delta = tb_event_time_stamp(event);
			ts = delta;
			break;

		case TB_TYPEPADDING:
			if (event->time_delta == 1)
				break;
			fallthrough;
		case TB_TYPEDATA:
			ts += event->time_delta;
			break;

		default:
			RB_WARN_ON(cpu_ring, 1);
		}
	}
	if ((full && ts > info->ts) ||
	    (!full && ts + info->delta != info->ts)) {
		/* If another report is happening, ignore this one */
		if (atomic_inc_return(&ts_dump) != 1) {
			atomic_dec(&ts_dump);
			goto out;
		}
		atomic_inc(&cpu_ring->record_disabled);
		/* There's some cases in boot up that this can happen */
		WARN_ON_ONCE(system_state != SYSTEM_BOOTING);
		pr_info("[CPU: %d]TIME DOES NOT MATCH expected:%lld actual:%lld delta:%lld before:%lld after:%lld%s\n",
			cpu_ring->cpu,
			ts + info->delta, info->ts, info->delta,
			info->before, info->after,
			full ? " (full)" : "");
		dump_buffer_page(bpage, info, tail);
		atomic_dec(&ts_dump);
		/* Do not re-enable checking */
		return;
	}
out:
	atomic_dec(this_cpu_ptr(&checking));
}
#else
static inline void check_buffer(struct tb_per_cpu *cpu_ring,
			 struct tb_event_info *info,
			 unsigned long tail)
{
}
#endif /* CONFIG_RING_BUFFER_VALIDATE_TIME_DELTAS */

static struct tb_event *
__tb_reserve_next(struct tb_per_cpu *cpu_ring,
		  struct tb_event_info *info)
{
	struct tb_event *event;
	struct buffer_page *tail_page;
	unsigned long tail, write, w;
	bool a_ok;
	bool b_ok;

	/* Don't let the compiler play games with cpu_ring->tail_page */
	tail_page = info->tail_page = READ_ONCE(cpu_ring->tail_page);

 /*A*/	w = local_read(&tail_page->write) & RB_WRITE_MASK;
	barrier();
	b_ok = tb_time_read(&cpu_ring->before_stamp, &info->before);
	a_ok = tb_time_read(&cpu_ring->write_stamp, &info->after);
	barrier();
	info->ts = tb_clock_local();

	if ((info->add_timestamp & RB_ADD_STAMP_ABSOLUTE)) {
		info->delta = info->ts;
	} else {
		/*
		 * If interrupting an event time update, we may need an
		 * absolute timestamp.
		 * Don't bother if this is the start of a new page (w == 0).
		 */
		if (unlikely(!a_ok || !b_ok || (info->before != info->after && w))) {
			info->add_timestamp |= RB_ADD_STAMP_FORCE | RB_ADD_STAMP_EXTEND;
			info->length += RB_LEN_TIME_EXTEND;
		} else {
			info->delta = info->ts - info->after;
			if (unlikely(test_time_stamp(info->delta))) {
				info->add_timestamp |= RB_ADD_STAMP_EXTEND;
				info->length += RB_LEN_TIME_EXTEND;
			}
		}
	}

 /*B*/	tb_time_set(&cpu_ring->before_stamp, info->ts);

 /*C*/	write = local_add_return(info->length, &tail_page->write);

	/* set write to only the index of the write */
	write &= RB_WRITE_MASK;

	tail = write - info->length;

	/* See if we shot pass the end of this buffer page */
	if (unlikely(write > BUF_PAGE_SIZE)) {
		/* before and after may now different, fix it up*/
		b_ok = tb_time_read(&cpu_ring->before_stamp, &info->before);
		a_ok = tb_time_read(&cpu_ring->write_stamp, &info->after);
		if (a_ok && b_ok && info->before != info->after)
			(void)tb_time_cmpxchg(&cpu_ring->before_stamp,
					      info->before, info->after);
		if (a_ok && b_ok)
			check_buffer(cpu_ring, info, CHECK_FULL_PAGE);
		return tb_move_tail(cpu_ring, tail, info);
	}

	if (likely(tail == w)) {
		u64 save_before;
		bool s_ok;

		/* Nothing interrupted us between A and C */
 /*D*/		tb_time_set(&cpu_ring->write_stamp, info->ts);
		barrier();
 /*E*/		s_ok = tb_time_read(&cpu_ring->before_stamp, &save_before);
		RB_WARN_ON(cpu_ring, !s_ok);
		if (likely(!(info->add_timestamp &
			     (RB_ADD_STAMP_FORCE | RB_ADD_STAMP_ABSOLUTE))))
			/* This did not interrupt any time update */
			info->delta = info->ts - info->after;
		else
			/* Just use full timestamp for interrupting event */
			info->delta = info->ts;
		barrier();
		check_buffer(cpu_ring, info, tail);
		if (unlikely(info->ts != save_before)) {
			/* SLOW PATH - Interrupted between C and E */

			a_ok = tb_time_read(&cpu_ring->write_stamp, &info->after);
			RB_WARN_ON(cpu_ring, !a_ok);

			/* Write stamp must only go forward */
			if (save_before > info->after) {
				/*
				 * We do not care about the result, only that
				 * it gets updated atomically.
				 */
				(void)tb_time_cmpxchg(&cpu_ring->write_stamp,
						      info->after, save_before);
			}
		}
	} else {
		u64 ts;
		/* SLOW PATH - Interrupted between A and C */
		a_ok = tb_time_read(&cpu_ring->write_stamp, &info->after);
		/* Was interrupted before here, write_stamp must be valid */
		RB_WARN_ON(cpu_ring, !a_ok);
		ts = tb_clock_local();
		barrier();
 /*E*/		if (write == (local_read(&tail_page->write) & RB_WRITE_MASK) &&
		    info->after < ts &&
		    tb_time_cmpxchg(&cpu_ring->write_stamp,
				    info->after, ts)) {
			/* Nothing came after this event between C and E */
			info->delta = ts - info->after;
		} else {
			/*
			 * Interrupted between C and E:
			 * Lost the previous events time stamp. Just set the
			 * delta to zero, and this will be the same time as
			 * the event this event interrupted. And the events that
			 * came after this will still be correct (as they would
			 * have built their delta on the previous event.
			 */
			info->delta = 0;
		}
		info->ts = ts;
		info->add_timestamp &= ~RB_ADD_STAMP_FORCE;
	}

	/*
	 * If this is the first commit on the page, then it has the same
	 * timestamp as the page itself.
	 */
	if (unlikely(!tail && !(info->add_timestamp &
				(RB_ADD_STAMP_FORCE | RB_ADD_STAMP_ABSOLUTE))))
		info->delta = 0;

	/* We reserved something on the buffer */

	event = __tb_page_index(tail_page, tail);
	tb_update_event(cpu_ring, event, info);

	local_inc(&tail_page->entries);

	/*
	 * If this is the first commit on the page, then update
	 * its timestamp.
	 */
	if (unlikely(!tail))
		tail_page->page->time_stamp = info->ts;

	/* account for these added bytes */
	local_add(info->length, &cpu_ring->entries_bytes);

	return event;
}

static __always_inline struct tb_event *
tb_reserve_next_event(struct tb_ring *buffer,
		      struct tb_per_cpu *cpu_ring,
		      unsigned long length)
{
	struct tb_event *event;
	struct tb_event_info info;
	int nr_loops = 0;
	int add_ts_default;

	tb_start_commit(cpu_ring);
	/* The commit page can not change after this */

#ifdef CONFIG_RING_BUFFER_ALLOW_SWAP
	/*
	 * Due to the ability to swap a cpu buffer from a buffer
	 * it is possible it was swapped before we committed.
	 * (committing stops a swap). We check for it here and
	 * if it happened, we have to fail the write.
	 */
	barrier();
	if (unlikely(READ_ONCE(cpu_ring->buffer) != buffer)) {
		local_dec(&cpu_ring->committing);
		local_dec(&cpu_ring->commits);
		return NULL;
	}
#endif

	info.data = length;
	info.length = tb_calculate_event_length(length);

	if (tb_time_stamp_abs(cpu_ring->buffer)) {
		add_ts_default = RB_ADD_STAMP_ABSOLUTE;
		info.length += RB_LEN_TIME_EXTEND;
	} else {
		add_ts_default = RB_ADD_STAMP_NONE;
	}

 again:
	info.add_timestamp = add_ts_default;
	info.delta = 0;

	/*
	 * We allow for interrupts to reenter here and do a trace.
	 * If one does, it will cause this original code to loop
	 * back here. Even with heavy interrupts happening, this
	 * should only happen a few times in a row. If this happens
	 * 1000 times in a row, there must be either an interrupt
	 * storm or we have something buggy.
	 * Bail!
	 */
	if (RB_WARN_ON(cpu_ring, ++nr_loops > 1000))
		goto out_fail;

	event = __tb_reserve_next(cpu_ring, &info);

	if (unlikely(PTR_ERR(event) == -EAGAIN)) {
		if (info.add_timestamp & (RB_ADD_STAMP_FORCE | RB_ADD_STAMP_EXTEND))
			info.length -= RB_LEN_TIME_EXTEND;
		goto again;
	}

	if (likely(event))
		return event;
 out_fail:
	tb_end_commit(cpu_ring);
	return NULL;
}

/**
 * tb_lock_reserve - reserve a part of the buffer
 * @buffer: the ring buffer to reserve from
 * @length: the length of the data to reserve (excluding event header)
 *
 * Returns a reserved event on the ring buffer to copy directly to.
 * The user of this interface will need to get the body to write into
 * and can use the tb_event_data() interface.
 *
 * The length is the length of the data needed, not the event length
 * which also includes the event header.
 *
 * Must be paired with tb_unlock_commit, unless NULL is returned.
 * If NULL is returned, then nothing has been allocated or locked.
 */
struct tb_event *
tb_lock_reserve(struct tb_ring *buffer, unsigned long length)
{
	struct tb_per_cpu *cpu_ring;
	struct tb_event *event;
	int cpu;

	/* If we are tracing schedule, we don't want to recurse */
	preempt_disable_notrace();

	if (unlikely(atomic_read(&buffer->record_disabled)))
		goto out;

	cpu = raw_smp_processor_id();

	if (unlikely(!cpumask_test_cpu(cpu, buffer->cpumask)))
		goto out;

	cpu_ring = buffer->buffers[cpu];

	if (unlikely(atomic_read(&cpu_ring->record_disabled)))
		goto out;

	local_inc(&cpu_ring->produced_events);
	cpu_ring->produced_size += length;

	if (unlikely(length > BUF_MAX_DATA_SIZE)) {
		if (length > cpu_ring->max_event_size)
			cpu_ring->max_event_size = length;
		goto out_reject;
	}

	if (unlikely(tb_recursive_lock(cpu_ring)))
		goto out_reject;

	event = tb_reserve_next_event(buffer, cpu_ring, length);
	if (!event)
		goto out_unlock;

	return event;

 out_unlock:
	tb_recursive_unlock(cpu_ring);
 out_reject:
	local_inc(&cpu_ring->rejected_events);
	cpu_ring->rejected_size += length;
 out:
	preempt_enable_notrace();
	return NULL;
}

/*
 * Decrement the entries to the page that an event is on.
 * The event does not even need to exist, only the pointer
 * to the page it is on. This may only be called before the commit
 * takes place.
 */
static inline void
tb_decrement_entry(struct tb_per_cpu *cpu_ring,
		   struct tb_event *event)
{
	unsigned long addr = (unsigned long)event;
	struct buffer_page *bpage = cpu_ring->commit_page;
	struct buffer_page *start;

	addr &= PAGE_MASK;

	/* Do the likely case first */
	if (likely(bpage->page == (void *)addr)) {
		local_dec(&bpage->entries);
		return;
	}

	/*
	 * Because the commit page may be on the reader page we
	 * start with the next page and check the end loop there.
	 */
	tb_inc_page(&bpage);
	start = bpage;
	do {
		if (bpage->page == (void *)addr) {
			local_dec(&bpage->entries);
			return;
		}
		tb_inc_page(&bpage);
	} while (bpage != start);

	/* commit not part of this buffer?? */
	RB_WARN_ON(cpu_ring, 1);
}

/**
 * tb_discard_commit - discard an event that has not been committed
 * @buffer: the ring buffer
 * @event: non committed event to discard
 *
 * Sometimes an event that is in the ring buffer needs to be ignored.
 * This function lets the user discard an event in the ring buffer
 * and then that event will not be read later.
 *
 * This function only works if it is called before the item has been
 * committed. It will try to free the event from the ring buffer
 * if another event has not been added behind it.
 *
 * If another event has been added behind it, it will set the event
 * up as discarded, and perform the commit.
 *
 * If this function is called, do not call tb_unlock_commit on
 * the event.
 */
void tb_discard_commit(struct tb_ring *buffer,
				struct tb_event *event)
{
	struct tb_per_cpu *cpu_ring;
	int cpu;

	/* The event is discarded regardless */
	tb_event_discard(event);

	cpu = smp_processor_id();
	cpu_ring = buffer->buffers[cpu];
	local_inc(&cpu_ring->discarded_events);
	cpu_ring->discarded_size += tb_event_data_length(event);

	/*
	 * This must only be called if the event has not been
	 * committed yet. Thus we can assume that preemption
	 * is still disabled.
	 */
	RB_WARN_ON(buffer, !local_read(&cpu_ring->committing));

	tb_decrement_entry(cpu_ring, event);
	if (tb_try_to_discard(cpu_ring, event))
		goto out;

 out:
	tb_end_commit(cpu_ring);

	tb_recursive_unlock(cpu_ring);

	preempt_enable_notrace();

}

/**
 * tb_write - write data to the buffer without reserving
 * @buffer: The ring buffer to write to.
 * @length: The length of the data being written (excluding the event header)
 * @data: The data to write to the buffer.
 *
 * This is like tb_lock_reserve and tb_unlock_commit as
 * one function. If you already have the data to write to the buffer, it
 * may be easier to simply call this function.
 *
 * Note, like tb_lock_reserve, the length is the length of the data
 * and not the length of the event which would hold the header.
 */
int tb_write(struct tb_ring *buffer,
		      unsigned long length,
		      void *data)
{
	struct tb_per_cpu *cpu_ring;
	struct tb_event *event;
	void *body;
	int ret = -EBUSY;
	int cpu;

	preempt_disable_notrace();

	if (atomic_read(&buffer->record_disabled))
		goto out;

	cpu = raw_smp_processor_id();

	if (!cpumask_test_cpu(cpu, buffer->cpumask))
		goto out;

	cpu_ring = buffer->buffers[cpu];

	if (atomic_read(&cpu_ring->record_disabled))
		goto out;

	local_inc(&cpu_ring->produced_events);
	cpu_ring->produced_size += length;

	if (length > BUF_MAX_DATA_SIZE) {
		if (length > cpu_ring->max_event_size)
			cpu_ring->max_event_size = length;
		goto out_reject;
	}

	if (unlikely(tb_recursive_lock(cpu_ring)))
		goto out_reject;

	event = tb_reserve_next_event(buffer, cpu_ring, length);
	if (!event)
		goto out_unlock;

	body = tb_event_data_start(event);

	memcpy(body, data, length);

	tb_commit(cpu_ring, event);

	tb_wakeups(buffer, cpu_ring);

	tb_recursive_unlock(cpu_ring);
	preempt_enable_notrace();
	return 0;

 out_unlock:
	tb_recursive_unlock(cpu_ring);
 out_reject:
	local_inc(&cpu_ring->rejected_events);
	cpu_ring->rejected_size += length;
 out:
	preempt_enable_notrace();

	return ret;
}

static bool tb_per_cpu_empty(struct tb_per_cpu *cpu_ring)
{
	struct buffer_page *reader = cpu_ring->reader_page;
	struct buffer_page *head = tb_set_head_page(cpu_ring);
	struct buffer_page *commit = cpu_ring->commit_page;

	/* In case of error, head will be NULL */
	if (unlikely(!head))
		return true;

	/* Reader should exhaust content in reader page */
	if (reader->read != tb_page_commit(reader))
		return false;

	/*
	 * If writers are committing on the reader page, knowing all
	 * committed content has been read, the ring buffer is empty.
	 */
	if (commit == reader)
		return true;

	/*
	 * If writers are committing on a page other than reader page
	 * and head page, there should always be content to read.
	 */
	if (commit != head)
		return false;

	/*
	 * Writers are committing on the head page, we just need
	 * to care about there're committed data, and the reader will
	 * swap reader page with head page when it is to read data.
	 */
	return tb_page_commit(commit) == 0;
}

/**
 * tb_record_disable - stop all writes into the buffer
 * @buffer: The ring buffer to stop writes to.
 *
 * This prevents all writes to the buffer. Any attempt to write
 * to the buffer after this will fail and return NULL.
 *
 * The caller should call synchronize_rcu() after this.
 */
 void tb_record_disable(struct tb_ring *buffer)
{
	atomic_inc(&buffer->record_disabled);
}

/**
 * tb_record_enable - enable writes to the buffer
 * @buffer: The ring buffer to enable writes
 *
 * Note, multiple disables will need the same number of enables
 * to truly enable the writing (much like preempt_disable).
 */
void tb_record_enable(struct tb_ring *buffer)
{
	atomic_dec(&buffer->record_disabled);
}

/**
 * tb_record_off - stop all writes into the buffer
 * @buffer: The ring buffer to stop writes to.
 *
 * This prevents all writes to the buffer. Any attempt to write
 * to the buffer after this will fail and return NULL.
 *
 * This is different than tb_record_disable() as
 * it works like an on/off switch, where as the disable() version
 * must be paired with a enable().
 */
void tb_record_off(struct tb_ring *buffer)
{
	unsigned int rd;
	unsigned int new_rd;

	do {
		rd = atomic_read(&buffer->record_disabled);
		new_rd = rd | RB_BUFFER_OFF;
	} while (atomic_cmpxchg(&buffer->record_disabled, rd, new_rd) != rd);
}

/**
 * tb_record_on - restart writes into the buffer
 * @buffer: The ring buffer to start writes to.
 *
 * This enables all writes to the buffer that was disabled by
 * tb_record_off().
 *
 * This is different than tb_record_enable() as
 * it works like an on/off switch, where as the enable() version
 * must be paired with a disable().
 */
void tb_record_on(struct tb_ring *buffer)
{
	unsigned int rd;
	unsigned int new_rd;

	do {
		rd = atomic_read(&buffer->record_disabled);
		new_rd = rd & ~RB_BUFFER_OFF;
	} while (atomic_cmpxchg(&buffer->record_disabled, rd, new_rd) != rd);
}

/**
 * tb_record_is_on - return true if the ring buffer can write
 * @buffer: The ring buffer to see if write is enabled
 *
 * Returns true if the ring buffer is in a state that it accepts writes.
 */
bool tb_record_is_on(struct tb_ring *buffer)
{
	return !atomic_read(&buffer->record_disabled);
}

/**
 * tb_record_is_set_on - return true if the ring buffer is set writable
 * @buffer: The ring buffer to see if write is set enabled
 *
 * Returns true if the ring buffer is set writable by tb_record_on().
 * Note that this does NOT mean it is in a writable state.
 *
 * It may return true when the ring buffer has been disabled by
 * tb_record_disable(), as that is a temporary disabling of
 * the ring buffer.
 */
bool tb_record_is_set_on(struct tb_ring *buffer)
{
	return !(atomic_read(&buffer->record_disabled) & RB_BUFFER_OFF);
}

/**
 * tb_record_disable_cpu - stop all writes into the cpu_ring
 * @buffer: The ring buffer to stop writes to.
 * @cpu: The CPU buffer to stop
 *
 * This prevents all writes to the buffer. Any attempt to write
 * to the buffer after this will fail and return NULL.
 *
 * The caller should call synchronize_rcu() after this.
 */
void tb_record_disable_cpu(struct tb_ring *buffer, int cpu)
{
	struct tb_per_cpu *cpu_ring;

	if (!cpumask_test_cpu(cpu, buffer->cpumask))
		return;

	cpu_ring = buffer->buffers[cpu];
	atomic_inc(&cpu_ring->record_disabled);
}

/**
 * tb_record_enable_cpu - enable writes to the buffer
 * @buffer: The ring buffer to enable writes
 * @cpu: The CPU to enable.
 *
 * Note, multiple disables will need the same number of enables
 * to truly enable the writing (much like preempt_disable).
 */
void tb_record_enable_cpu(struct tb_ring *buffer, int cpu)
{
	struct tb_per_cpu *cpu_ring;

	if (!cpumask_test_cpu(cpu, buffer->cpumask))
		return;

	cpu_ring = buffer->buffers[cpu];
	atomic_dec(&cpu_ring->record_disabled);
}

/*
 * The total entries in the ring buffer is the running counter
 * of entries entered into the ring buffer, minus the sum of
 * the entries read from the ring buffer and the number of
 * entries that were overwritten.
 */
static inline unsigned long
tb_num_of_entries(struct tb_per_cpu *cpu_ring)
{
	return local_read(&cpu_ring->entries) -
		(local_read(&cpu_ring->overrun) + cpu_ring->read);
}

/**
 * tb_oldest_event_ts - get the oldest event timestamp from the buffer
 * @buffer: The ring buffer
 * @cpu: The per CPU buffer to read from.
 */
u64 tb_oldest_event_ts(struct tb_ring *buffer, int cpu)
{
	unsigned long flags;
	struct tb_per_cpu *cpu_ring;
	struct buffer_page *bpage;
	u64 ret = 0;

	if (!cpumask_test_cpu(cpu, buffer->cpumask))
		return 0;

	cpu_ring = buffer->buffers[cpu];
	raw_spin_lock_irqsave(&cpu_ring->reader_lock, flags);
	/*
	 * if the tail is on reader_page, oldest time stamp is on the reader
	 * page
	 */
	if (cpu_ring->tail_page == cpu_ring->reader_page)
		bpage = cpu_ring->reader_page;
	else
		bpage = tb_set_head_page(cpu_ring);
	if (bpage)
		ret = bpage->page->time_stamp;
	raw_spin_unlock_irqrestore(&cpu_ring->reader_lock, flags);

	return ret;
}

/**
 * tb_bytes_cpu - get the number of bytes consumed in a cpu buffer
 * @buffer: The ring buffer
 * @cpu: The per CPU buffer to read from.
 */
unsigned long tb_bytes_cpu(struct tb_ring *buffer, int cpu)
{
	struct tb_per_cpu *cpu_ring;
	unsigned long ret;

	if (!cpumask_test_cpu(cpu, buffer->cpumask))
		return 0;

	cpu_ring = buffer->buffers[cpu];
	ret = local_read(&cpu_ring->entries_bytes) - cpu_ring->read_bytes;

	return ret;
}

/**
 * tb_entries_cpu - get the number of entries in a cpu buffer
 * @buffer: The ring buffer
 * @cpu: The per CPU buffer to get the entries from.
 */
unsigned long tb_entries_cpu(struct tb_ring *buffer, int cpu)
{
	struct tb_per_cpu *cpu_ring;

	if (!cpumask_test_cpu(cpu, buffer->cpumask))
		return 0;

	cpu_ring = buffer->buffers[cpu];

	return tb_num_of_entries(cpu_ring);
}

/**
 * tb_overrun_cpu - get the number of overruns caused by the ring
 * buffer wrapping around (only if TB_FL_OVERWRITE is on).
 * @buffer: The ring buffer
 * @cpu: The per CPU buffer to get the number of overruns from
 */
unsigned long tb_overrun_cpu(struct tb_ring *buffer, int cpu)
{
	struct tb_per_cpu *cpu_ring;
	unsigned long ret;

	if (!cpumask_test_cpu(cpu, buffer->cpumask))
		return 0;

	cpu_ring = buffer->buffers[cpu];
	ret = local_read(&cpu_ring->overrun);

	return ret;
}

/**
 * tb_commit_overrun_cpu - get the number of overruns caused by
 * commits failing due to the buffer wrapping around while there are uncommitted
 * events, such as during an interrupt storm.
 * @buffer: The ring buffer
 * @cpu: The per CPU buffer to get the number of overruns from
 */
unsigned long
tb_commit_overrun_cpu(struct tb_ring *buffer, int cpu)
{
	struct tb_per_cpu *cpu_ring;
	unsigned long ret;

	if (!cpumask_test_cpu(cpu, buffer->cpumask))
		return 0;

	cpu_ring = buffer->buffers[cpu];
	ret = local_read(&cpu_ring->commit_overrun);

	return ret;
}

/**
 * tb_dropped_events_cpu - get the number of dropped events caused by
 * the ring buffer filling up (only if TB_FL_OVERWRITE is off).
 * @buffer: The ring buffer
 * @cpu: The per CPU buffer to get the number of overruns from
 */
unsigned long
tb_dropped_events_cpu(struct tb_ring *buffer, int cpu)
{
	struct tb_per_cpu *cpu_ring;
	unsigned long ret;

	if (!cpumask_test_cpu(cpu, buffer->cpumask))
		return 0;

	cpu_ring = buffer->buffers[cpu];
	ret = local_read(&cpu_ring->dropped_events);

	return ret;
}

/**
 * tb_read_events_cpu - get the number of events successfully read
 * @buffer: The ring buffer
 * @cpu: The per CPU buffer to get the number of events read
 */
unsigned long
tb_read_events_cpu(struct tb_ring *buffer, int cpu)
{
	struct tb_per_cpu *cpu_ring;

	if (!cpumask_test_cpu(cpu, buffer->cpumask))
		return 0;

	cpu_ring = buffer->buffers[cpu];
	return cpu_ring->read;
}

/**
 * tb_entries - get the number of entries in a buffer
 * @buffer: The ring buffer
 *
 * Returns the total number of entries in the ring buffer
 * (all CPU entries)
 */
unsigned long tb_entries(struct tb_ring *buffer)
{
	struct tb_per_cpu *cpu_ring;
	unsigned long entries = 0;
	int cpu;

	/* if you care about this being correct, lock the buffer */
	for_each_buffer_cpu(buffer, cpu) {
		cpu_ring = buffer->buffers[cpu];
		entries += tb_num_of_entries(cpu_ring);
	}

	return entries;
}

/**
 * tb_overruns - get the number of overruns in buffer
 * @buffer: The ring buffer
 *
 * Returns the total number of overruns in the ring buffer
 * (all CPU entries)
 */
unsigned long tb_overruns(struct tb_ring *buffer)
{
	struct tb_per_cpu *cpu_ring;
	unsigned long overruns = 0;
	int cpu;

	/* if you care about this being correct, lock the buffer */
	for_each_buffer_cpu(buffer, cpu) {
		cpu_ring = buffer->buffers[cpu];
		overruns += local_read(&cpu_ring->overrun);
	}

	return overruns;
}

static void
tb_update_read_stamp(struct tb_per_cpu *cpu_ring,
		     struct tb_event *event)
{
	u64 delta;

	switch (event->type_len) {
	case TB_TYPEPADDING:
		return;

	case TB_TYPETIME_EXTEND:
		delta = tb_event_time_stamp(event);
		cpu_ring->read_stamp += delta;
		return;

	case TB_TYPETIME_STAMP:
		delta = tb_event_time_stamp(event);
		cpu_ring->read_stamp = delta;
		return;

	case TB_TYPEDATA:
		cpu_ring->read_stamp += event->time_delta;
		return;

	default:
		RB_WARN_ON(cpu_ring, 1);
	}
	return;
}

static struct buffer_page *
tb_get_reader_page(struct tb_per_cpu *cpu_ring)
{
	struct buffer_page *reader = NULL;
	unsigned long overwrite;
	unsigned long flags;
	int nr_loops = 0;
	int ret;

	local_irq_save(flags);
	arch_spin_lock(&cpu_ring->lock);

 again:
	/*
	 * This should normally only loop twice. But because the
	 * start of the reader inserts an empty page, it causes
	 * a case where we will loop three times. There should be no
	 * reason to loop four times (that I know of).
	 */
	if (RB_WARN_ON(cpu_ring, ++nr_loops > 3)) {
		reader = NULL;
		goto out;
	}

	reader = cpu_ring->reader_page;

	/* If there's more to read, return this page */
	if (cpu_ring->reader_page->read < tb_page_size(reader))
		goto out;

	/* Never should we have an index greater than the size */
	if (RB_WARN_ON(cpu_ring,
		       cpu_ring->reader_page->read > tb_page_size(reader)))
		goto out;

	/* check if we caught up to the tail */
	reader = NULL;
	if (cpu_ring->commit_page == cpu_ring->reader_page)
		goto out;

	/* Don't bother swapping if the ring buffer is empty */
	if (tb_num_of_entries(cpu_ring) == 0)
		goto out;

	/*
	 * Reset the reader page to size zero.
	 */
	local_set(&cpu_ring->reader_page->write, 0);
	local_set(&cpu_ring->reader_page->entries, 0);
	local_set(&cpu_ring->reader_page->page->commit, 0);
	cpu_ring->reader_page->real_end = 0;

 spin:
	/*
	 * Splice the empty reader page into the list around the head.
	 */
	reader = tb_set_head_page(cpu_ring);
	if (!reader)
		goto out;
	cpu_ring->reader_page->list.next = tb_list_head(reader->list.next);
	cpu_ring->reader_page->list.prev = reader->list.prev;

	/*
	 * cpu_ring->pages just needs to point to the buffer, it
	 *  has no specific buffer page to point to. Lets move it out
	 *  of our way so we don't accidentally swap it.
	 */
	cpu_ring->pages = reader->list.prev;

	/* The reader page will be pointing to the new head */
	tb_set_list_to_head(&cpu_ring->reader_page->list);

	/*
	 * We want to make sure we read the overruns after we set up our
	 * pointers to the next object. The writer side does a
	 * cmpxchg to cross pages which acts as the mb on the writer
	 * side. Note, the reader will constantly fail the swap
	 * while the writer is updating the pointers, so this
	 * guarantees that the overwrite recorded here is the one we
	 * want to compare with the last_overrun.
	 */
	smp_mb();
	overwrite = local_read(&(cpu_ring->overrun));

	/*
	 * Here's the tricky part.
	 *
	 * We need to move the pointer past the header page.
	 * But we can only do that if a writer is not currently
	 * moving it. The page before the header page has the
	 * flag bit '1' set if it is pointing to the page we want.
	 * but if the writer is in the process of moving it
	 * than it will be '2' or already moved '0'.
	 */

	ret = tb_head_page_replace(reader, cpu_ring->reader_page);

	/*
	 * If we did not convert it, then we must try again.
	 */
	if (!ret)
		goto spin;

	/*
	 * Yay! We succeeded in replacing the page.
	 *
	 * Now make the new head point back to the reader page.
	 */
	tb_list_head(reader->list.next)->prev = &cpu_ring->reader_page->list;
	tb_inc_page(&cpu_ring->head_page);

	local_inc(&cpu_ring->pages_read);

	/* Finally update the reader page to the new head */
	cpu_ring->reader_page = reader;
	cpu_ring->reader_page->read = 0;

	if (overwrite != cpu_ring->last_overrun) {
		cpu_ring->lost_events = overwrite - cpu_ring->last_overrun;
		cpu_ring->last_overrun = overwrite;
	}

	goto again;

 out:
	/* Update the read_stamp on the first event */
	if (reader && reader->read == 0)
		cpu_ring->read_stamp = reader->page->time_stamp;

	arch_spin_unlock(&cpu_ring->lock);
	local_irq_restore(flags);

	return reader;
}

static void tb_advance_reader(struct tb_per_cpu *cpu_ring)
{
	struct tb_event *event;
	struct buffer_page *reader;
	unsigned length;

	reader = tb_get_reader_page(cpu_ring);

	/* This function should not be called when buffer is empty */
	if (RB_WARN_ON(cpu_ring, !reader))
		return;

	event = tb_reader_event(cpu_ring);

	if (event->type_len <= TB_TYPEDATA_TYPE_LEN_MAX)
		cpu_ring->read++;

	tb_update_read_stamp(cpu_ring, event);

	length = tb_event_length(event);
	cpu_ring->reader_page->read += length;
}

int tb_lost_events(struct tb_per_cpu *cpu_ring)
{
	return cpu_ring->lost_events;
}

struct tb_event *
tb_buffer_peek(struct tb_per_cpu *cpu_ring, u64 *ts,
	       unsigned long *lost_events)
{
	struct tb_event *event;
	struct buffer_page *reader;
	int nr_loops = 0;

	if (ts)
		*ts = 0;
 again:
	/*
	 * We repeat when a time extend is encountered.
	 * Since the time extend is always attached to a data event,
	 * we should never loop more than once.
	 * (We never hit the following condition more than twice).
	 */
	if (RB_WARN_ON(cpu_ring, ++nr_loops > 2))
		return NULL;

	reader = tb_get_reader_page(cpu_ring);
	if (!reader)
		return NULL;

	event = tb_reader_event(cpu_ring);

	switch (event->type_len) {
	case TB_TYPEPADDING:
		if (tb_null_event(event))
			RB_WARN_ON(cpu_ring, 1);
		/*
		 * Because the writer could be discarding every
		 * event it creates (which would probably be bad)
		 * if we were to go back to "again" then we may never
		 * catch up, and will trigger the warn on, or lock
		 * the box. Return the padding, and we will release
		 * the current locks, and try again.
		 */
		return event;

	case TB_TYPETIME_EXTEND:
		/* Internal data, OK to advance */
		tb_advance_reader(cpu_ring);
		goto again;

	case TB_TYPETIME_STAMP:
		if (ts) {
			*ts = tb_event_time_stamp(event);
			tb_normalize_time_stamp(cpu_ring->buffer,
							 cpu_ring->cpu, ts);
		}
		/* Internal data, OK to advance */
		tb_advance_reader(cpu_ring);
		goto again;

	case TB_TYPEDATA:
		if (ts && !(*ts)) {
			*ts = cpu_ring->read_stamp + event->time_delta;
			tb_normalize_time_stamp(cpu_ring->buffer,
							 cpu_ring->cpu, ts);
		}
		if (lost_events)
			*lost_events = tb_lost_events(cpu_ring);
		return event;

	default:
		RB_WARN_ON(cpu_ring, 1);
	}

	return NULL;
}

static inline bool tb_reader_lock(struct tb_per_cpu *cpu_ring)
{
	if (likely(!in_nmi())) {
		raw_spin_lock(&cpu_ring->reader_lock);
		return true;
	}

	/*
	 * If an NMI die dumps out the content of the ring buffer
	 * trylock must be used to prevent a deadlock if the NMI
	 * preempted a task that holds the ring buffer locks. If
	 * we get the lock then all is fine, if not, then continue
	 * to do the read, but this can corrupt the ring buffer,
	 * so it must be permanently disabled from future writes.
	 * Reading from NMI is a oneshot deal.
	 */
	if (raw_spin_trylock(&cpu_ring->reader_lock))
		return true;

	/* Continue without locking, but disable the ring buffer */
	atomic_inc(&cpu_ring->record_disabled);
	return false;
}

static inline void
tb_reader_unlock(struct tb_per_cpu *cpu_ring, bool locked)
{
	if (likely(locked))
		raw_spin_unlock(&cpu_ring->reader_lock);
	return;
}

/**
 * tb_peek - peek at the next event to be read
 * @buffer: The ring buffer to read
 * @cpu: The cpu to peak at
 * @ts: The timestamp counter of this event.
 * @lost_events: a variable to store if events were lost (may be NULL)
 *
 * This will return the event that will be read next, but does
 * not consume the data.
 */
struct tb_event *
tb_peek(struct tb_ring *buffer, int cpu, u64 *ts,
		 unsigned long *lost_events)
{
	struct tb_per_cpu *cpu_ring = buffer->buffers[cpu];
	struct tb_event *event;
	unsigned long flags;
	bool dolock;

	if (!cpumask_test_cpu(cpu, buffer->cpumask))
		return NULL;

 again:
	local_irq_save(flags);
	dolock = tb_reader_lock(cpu_ring);
	event = tb_buffer_peek(cpu_ring, ts, lost_events);
	if (event && event->type_len == TB_TYPEPADDING)
		tb_advance_reader(cpu_ring);
	tb_reader_unlock(cpu_ring, dolock);
	local_irq_restore(flags);

	if (event && event->type_len == TB_TYPEPADDING)
		goto again;

	return event;
}

/**
 * tb_consume - return an event and consume it
 * @buffer: The ring buffer to get the next event from
 * @cpu: the cpu to read the buffer from
 * @ts: a variable to store the timestamp (may be NULL)
 * @lost_events: a variable to store if events were lost (may be NULL)
 *
 * Returns the next event in the ring buffer, and that event is consumed.
 * Meaning, that sequential reads will keep returning a different event,
 * and eventually empty the ring buffer if the producer is slower.
 */
struct tb_event *
tb_consume(struct tb_ring *buffer, int cpu, u64 *ts,
		    unsigned long *lost_events)
{
	struct tb_per_cpu *cpu_ring;
	struct tb_event *event = NULL;
	unsigned long flags;
	bool dolock;

 again:
	/* might be called in atomic */
	preempt_disable();

	if (!cpumask_test_cpu(cpu, buffer->cpumask))
		goto out;

	cpu_ring = buffer->buffers[cpu];
	local_irq_save(flags);
	dolock = tb_reader_lock(cpu_ring);

	event = tb_buffer_peek(cpu_ring, ts, lost_events);
	if (event) {
		local_inc(&cpu_ring->consumed_events);
		cpu_ring->consumed_size += tb_event_data_length(event);
		cpu_ring->lost_events = 0;
		tb_advance_reader(cpu_ring);
	}

	tb_reader_unlock(cpu_ring, dolock);
	local_irq_restore(flags);

 out:
	preempt_enable();

	if (event && event->type_len == TB_TYPEPADDING)
		goto again;

	return event;
}

/**
 * tb_size - return the size of the ring buffer (in bytes)
 * @buffer: The ring buffer.
 * @cpu: The CPU to get ring buffer size from.
 */
unsigned long tb_size(struct tb_ring *buffer, int cpu)
{
	/*
	 * Earlier, this method returned
	 *	BUF_PAGE_SIZE * buffer->nr_pages
	 * Since the nr_pages field is now removed, we have converted this to
	 * return the per cpu buffer value.
	 */
	if (!cpumask_test_cpu(cpu, buffer->cpumask))
		return 0;

	return BUF_PAGE_SIZE * buffer->buffers[cpu]->nr_pages;
}

/**
 * tb_empty_cpu - is a cpu buffer of a ring buffer empty?
 * @buffer: The ring buffer
 * @cpu: The CPU buffer to test
 */
bool tb_empty_cpu(struct tb_ring *buffer, int cpu)
{
	struct tb_per_cpu *cpu_ring;
	unsigned long flags;
	bool dolock;
	int ret;

	if (!cpumask_test_cpu(cpu, buffer->cpumask))
		return true;

	cpu_ring = buffer->buffers[cpu];
	local_irq_save(flags);
	dolock = tb_reader_lock(cpu_ring);
	ret = tb_per_cpu_empty(cpu_ring);
	tb_reader_unlock(cpu_ring, dolock);
	local_irq_restore(flags);

	return ret;
}

/**
 * rind_buffer_empty - is the ring buffer empty?
 * @buffer: The ring buffer to test
 */
bool tb_empty(struct tb_ring *ring)
{
	int cpu;

	/* yes this is racy, but if you don't like the race, lock the buffer */
	for_each_buffer_cpu(ring, cpu) {
		if (!tb_empty_cpu(ring, cpu))
			return false;
	}

	return true;
}

void tb_stat(struct tb_ring *ring, struct tb_stat *stat)
{
	int cpu;

	if (IS_ERR_OR_NULL(stat))
		return;

	memset(stat, 0, sizeof(*stat));
	for_each_buffer_cpu(ring, cpu) {

		struct tb_per_cpu *cpu_ring = ring->buffers[cpu];
		stat->num_cpu_rings += 1;

		stat->produced_events += local_read(&cpu_ring->produced_events);
		stat->rejected_events += local_read(&cpu_ring->rejected_events);
		stat->dropped_events += local_read(&cpu_ring->dropped_events);
		stat->discarded_events += local_read(&cpu_ring->discarded_events);
		stat->overwritten_events += local_read(&cpu_ring->overrun);
		stat->consumed_events += local_read(&cpu_ring->consumed_events);

		stat->produced_size += cpu_ring->produced_size;
		stat->rejected_size += cpu_ring->rejected_size;
		stat->discarded_size += cpu_ring->discarded_size;
		stat->dropped_size += cpu_ring->dropped_size;
		stat->overwritten_size += cpu_ring->overwritten_size;
		stat->consumed_size += cpu_ring->consumed_size;

		stat->max_event_size = max(cpu_ring->max_event_size, stat->max_event_size);
	}
	stat->overwritable = ~~(ring->flags & TB_FL_OVERWRITE);
}

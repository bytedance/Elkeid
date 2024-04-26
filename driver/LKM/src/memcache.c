// SPDX-License-Identifier: GPL-2.0

#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/irqflags.h>
#include <linux/cpumask.h>
#include <linux/log2.h>

#include "../include/memcache.h"

/*
 * memcache: ring-array based lockless MPMC/FIFO queues
 *
 * Copyright: wuqiang.matt@bytedance.com,mhiramat@kernel.org
 */

/* initialize percpu memcache_slot */
static int
memcache_init_percpu_slot(struct memcache_head *pool,
			 struct memcache_slot *slot,
			 int nodes, void *context,
			 memcache_init_obj_cb objinit)
{
	void *obj = (void *)&slot->entries[pool->capacity];
	int i;

	/* initialize elements of percpu memcache_slot */
	slot->mask = pool->capacity - 1;

	for (i = 0; i < nodes; i++) {
		if (objinit) {
			int rc = objinit(obj, context);
			if (rc)
				return rc;
		}
		slot->entries[slot->tail & slot->mask] = obj;
		obj = obj + pool->obj_size;
		slot->tail++;
		slot->last = slot->tail;
		pool->nr_objs++;
	}

	return 0;
}

/* allocate and initialize percpu slots */
static int
memcache_init_percpu_slots(struct memcache_head *pool, int nr_objs,
			  void *context, memcache_init_obj_cb objinit)
{
	int i, cpu_count = 0;

	for (i = 0; i < pool->nr_cpus; i++) {

		struct memcache_slot *slot;
		int nodes, size, rc;

		/* skip the cpu node which could never be present */
		if (!cpu_possible(i))
			continue;

		/* compute how many objects to be allocated with this slot */
		nodes = nr_objs / num_possible_cpus();
		if (cpu_count < (nr_objs % num_possible_cpus()))
			nodes++;
		cpu_count++;

		size = sizeof(struct memcache_slot) + sizeof(void *) * pool->capacity +
			pool->obj_size * nodes;

		/*
		 * here we allocate percpu-slot & objs together in a single
		 * allocation to make it more compact, taking advantage of
		 * warm caches and TLB hits. in default vmalloc is used to
		 * reduce the pressure of kernel slab system. as we know,
		 * mimimal size of vmalloc is one page since vmalloc would
		 * always align the requested size to page size
		 */
		if (pool->gfp & GFP_ATOMIC)
			slot = kmalloc_node(size, pool->gfp, cpu_to_node(i));
		else
			slot = vmalloc_node(size, cpu_to_node(i));
		if (!slot)
			return -ENOMEM;
		memset(slot, 0, size);
		pool->cpu_slots[i] = slot;

		/* initialize the memcache_slot of cpu node i */
		rc = memcache_init_percpu_slot(pool, slot, nodes, context, objinit);
		if (rc)
			return rc;
	}

	return 0;
}

/* cleanup all percpu slots of the object pool */
static void memcache_fini_percpu_slots(struct memcache_head *pool)
{
	int i;

	if (!pool->cpu_slots)
		return;

	if (pool->gfp & GFP_ATOMIC) {
	    for (i = 0; i < pool->nr_cpus; i++)
		kfree(pool->cpu_slots[i]);
        } else {
	    for (i = 0; i < pool->nr_cpus; i++)
		vfree(pool->cpu_slots[i]);
	}
	kfree(pool->cpu_slots);
}

/* initialize object pool and pre-allocate objects */
int
memcache_init(struct memcache_head *pool, int nr_objs, int object_size,
		gfp_t gfp, void *context, memcache_init_obj_cb objinit,
		memcache_fini_cb release)
{
	int rc, capacity, slot_size;

	/* check input parameters */
	if (nr_objs <= 0 || nr_objs > MEMCACHE_NR_OBJS_MAX ||
	    object_size <= 0 || object_size > MEMCACHE_OBJSIZE_MAX)
		return -EINVAL;

	/* align up to unsigned long size */
	object_size = ALIGN(object_size, sizeof(long));

	/* calculate capacity of percpu memcache_slot */
	capacity = roundup_pow_of_two(nr_objs);
	if (!capacity)
		return -EINVAL;

	/* initialize memcache pool */
	memset(pool, 0, sizeof(struct memcache_head));
	pool->nr_cpus = nr_cpu_ids;
	pool->obj_size = object_size;
	pool->capacity = capacity;
	pool->gfp = gfp & ~__GFP_ZERO;
	pool->context = context;
	pool->release = release;
	slot_size = pool->nr_cpus * sizeof(struct memcache_slot);
	pool->cpu_slots = kzalloc(slot_size, pool->gfp);
	if (!pool->cpu_slots)
		return -ENOMEM;

	/* initialize per-cpu slots */
	rc = memcache_init_percpu_slots(pool, nr_objs, context, objinit);
	if (rc)
		memcache_fini_percpu_slots(pool);
	else
		atomic_set(&pool->ref, pool->nr_objs + 1);

	return rc;
}

int memcache_push(void *obj, struct memcache_head *pool)
{
        struct memcache_slot *slot;
        uint32_t tail, last;

        get_cpu();

        slot = pool->cpu_slots[raw_smp_processor_id()];

        do {
		/* loading tail and head as a local snapshot, tail first */
		tail = READ_ONCE(slot->tail);
		smp_rmb();
                last = tail + 1;
        } while (cmpxchg_local(&slot->tail, tail, last) != tail);

        /* now the tail position is reserved for the given obj */
        WRITE_ONCE(slot->entries[tail & slot->mask], obj);

        /* make sure obj is visible before marking it's ready */
        smp_wmb();

        /* update sequence to make this obj available for pop() */
        while (cmpxchg_local(&slot->last, tail, last) == tail) {
                tail = last;
                last = READ_ONCE(slot->tail);
                if (tail == last)
                        break;
        }

        put_cpu();

        return 0;
}

/* try to retrieve object from slot */
static inline void *memcache_try_get_slot(struct memcache_head *pool, int cpu)
{
	struct memcache_slot *slot = pool->cpu_slots[cpu];
	/* load head snapshot, other cpus may change it */
	uint32_t head = READ_ONCE(slot->head);

	while (head != READ_ONCE(slot->last)) {
		void *obj;

		/*
		 * data visibility of 'last' and 'head' could be out of
		 * order since memory updating of 'last' and 'head' are
		 * performed in push() and pop() independently
		 *
		 * before any retrieving attempts, pop() must guarantee
		 * 'last' is behind 'head', that is to say, there must
		 * be available objects in slot, which could be ensured
		 * by condition 'last != head && last - head <= nr_objs'
		 * that is equivalent to 'last - head - 1 < nr_objs' as
		 * 'last' and 'head' are both unsigned int32
		 */
		if (READ_ONCE(slot->last) - head - 1 >= pool->nr_objs) {
			head = READ_ONCE(slot->head);
			continue;
		}

		/* obj must be retrieved before moving forward head */
		obj = READ_ONCE(slot->entries[head & slot->mask]);

		/* move head forward to mark it's consumption */
		if (cmpxchg(&slot->head, head, head + 1) == head)
			return obj;

		/* reload head */
		head = READ_ONCE(slot->head);	
	}

	return NULL;
}

/**
 * Workaround for Linux 2.6.32 CentOS 6.0
 *
 * cpumask_next_wrapped - helper to implement for_each_cpu_wrap
 * @n: the cpu prior to the place to search
 * @mask: the cpumask pointer
 *
 * Return: >= nr_cpu_ids on completion
 *
 * Note: the @wrap argument is required for the start condition when
 * we cannot assume @start is set in @mask.
 */
static int cpumask_next_wrapped(int n, const struct cpumask *mask)
{
	int start = -1, wrap = 1, next;

again:
	next = cpumask_next(n, mask);

	if (wrap && n < start && next >= start) {
		return nr_cpumask_bits;

	} else if (next >= nr_cpumask_bits) {
		wrap = true;
		n = -1;
		goto again;
	}

	return next;
}

/* allocate an object from object pool */
void *memcache_pop(struct memcache_head *pool)
{
	void *obj = NULL;
	unsigned long flags;
	int i, cpu;

	/* disable local irq to avoid preemption & interruption */
	raw_local_irq_save(flags);

	cpu = raw_smp_processor_id();
	for (i = 0; i < num_possible_cpus(); i++) {
		obj = memcache_try_get_slot(pool, cpu);
		if (obj)
			break;
		cpu = cpumask_next_wrapped(cpu, cpu_possible_mask);
	}
	raw_local_irq_restore(flags);

	return obj;
}

/* release whole memcache forcely */
void memcache_free(struct memcache_head *pool)
{
	if (!pool->cpu_slots)
		return;

	/* release percpu slots */
	memcache_fini_percpu_slots(pool);

	/* call user's cleanup callback if provided */
	if (pool->release)
		pool->release(pool, pool->context);
}

/* drop the allocated object, rather reclaim it to memcache */
int memcache_drop(void *obj, struct memcache_head *pool)
{
	if (!obj || !pool)
		return -EINVAL;

	if (atomic_dec_and_test(&pool->ref)) {
		memcache_free(pool);
		return 0;
	}

	return -EAGAIN;
}

/* drop unused objects and defref memcache for releasing */
void memcache_fini(struct memcache_head *pool)
{
	int count = 1; /* extra ref for memcache itself */

	/* drop all remained objects from memcache */
	while (memcache_pop(pool))
		count++;

	if (atomic_sub_and_test(count, &pool->ref))
		memcache_free(pool);
}

int memcache_nobjs(struct memcache_head *pool)
{
    return pool->nr_objs;
}

void *memcache_user(struct memcache_head *pool)
{
    return pool->context;
}

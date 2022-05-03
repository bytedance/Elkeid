/* SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause */
#ifndef _MEMCACHE_H_
#define _MEMCACHE_H_

#include <linux/slab.h>
#include <linux/vmalloc.h>

/*
 * memcache: a lock-less version of object pool implementation
 *
 * Copyright:
 * cameron@moodycamel.com, mhiramat@kernel.org, wuqiang.matt@bytedance.com
 *
 * The object pool is a scalable implementaion of high performance queue
 * for objects allocation and reclamation, such as kretprobe instances.
 *
 * It's based on cameron's CAS-based lock-free freelist:
 * https://moodycamel.com/blog/2014/solving-the-aba-problem-for-lock-free-free-lists
 *
 * With leveraging per-cpu lockless queue to mitigate hot spots of memory
 * contention, it could deliver near-linear scalability for high parallel
 * loads. The object pool are best suited for the following cases:
 * 1) memory allocation or reclamation is prohibited or too expensive
 * 2) objects are allocated and reclaimed very frequently
 *
 * Limitations:
 * 1) Memory of objects won't be freed until the pool is deallocated
 * 2) Order and fairness are not guaranteed: some threads might stay
 *    hungry much longer than other competitors
 *
 * Objects could be pre-allocated during initialization or filled later
 * with user's buffer or private allocations. Mixing different objects
 * of self-managed/batched/manually-added is NOT recommended, though
 * it's supported. For mixed case, the caller should take care of the
 * releasing of objects or user pool.
 *
 * Typical use cases:
 *
 * 1) self-managed objects
 *
 * obj_init(): do initial settings of each object, only called once
 *    static int obj_init(void *context, struct memcache_node *obj)
 *    {
 *		struct my_node *node;
 *		node = container_of(obj, struct my_node, obj);
 * 		do_init_node(context, node);
 * 		return 0;
 *    }
 *
 * main():
 *    memcache_init(&fh, num_possible_cpus() * 4, 16, GFP_KERNEL, context, obj_init);
 *    <object pool initialized>
 *
 *    obj = memcache_pop(&fh);
 *    do_something_with(obj);
 *    memcache_push(obj, &fh);
 *
 *    <object pool to be destroyed>
 *    memcache_fini(&fh, NULL, NULL);
 *
 * 2) batced with user's buffer
 *
 * obj_init():
 *    static int obj_init(void *context, struct memcache_node *obj)
 *    {
 *		struct my_node *node;
 *		node = container_of(obj, struct my_node, obj);
 * 		do_init_node(context, node);
 * 		return 0;
 *    }
 *
 * free_buf():
 *    static int free_buf(void *context, void *obj, int user, int element)
 *    {
 * 		if (obj && user && !element)
 * 			kfree(obj);
 *    }
 *
 * main():
 *    memcache_init(&fh, num_possible_cpus() * 4, 0, GFP_KERNEL, 0, 0);
 *    buffer = kmalloc(size, ...);
 *    memcache_populate(&fh, buffer, size, 16, context, obj_init);
 *    <object pool initialized>
 *
 *    obj = memcache_pop(&fh);
 *    do_something_with(obj);
 *    memcache_push(obj, &fh);
 *
 *    <object pool to be destroyed>
 *    memcache_fini(&fh, context, free_buf);
 *
 * 3) manually added with user objects
 *
 *  free_obj():
 *    static int free_obj(void *context, void *obj, int user, int element)
 *    {
 *		struct my_node *node;
 *              node = container_of(obj, struct my_node, obj);
 * 		if (obj && user && element)
 * 			kfree(node);
 *    }
 *
 * main():
 *    memcache_init(&fh, num_possible_cpus() * 4, 0, 0, GFP_KERNEL, 0, 0);
 *
 *    for () {
 *      node = kmalloc(objsz, ...);
 *      do_init_node(node);
 *      memcache_add_scattered(&node.obj, oh);
 *    }
 *    <object pool initialized>
 *
 *    obj = memcache_pop(&fh);
 *    do_something_with(obj);
 *    memcache_push(obj, &fh);
 *
 *    <object pool to be destroyed>
 *    memcache_fini(&fh, context, free_obj);
 */

#define memcache_try_add memcache_add_scattered
#define memcache_add memcache_push
#define memcache_try_get memcache_pop
#define memcache_destroy memcache_fini
#define memcache_init(head, max) memcache_init_pool(head, max, 0, GFP_KERNEL, 0, 0)

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
 * common componment of every node
 */
struct memcache_node {
	struct memcache_node   *next;
	atomic_t                refs;
	uint32_t                id;
};

#define REFS_IN_MEMCACHE 0x80000000
#define MASK_FL_MEMCACHE 0x7FFFFFFF

/*
 * memcache_slot: per-cpu singly linked list
 *
 * All pre-allocated objects are next to memcache_slot. Objects and
 * memcache_slot are to be allocated from local node's memory pool.
 */
struct memcache_slot {
	struct memcache_node   *fs_head;	/* head of percpu list */
};
#define MEMCACHE_SLOT_OBJS(s) ((void *)(s) + sizeof(struct memcache_slot))

/*
 * memcache_head: object pooling metadata
 */
struct memcache_head {
	uint32_t                fh_objsz;	/* object & element size */
	uint32_t                fh_nobjs;	/* total objs in memcache */
	uint32_t                fh_ncpus;	/* num of possible cpus */
	uint32_t                fh_in_slot:1;	/* objs alloced with slots */
	uint32_t                fh_vmalloc:1;	/* alloc from vmalloc zone */
	gfp_t                   fh_gfp;		/* k/vmalloc gfp flags */
	uint32_t                fh_sz_pool;	/* user pool size in bytes */
	void                   *fh_pool;	/* user managed memory pool */
	struct memcache_slot  **fh_slots;	/* array of percpu slots */
	uint32_t               *fh_sz_slots;	/* size in bytes of slots */
};

typedef int (*memcache_init_node_cb)(void *context, struct memcache_node *);

 #define memcache_cmpxchg(p, o, n) 						\
	(void *)atomic_long_cmpxchg((atomic_long_t *)(p), (long)(o), (long)(n))

/* attach object to percpu slot */
static inline void
__memcache_insert_slot(struct memcache_node *node, struct memcache_slot *slot)
{
	atomic_set(&node->refs, 1);
	node->next = slot->fs_head;
	slot->fs_head = node;
}
static inline void
__memcache_insert_node(struct memcache_node *node, struct memcache_head *head)
{
	__memcache_insert_slot(node, head->fh_slots[node->id % head->fh_ncpus]);
}

/* allocate and initialize percpu slots */
static inline int
__memcache_init_slots(struct memcache_head *head, uint32_t nobjs,
                      void *context, memcache_init_node_cb objinit)
{
	uint32_t i, objsz, cpus = head->fh_ncpus;
	gfp_t gfp = head->fh_gfp;

	/* allocate array for percpu slots */
	head->fh_slots = kzalloc(cpus * sizeof(uint32_t) +
	                         cpus * sizeof(void *), gfp);
	if (!head->fh_slots)
		return -ENOMEM;
	head->fh_sz_slots = (uint32_t *)&head->fh_slots[cpus];

	/* align object size by sizeof(void *) */
	objsz = ALIGN(head->fh_objsz, sizeof(void *));

	/* shall we allocate objects along with memcache_slot */
	if (objsz)
		head->fh_in_slot = 1;

	/* intialize per-cpu slots */
	for (i = 0; i < cpus; i++) {
		struct memcache_slot *slot;
		uint32_t j, n, s;

		/* compute how many objects to be managed by this slot */
		n = nobjs / cpus;
		if (i < (nobjs % cpus))
			n++;
		s = sizeof(struct memcache_slot) + objsz * n;

		/* decide which zone shall the slot be allocated from */
		if (0 == i) {
			if ((gfp & GFP_ATOMIC) || s < (PAGE_SIZE / 2))
				head->fh_vmalloc = 0;
			else
				head->fh_vmalloc = 1;
		}

		/* allocate percpu slot & objects from local memory */
		if (head->fh_vmalloc)
			slot = vmalloc_node(s, cpu_to_node(i));
		else
			slot = kmalloc_node(s, head->fh_gfp, cpu_to_node(i));
		if (!slot)
			return -ENOMEM;

		/* initialize percpu slot for current cpu */
		memset(slot, 0, s);
		head->fh_slots[i] = slot;
		head->fh_sz_slots[i] = s;

		if (!head->fh_in_slot)
			continue;

		/* initialize pre-allocated record entries */
		for (j = 0; j < n; j++) {
			struct memcache_node *node;
			node = MEMCACHE_SLOT_OBJS(slot) + j * objsz;
			node->id = i;
			if (objinit) {
				int rc = objinit(context, node);
				if (rc)
					return rc;
			}
		}
	}

	if (!head->fh_in_slot)
		return 0;

	for (i = 0; i < cpus; i++) {
		struct memcache_slot *slot = head->fh_slots[i];
		uint32_t j, n;

		/* compute objects to be managed by this slot */
		n = nobjs / cpus;
		if (i < (nobjs % cpus))
			n++;

		/* insert node to percpu slot */
		for (j = 0; j < n; j++) {
			struct memcache_node *node;
			node = MEMCACHE_SLOT_OBJS(slot) + j * objsz;
			__memcache_insert_slot(node, slot);
			head->fh_nobjs++;
		}
	}

	return 0;
}

/* cleanup all percpu slots of the object pool */
static inline void __memcache_fini_slots(struct memcache_head *head)
{
	uint32_t i;

	if (!head->fh_slots)
		return;

	for (i = 0; i < head->fh_ncpus; i++) {
		if (!head->fh_slots[i])
			continue;
		if (head->fh_vmalloc)
			vfree(head->fh_slots[i]);
		else
			kfree(head->fh_slots[i]);
	}
	kfree(head->fh_slots);
	head->fh_slots = NULL;
	head->fh_sz_slots = NULL;
}

/**
 * memcache_init: initialize object pool and pre-allocate objects
 *
 * args:
 * @fh:    the object pool to be initialized, declared by the caller
 * @nojbs: total objects to be managed by this object pool
 * @ojbsz: size of an object, to be pre-allocated if objsz is not 0
 * @gfp:   gfp flags of caller's context for memory allocation
 * @context: user context for object initialization callback
 * @objinit: object initialization callback for extra setting-up
 *
 * return:
 *         0 for success, otherwise error code
 *
 * All pre-allocated objects are to be zeroed. Caller could do extra
 * initialization in objinit callback. The objinit callback will be
 * called once and only once after the slot allocation
 */
static inline int
memcache_init_pool(struct memcache_head *head, int nobjs, int objsz, gfp_t gfp,
                   void *context, memcache_init_node_cb objinit)
{
	memset(head, 0, sizeof(struct memcache_head));
	head->fh_ncpus = num_possible_cpus();
	head->fh_objsz = objsz;
	head->fh_gfp = gfp & ~__GFP_ZERO;

	if (__memcache_init_slots(head, nobjs, context, objinit)) {
		__memcache_fini_slots(head);
		return -ENOMEM;
	}

	return 0;
}

/**
 * memcache_populate: add objects from user provided pool in batch
 *  *
 * args:
 * @oh:  object pool
 * @buf: user buffer for pre-allocated objects
 * @size: size of user buffer
 * @objsz: size of object & element
 * @context: user context for objinit callback
 * @objinit: object initialization callback
 *
 * return:
 *     0 or error code
 */
static inline int
memcache_populate(struct memcache_head *head, void *buf, int size, int objsz,
                  void *context, memcache_init_node_cb objinit)
{
	int nobjs, szobj, i;

	if (head->fh_pool || !buf || !objsz || size < objsz)
		return -EINVAL;
	if (head->fh_objsz && head->fh_objsz != objsz)
		return -EINVAL;

	WARN_ON_ONCE(((unsigned long)buf) & (sizeof(void *) - 1));
	WARN_ON_ONCE(((uint32_t)objsz) & (sizeof(void *) - 1));

	/* align object size by sizeof(void *) */
	szobj = ALIGN(objsz, sizeof(void *));

	/* calculate total number of objects stored in buf */
	nobjs = size / szobj;

	/* initialize pre-allocated memcache nodes */
	for (i = 0; i < nobjs; i++) {
		struct memcache_node *node = buf + i * szobj;
		node->id = i * head->fh_ncpus / nobjs;
		if (objinit) {
			int rc = objinit(context, node);
			if (rc)
				return rc;
		}
	}

	/* insert nodes into memcache */
	for (i = 0; i < nobjs; i++) {
		struct memcache_node *node = buf + i * szobj;
		__memcache_insert_node(node, head);
		head->fh_nobjs++;
	}

	head->fh_pool = buf;
	head->fh_sz_pool = size;
	head->fh_objsz = objsz;

	return 0;
}

static inline void __memcache_cas_add(struct memcache_node *node, struct memcache_slot *slot)
{
	/*
	 * Since the refcount is zero, and nobody can increase it until it's
	 * zero (except us, and we run only one copy of this method per node at
	 * a time, i.e. the single thread case), then we know we can safely
	 * change the next pointer of the node; however, once the refcount is
	 * back above zero, then other threads could increase it (happens under
	 * heavy contention, when the refcount goes to zero in between a load
	 * and a refcount increment of a node in try_get, then back up to
	 * something non-zero, then the refcount increment is done by the other
	 * thread) -- so if the CAS to add the node to the actual list fails,
	 * decrese the refcount and leave the add operation to the next thread
	 * who puts the refcount back to zero (which could be us, hence the
	 * loop).
	 */
	struct memcache_node *head;

	for (;;) {
		head = READ_ONCE(slot->fs_head);
		smp_rmb();
		WRITE_ONCE(node->next, head);
		atomic_set(&node->refs, 1);
		smp_wmb();

		if (head == memcache_cmpxchg(&slot->fs_head, head, node))
			break;

		/*
		 * Hmm, the add failed, but we can only try again when refcount
		 * goes back to zero (with REFS_IN_MEMCACHE set).
		 */
		if (atomic_add_return(REFS_IN_MEMCACHE - 1, &node->refs) != REFS_IN_MEMCACHE)
			break;
	}
}

/* adding object to slot */
static inline int __memcache_add_slot(struct memcache_node *node, struct memcache_slot *slot)
{
	/*
	 * We know that the should-be-on-memcache bit is 0 at this point, so
	 * it's safe to set it using a fetch_add.
	 */
	if (atomic_add_return(REFS_IN_MEMCACHE, &node->refs) == REFS_IN_MEMCACHE) {
		/*
		 * Oh look! We were the last one referencing this node, and we
		 * know we want to add it to the free list, so let's do it!
		 */
		__memcache_cas_add(node, slot);
	}

	return 0;
}

/**
 * memcache_push: reclaim the object and return back to objects pool
 *
 * args:
 * @node: object pointer to be pushed to object pool
 * @head: object pool
 *
 * return:
 *     0 (memcache_push never fail)
 *
 * memcache_push() can be nested (irp/softirq/preemption)
 */
static inline int memcache_push(struct memcache_node *node, struct memcache_head *head)
{
	int cpu = raw_smp_processor_id() % head->fh_ncpus;
	return __memcache_add_slot(node, head->fh_slots[cpu]);
}

/* try to retrieve object from slot */
static inline struct memcache_node *__memcache_pop_slot(struct memcache_slot *slot)
{
	struct memcache_node *next, *head;
	unsigned int refs;

	for (;;) {

		head = READ_ONCE(slot->fs_head);
		smp_rmb();
		if (!head)
			break;
		refs = atomic_read(&head->refs);
		smp_rmb();
		if ((refs & MASK_FL_MEMCACHE) == 0 ||
		    refs != atomic_cmpxchg(&head->refs, refs, refs+1)) {
			continue;
		}

		/*
		 * Good, reference count has been incremented (it wasn't at
		 * zero), which means we can read the next and not worry about
		 * it changing between now and the time we do the CAS.
		 */
		next = READ_ONCE(head->next);
		if (head == memcache_cmpxchg(&slot->fs_head, head, next)) {
			/*
			 * Yay, got the node. This means it was on the list,
			 * which means should-be-on-memcache must be false no
			 * matter the refcount (because nobody else knows it's
			 * been taken off yet, it can't have been put back on).
			 */
			WARN_ON_ONCE(atomic_read(&head->refs) & REFS_IN_MEMCACHE);

			/*
			 * Decrease refcount twice, once for our ref, and once
			 * for the list's ref.
			 */
			atomic_add(-2, &head->refs);

			return head;
		}

		/*
		 * OK, the head must have changed on us, but we still need to decrement
		 * the refcount we increased.
		 */
		refs = atomic_add_return(-1, &head->refs);
		if (refs == REFS_IN_MEMCACHE)
			__memcache_cas_add(head, slot);
	}

	return NULL;
}

/**
 * memcache_pop: allocate an object from objects pool
 *
 * args:
 * @head: object pool
 *
 * return:
 *   node: NULL if failed (object pool is empty)
 *
 * memcache_pop can be nesed, and guaranteed to be deadlock-free.
 * So it can be called in any context, like irq/softirq/nmi.
 */
static inline struct memcache_node *memcache_pop(struct memcache_head *head)
{
	struct memcache_node *node;
	int i, cpu;

	if (!head->fh_slots)
		return NULL;

	cpu = raw_smp_processor_id() % head->fh_ncpus;
	for (i = 0; i < head->fh_ncpus; i++) {
		struct memcache_slot *slot;
		slot = head->fh_slots[cpu];
		node = __memcache_pop_slot(slot);
		if (node)
			return node;
		if (++cpu >= head->fh_ncpus)
			cpu = 0;
	}

	return NULL;
}

/* whether this object is from user buffer (batched adding) */
static inline int memcache_is_inpool(void *obj, struct memcache_head *fh)
{
	return (obj && fh->fh_pool && obj >= fh->fh_pool &&
		obj < fh->fh_pool + fh->fh_sz_pool);
}

/* whether this object is pre-allocated with percpu slots */
static inline int memcache_is_inslot(void *obj, struct memcache_head *fh)
{
	uint32_t i;

	if (!obj)
		return 0;

	for (i = 0; i < fh->fh_ncpus; i++) {
		void *ptr = fh->fh_slots[i];
		if (obj >= ptr && obj < ptr + fh->fh_sz_slots[i])
		    return 1;
	}

	return 0;
}

/**
 * memcache_fini: cleanup the whole object pool (releasing all objects)
 *
 * args:
 * @head: object pool
 * @context: user provided value for the callback of release() funciton
 * @release: user provided callback for resource cleanup or statistics
 *
 * the protocol of release callback:
 * static int release(void *context, void *obj, int user, int element);
 * args:
 *  context: user provided value
 *  obj: the object (element or buffer) to be cleaned up
 *  user: the object is manually provided by user
 *  element: obj is an object or user-provided buffer
 */
static inline void memcache_fini(struct memcache_head *head, void *context,
                                 int (*release)(void *, void *, int, int))
{
	uint32_t i;

	if (!head->fh_slots)
		return;

	for (i = 0; release && i < head->fh_ncpus; i++) {
		void *obj;
		if (!head->fh_slots[i])
			continue;
		do {
			obj = __memcache_pop_slot(head->fh_slots[i]);
			if (obj) {
				int user = !memcache_is_inpool(obj, head) &&
				           !memcache_is_inslot(obj, head);
				release(context, obj, user, 1);
			}
		} while (obj);
	}

	if (head->fh_pool && release) {
		release(context, head->fh_pool, 1, 0);
		head->fh_pool = NULL;
		head->fh_sz_pool = 0;
	}

	__memcache_fini_slots(head);
}

#endif /* _MEMCACHE_H_ */

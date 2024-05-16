/* SPDX-License-Identifier: GPL-2.0 */

#ifndef _LINUX_MEMCACHE_H
#define _LINUX_MEMCACHE_H

#include <linux/types.h>

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
 * objpool: ring-array based lockless MPMC queue
 *
 * Copyright: wuqiang.matt@bytedance.com,mhiramat@kernel.org
 *
 * objpool is a scalable implementation of high performance queue for
 * object allocation and reclamation, such as kretprobe instances.
 *
 * With leveraging percpu ring-array to mitigate hot spots of memory
 * contention, it delivers near-linear scalability for high parallel
 * scenarios. The objpool is best suited for the following cases:
 * 1) Memory allocation or reclamation are prohibited or too expensive
 * 2) Consumers are of different priorities, such as irqs and threads
 *
 * Limitations:
 * 1) Maximum objects (capacity) is fixed after objpool creation
 * 2) All pre-allocated objects are managed in percpu ring array,
 *    which consumes more memory than linked lists
 */

/**
 * struct memcache_slot - percpu ring array of objpool
 * @head: head sequence of the local ring array (to retrieve at)
 * @tail: tail sequence of the local ring array (to append at)
 * @last: the last sequence number marked as ready for retrieve
 * @mask: bits mask for modulo capacity to compute array indexes
 * @entries: object entries on this slot
 *
 * Represents a cpu-local array-based ring buffer, its size is specialized
 * during initialization of object pool. The percpu objpool node is to be
 * allocated from local memory for NUMA system, and to be kept compact in
 * continuous memory: CPU assigned number of objects are stored just after
 * the body of memcache_node.
 *
 * Real size of the ring array is far too smaller than the value range of
 * head and tail, typed as uint32_t: [0, 2^32), so only lower bits (mask)
 * of head and tail are used as the actual position in the ring array. In
 * general the ring array is acting like a small sliding window, which is
 * always moving forward in the loop of [0, 2^32).
 */
struct memcache_slot {
	uint32_t            head;
	uint32_t            tail;
	uint32_t            last;
	uint32_t            mask;
	void               *entries[];
} __packed;

struct memcache_head;

/*
 * caller-specified callback for object initial setup, it's only called
 * once for each object (just after the memory allocation of the object)
 */
typedef int (*memcache_init_obj_cb)(void *obj, void *context);

/* caller-specified cleanup callback for objpool destruction */
typedef int (*memcache_fini_cb)(struct memcache_head *head, void *context);

/**
 * struct memcache_head - object pooling metadata
 * @obj_size:   object size, aligned to sizeof(void *)
 * @nr_objs:    total objs (to be pre-allocated with objpool)
 * @nr_cpus:    local copy of nr_cpu_ids
 * @capacity:   max objs can be managed by one memcache_slot
 * @gfp:        gfp flags for kmalloc & vmalloc
 * @ref:        refcount of objpool
 * @flags:      flags for objpool management
 * @cpu_slots:  pointer to the array of memcache_slot
 * @release:    resource cleanup callback
 * @context:    caller-provided context
 */
struct memcache_head {
	int                     obj_size;
	int                     nr_objs;
	int                     nr_cpus;
	int                     capacity;
	gfp_t                   gfp;
	atomic_t                ref;
	unsigned long           flags;
	struct memcache_slot  **cpu_slots;
	memcache_fini_cb        release;
	void                   *context;
};

#define MEMCACHE_NR_OBJS_MAX	(1UL << 24) /* maximum numbers of total objects */
#define MEMCACHE_OBJSIZE_MAX	(1UL << 16) /* maximum size of an object */

/**
 * memcache_init() - initialize objpool and pre-allocated objects
 * @pool:    the object pool to be initialized, declared by caller
 * @nr_objs: total objects to be pre-allocated by this object pool
 * @object_size: size of an object (should be > 0)
 * @gfp:     flags for memory allocation (via kmalloc or vmalloc)
 * @context: user context for object initialization callback
 * @objinit: object initialization callback for extra setup
 * @release: cleanup callback for extra cleanup task
 *
 * return value: 0 for success, otherwise error code
 *
 * All pre-allocated objects are to be zeroed after memory allocation.
 * Caller could do extra initialization in objinit callback. objinit()
 * will be called just after slot allocation and called only once for
 * each object. After that the objpool won't touch any content of the
 * objects. It's caller's duty to perform reinitialization after each
 * pop (object allocation) or do clearance before each push (object
 * reclamation).
 */
int memcache_init(struct memcache_head *pool, int nr_objs, int object_size,
		 gfp_t gfp, void *context, memcache_init_obj_cb objinit,
		 memcache_fini_cb release);

/**
 * memcache_pop() - allocate an object from objpool
 * @pool: object pool
 *
 * return value: object ptr or NULL if failed
 */
void *memcache_pop(struct memcache_head *pool);

/**
 * memcache_push() - reclaim the object and return back to objpool
 * @obj:  object ptr to be pushed to objpool
 * @pool: object pool
 *
 * return: 0 or error code (it fails only when user tries to push
 * the same object multiple times or wrong "objects" into objpool)
 */
int memcache_push(void *obj, struct memcache_head *pool);

/**
 * memcache_drop() - discard the object and deref objpool
 * @obj:  object ptr to be discarded
 * @pool: object pool
 *
 * return: 0 if objpool was released; -EAGAIN if there are still
 *         outstanding objects
 *
 * memcache_drop is normally for the release of outstanding objects
 * after objpool cleanup (memcache_fini). Thinking of this example:
 * kretprobe is unregistered and memcache_fini() is called to release
 * all remained objects, but there are still objects being used by
 * unfinished kretprobes (like blockable function: sys_accept). So
 * only when the last outstanding object is dropped could the whole
 * objpool be released along with the call of memcache_drop()
 */
int memcache_drop(void *obj, struct memcache_head *pool);

/**
 * memcache_free() - release objpool forcely (all objects to be freed)
 * @pool: object pool to be released
 */
void memcache_free(struct memcache_head *pool);

/**
 * memcache_fini() - deref object pool (also releasing unused objects)
 * @pool: object pool to be dereferenced
 *
 * memcache_fini() will try to release all remained free objects and
 * then drop an extra reference of the objpool. If all objects are
 * already returned to objpool (so called synchronous use cases),
 * the objpool itself will be freed together. But if there are still
 * outstanding objects (so called asynchronous use cases, such like
 * blockable kretprobe), the objpool won't be released until all
 * the outstanding objects are dropped, but the caller must assure
 * there are no concurrent memcache_push() on the fly. Normally RCU
 * is being required to make sure all ongoing memcache_push() must
 * be finished before calling memcache_fini(), so does test_objpool,
 * kretprobe or rethook
 */
void memcache_fini(struct memcache_head *pool);

int memcache_nobjs(struct memcache_head *pool);

void *memcache_user(struct memcache_head *pool);

#endif /* _LINUX_MEMCACHE_H */
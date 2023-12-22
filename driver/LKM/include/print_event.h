/* SPDX-License-Identifier: GPL-2.0 */

#ifndef _PRINT_EVENT_H
#define _PRINT_EVENT_H

/* Stage 1 */
#undef PE_PROTO
#undef PE_ARGS
#undef PE_STRUCT__entry
#undef PE_fast_assign
#undef PE_printk

#undef __field
#undef __array
#undef __field_struct
#undef __string
#undef __get_str
#undef __get_stl
#undef __get_ent
#undef __assign_str

#define PE_PROTO(args...)			args
#define PE_ARGS(args...)			args
#define PE_STRUCT__entry(args...)		args
#define PE_fast_assign(args...)
#define PE_printk(fmt, args...)

#define __field(type, item)
#define __array(type, item, len)
#define __field_struct(type, item)
#define __string(item, src)			u32	item;

#undef PRINT_EVENT_DEFINE
#define PRINT_EVENT_DEFINE(name, proto, args, tstruct, assign, print)	\
	struct print_event_data_offsets_##name {			\
		tstruct;						\
	};

#include TRACE_INCLUDE(TRACE_INCLUDE_FILE)

/* Stage 2 */
#undef PE_PROTO
#undef PE_ARGS
#undef PE_STRUCT__entry
#undef PE_fast_assign
#undef PE_printk

#undef __field
#undef __array
#undef __field_struct
#undef __string
#undef __get_str
#undef __get_stl
#undef __get_ent
#undef __assign_str

#define PE_PROTO(args...)			args
#define PE_ARGS(args...)			args
#define PE_STRUCT__entry(args...)		args
#define PE_fast_assign(args...)
#define PE_printk(fmt, args...)

#define __field(type, item)
#define __array(type, item, len)
#define __field_struct(type, item)
#define __string(item, src) do {					\
		int len = (src) ? strlen(src) + 1 : sizeof("(null)");	\
									\
		__data_offsets->item = __data_size;			\
		__data_size += len;					\
	} while (0);

#define __get_str(x, y)
#define __get_stl(x, y, len)
#define __get_ent(x, y)
#define __assign_str(item, src)

#undef PRINT_EVENT_DEFINE
#define PRINT_EVENT_DEFINE(name, proto, args, tstruct, assign, print)	\
	static inline notrace						\
	int print_event_get_offsets_##name(				\
		struct print_event_data_offsets_##name *__data_offsets,	\
		proto)							\
	{								\
		int __data_size = 0;					\
									\
		tstruct;						\
									\
		return __data_size;					\
	}

#include TRACE_INCLUDE(TRACE_INCLUDE_FILE)

/* Stage 3 */
#undef PE_PROTO
#undef PE_ARGS
#undef PE_STRUCT__entry
#undef PE_fast_assign
#undef PE_printk

#undef __field
#undef __array
#undef __field_struct
#undef __string
#undef __get_str
#undef __get_stl
#undef __get_ent
#undef __assign_str

#define PE_PROTO(args...)			args
#define PE_ARGS(args...)			args
#define PE_STRUCT__entry(args...)		args
#define PE_fast_assign(args...)			args
#define PE_printk(fmt, args...)			fmt "\x17", args

#define __field(type, item)			type	item;
#define __array(type, item, len)		type	item[len];
#define __field_struct(type, item)		type	item;
#define __string(item, src)			u32	__data_loc_##item;

#define __get_str(item, y)						\
	(__entry->__data + __entry->__data_loc_##item)
#define __get_stl(x, y, len)	__entry->x
#define __get_ent(x, y)			__entry->x


#define __assign_str(item, src)	do {					\
		__entry->__data_loc_##item = __data_offsets.item;	\
		strcpy(__get_str(item, item),					\
		       (src) ? (const char *)(src) : "(null)");		\
	} while (0)

#undef PRINT_EVENT_DEFINE
#define PRINT_EVENT_DEFINE(name, proto, args, tstruct, assign, print)	\
	struct print_event_entry_##name {				\
		struct print_event_entry	head;			\
		tstruct							\
		char				__data[0];		\
	};								\
									\
	static struct print_event_class * const				\
		__print_event_class_##name;				\
	static notrace							\
	enum print_line_t name##_format_event(struct trace_seq *seq,	\
			struct print_event_entry *entry)		\
	{								\
		struct print_event_entry_##name *__entry;		\
									\
		__entry = (typeof(__entry))entry;			\
		if (WARN_ON_ONCE(__print_event_class_##name->id !=	\
				 __entry->head.id))			\
			return TRACE_TYPE_UNHANDLED;			\
									\
		trace_seq_printf(seq, print);				\
									\
		return __trace_handle_return(seq);			\
	}								\
	static struct print_event_class print_event_class_##name = {	\
		.format	= name##_format_event,				\
	};								\
	static struct print_event_class * const				\
		__print_event_class_##name __used =			\
		&print_event_class_##name;				\
									\
	static inline notrace						\
	void __do_##name##_print(struct print_event_class *__class,	\
				 proto)					\
	{								\
		int __data_size;					\
		struct print_event_entry_##name *__entry;		\
		struct tb_event *event;			\
		struct print_event_data_offsets_##name __data_offsets;	\
									\
		__data_size = print_event_get_offsets_##name(&__data_offsets,\
							     args);	\
		event = tb_lock_reserve(__class->trace,	\
				sizeof(*__entry) + __data_size);	\
		if (!event)						\
			return;						\
									\
		__entry = tb_event_data(event);		\
		__entry->head.id = __class->id;				\
		{ assign; }						\
		tb_unlock_commit(__class->trace);	\
	}								\
									\
	static notrace void name##_print(proto)				\
	{								\
		__do_##name##_print(__print_event_class_##name,		\
				    args);				\
	}

#include TRACE_INCLUDE(TRACE_INCLUDE_FILE)

/* Stage 4 */
#undef PE_PROTO
#undef PE_ARGS
#undef PE_STRUCT__entry
#undef PE_fast_assign
#undef PE_printk

#define PE_PROTO(args...)
#define PE_ARGS(args...)
#define PE_STRUCT__entry(args...)
#define PE_fast_assign(args...)
#define PE_printk(fmt, args...)

#undef PRINT_EVENT_DEFINE
#define PRINT_EVENT_DEFINE(name, proto, args, tstruct, assign, print) \
		&print_event_class_##name,

#if defined(_KPROBE_PRINT_H)
static struct print_event_class *kprobe_print_event_class[] = {
#include TRACE_INCLUDE(TRACE_INCLUDE_FILE)
};
int smith_query_kprobe_events(void)
{
	return ARRAY_SIZE(kprobe_print_event_class);
}
struct print_event_class *smith_query_kprobe_event_class(int id)
{
	if (id < 0 || id >= ARRAY_SIZE(kprobe_print_event_class))
		return NULL;
	return kprobe_print_event_class[id];
}
#elif defined(_ANTI_ROOTKIT_PRINT_H)
static struct print_event_class *anti_rootkit_print_event_class[] = {
#include TRACE_INCLUDE(TRACE_INCLUDE_FILE)
};
int smith_query_anti_rootkit_events(void)
{
	return ARRAY_SIZE(anti_rootkit_print_event_class);
}
struct print_event_class *smith_query_anti_rootkit_event_class(int id)
{
	if (id < 0 || id >= ARRAY_SIZE(anti_rootkit_print_event_class))
		return NULL;
	return anti_rootkit_print_event_class[id];
}
#else
#error "only kprobe and antiroot are supported."
#endif

#endif

/* SPDX-License-Identifier: GPL-3.0 */

#ifndef _PRINT_EVENT_H
#define _PRINT_EVENT_H
#include "trace.h"

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
#define __get_str(item)
#define __assign_str(item, src)

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

#define __get_str(item)
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

#define __get_str(item)							\
	(__entry->__data + __entry->__data_loc_##item)

#define __assign_str(item, src)	do {					\
		__entry->__data_loc_##item = __data_offsets.item;	\
		strcpy(__get_str(item),					\
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
		__print_event_class_##name __used			\
		__attribute__((section(".__print_event_class"))) =	\
		&print_event_class_##name;				\
									\
	static inline notrace						\
	void __do_##name##_print(struct print_event_class *__class,	\
				 proto)					\
	{								\
		int __data_size;					\
		struct print_event_entry_##name *__entry;		\
		struct ring_buffer_event *event;			\
		struct print_event_data_offsets_##name __data_offsets;	\
									\
		__data_size = print_event_get_offsets_##name(&__data_offsets,\
							     args);	\
		event = ring_buffer_lock_reserve(__class->buffer,	\
				sizeof(*__entry) + __data_size);	\
		if (!event)						\
			return;						\
									\
		__entry = ring_buffer_event_data(event);		\
		__entry->head.id = __class->id;				\
		{ assign; }						\
		ring_buffer_unlock_commit(__class->buffer, event);	\
	}								\
									\
	static notrace void name##_print(proto)				\
	{								\
		__do_##name##_print(__print_event_class_##name,		\
				    args);				\
	}

#include TRACE_INCLUDE(TRACE_INCLUDE_FILE)

#endif

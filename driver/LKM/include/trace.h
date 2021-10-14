/* SPDX-License-Identifier: GPL-2.0 */

#ifndef _TRACE_EVENT_H
#define _TRACE_EVENT_H
#include "ring.h"

#define PE_PROTO(args...)				args
#define PE_ARGS(args...)
#define PE_STRUCT__entry(args...)
#define PE_fast_assign(args...)
#define __get_str(s1, s2)				s2
#define __get_ent(n1, n2)				n2
#define __get_stl(n1, v, l)				v
#define PE_printk(fmt, args...)			fmt, args

#undef PRINT_EVENT_DEFINE
#define PRINT_EVENT_DEFINE(name, proto, args, print)						\
																			\
	static notrace void name##_print(proto)									\
	{																		\
		rs_vsprint_ring(print);  											\
	}

#endif /* _TRACE_EVENT_H */

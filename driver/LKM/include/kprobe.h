// SPDX-License-Identifier: GPL-3.0
/*
 * kprobe.h
 *
 * Here's a sample kernel module showing the use of return probes.
 */
#ifndef __KPROBE_TEMPLATE_H
#define __KPROBE_TEMPLATE_H

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/tracepoint.h>
#include <asm/irq_regs.h>

#define __KPROBE_MAP0(m, ...)
#define __KPROBE_MAP1(m, t, a, ...) m(t, a)
#define __KPROBE_MAP2(m, t, a, ...) m(t, a), __KPROBE_MAP1(m, __VA_ARGS__)
#define __KPROBE_MAP3(m, t, a, ...) m(t, a), __KPROBE_MAP2(m, __VA_ARGS__)
#define __KPROBE_MAP4(m, t, a, ...) m(t, a), __KPROBE_MAP3(m, __VA_ARGS__)
#define __KPROBE_MAP5(m, t, a, ...) m(t, a), __KPROBE_MAP4(m, __VA_ARGS__)
#define __KPROBE_MAP6(m, t, a, ...) m(t, a), __KPROBE_MAP5(m, __VA_ARGS__)
#define __KPROBE_MAP7(m, t, a, ...) m(t, a), __KPROBE_MAP6(m, __VA_ARGS__)
#define __KPROBE_MAP8(m, t, a, ...) m(t, a), __KPROBE_MAP7(m, __VA_ARGS__)
#define __KPROBE_MAP(n, ...) __KPROBE_MAP##n(__VA_ARGS__)

#define __KPROBE_TYPE_AS(t, v)	__same_type((__force t)0, v)
#define __KPROBE_TYPE_IS_LL(t)	(__KPROBE_TYPE_AS(t, 0LL) || __KPROBE_TYPE_AS(t, 0ULL))
#define __KPROBE_DECL(t, a)	t a
#define __KPROBE_CAST(t, a)	(__force t) a
#define __KPROBE_ARGS(t, a)	a
#define __KPROBE_LONG(t, a)	\
	__typeof(__builtin_choose_expr(__KPROBE_TYPE_IS_LL(t), 0LL, 0L)) a
#define __KPROBE_TEST(t, a)	\
	(void)BUILD_BUG_ON_ZERO(!__KPROBE_TYPE_IS_LL(t) && sizeof(t) > sizeof(long))

#if defined(CONFIG_X86_64)
#define SC_ARCH_REGS_TO_ARGS(x, ...)					\
	__KPROBE_MAP(x,__KPROBE_ARGS					\
		     ,,regs->di,,regs->si,,regs->dx			\
		     ,,regs->rcx,,regs->r8,,regs->r9)

#define arg0(pt_regs)	((pt_regs)->di)
#define arg1(pt_regs)	((pt_regs)->si)
#define arg2(pt_regs)	((pt_regs)->dx)
#define arg3(pt_regs)	((pt_regs)->rcx)
#define arg4(pt_regs)	((pt_regs)->r8)
#define arg5(pt_regs)	((pt_regs)->r9)
#elif defined(CONFIG_ARM64)
#define SC_ARCH_REGS_TO_ARGS(x, ...)					\
	__KPROBE_MAP(x,__KPROBE_ARGS					\
		     ,,regs->regs[0],,regs->regs[1],,regs->regs[2]	\
		     ,,regs->regs[3],,regs->regs[4],,regs->regs[5]	\
		     ,,regs->regs[6],,regs->regs[7])

#define arg0(pt_regs)	((pt_regs)->regs[0])
#define arg1(pt_regs)	((pt_regs)->regs[1])
#define arg2(pt_regs)	((pt_regs)->regs[2])
#define arg3(pt_regs)	((pt_regs)->regs[3])
#define arg4(pt_regs)	((pt_regs)->regs[4])
#define arg5(pt_regs)	((pt_regs)->regs[5])
#define arg6(pt_regs)	((pt_regs)->regs[6])
#define arg7(pt_regs)	((pt_regs)->regs[7])
#else
#error "Unsupported architecture"
#endif

struct tracepoint_entry {
	const char *name;
	void *handler;
	void *priv;
	struct tracepoint *tp;
};

/* kprobe macro */
#define __KPROBE_HANDLER_DEFINE_COMM(name, off)				\
	static int name##_handler(struct kprobe *p,			\
				  struct pt_regs *regs);		\
	static struct kprobe name##_kprobe = {				\
		.symbol_name	= #name,				\
		.offset		= off,					\
		.pre_handler	= name##_handler			\
	};								\
	static struct kprobe * const __##name##_kprobe __used		\
	__attribute__((section(".__kprobe_template"))) =		\
		&name##_kprobe;						\
									\
	static inline int __init name##_register(void)			\
	{								\
		int ret;						\
									\
		ret = register_kprobe(&name##_kprobe);			\
		if (ret < 0)						\
			pr_err("kprobe register fail at %s+%x"		\
			       " returned %d\n", #name, off, ret);	\
		else							\
			pr_info("kprobe register at %pS\n",		\
				name##_kprobe.addr);			\
		return ret;						\
	}								\
									\
	static inline void __exit name##_unregister(void)		\
	{								\
		unregister_kprobe(&name##_kprobe);			\
		pr_info("kprobe unregister at %pS\n",			\
			name##_kprobe.addr);				\
	}

#define __KPROBE_HANDLER_DEFINE_x(x, name, ...)				\
	__KPROBE_HANDLER_DEFINE_COMM(name, 0)				\
	static inline int __se_##name##_handler(__KPROBE_MAP(x,		\
			__KPROBE_LONG, __VA_ARGS__));			\
	static inline int __do_##name##_handler(__KPROBE_MAP(x,		\
			__KPROBE_DECL, __VA_ARGS__));			\
	static int name##_handler(struct kprobe *p,			\
				  struct pt_regs *regs)			\
	{								\
		return __se_##name##_handler(SC_ARCH_REGS_TO_ARGS(x,	\
							__VA_ARGS__));	\
	}								\
									\
	static inline int __se_##name##_handler(__KPROBE_MAP(x,		\
			__KPROBE_LONG, __VA_ARGS__))			\
	{								\
		int ret = __do_##name##_handler(__KPROBE_MAP(x,		\
				__KPROBE_CAST, __VA_ARGS__));		\
		__KPROBE_MAP(x, __KPROBE_TEST, __VA_ARGS__);		\
		return ret;						\
	}								\
	static inline int __do_##name##_handler(__KPROBE_MAP(x,		\
			__KPROBE_DECL, __VA_ARGS__))

#define __KPROBE_HANDLER_DEFINE0(function)				\
	__KPROBE_HANDLER_DEFINE_COMM(function, 0)			\
	static inline int __do_##function##_handler(void);		\
	static int function##_handler(struct kprobe *p,			\
				      struct pt_regs *regs)		\
	{								\
		return __do_##function##_handler();			\
	}								\
	static inline int __do_##function##_handler(void)

#define __KPROBE_HANDLER_DEFINE_OFFSET(func, offset, ...)		\
	__KPROBE_HANDLER_DEFINE_COMM(func, offset)			\
	static inline int __se_##func##_handler(__KPROBE_MAP(1,		\
			__KPROBE_DECL, __VA_ARGS__));			\
	static inline int __do_##func##_handler(__KPROBE_MAP(1,		\
			__KPROBE_DECL, __VA_ARGS__));			\
	static int func##_handler(struct kprobe *p,			\
				  struct pt_regs *regs)			\
	{								\
		return __se_##func##_handler(regs);			\
	}								\
									\
	static inline int __se_##func##_handler(__KPROBE_MAP(1,		\
			__KPROBE_DECL, __VA_ARGS__))			\
	{								\
		int ret = __do_##func##_handler(__KPROBE_MAP(1,		\
				__KPROBE_CAST, __VA_ARGS__));		\
		__KPROBE_MAP(1, __KPROBE_TEST, __VA_ARGS__);		\
		return ret;						\
	}								\
	static inline int __do_##func##_handler(__KPROBE_MAP(1,		\
			__KPROBE_DECL, __VA_ARGS__))

/* kretprobe macro */
#define __KRETPROBE_ENTRY_HANDLER_DEFINE_COMM(name, type, off)		\
	static int name##_entry_handler(struct kretprobe_instance *ri,	\
					struct pt_regs *regs);		\
	static int name##_ret_handler(struct kretprobe_instance *ri,	\
				      struct pt_regs *regs);		\
	static struct kretprobe name##_kretprobe = {			\
		.kp.symbol_name	= #name,				\
		.kp.offset	= off,					\
		.handler	= name##_ret_handler,			\
		.entry_handler	= name##_entry_handler,			\
		.data_size	= sizeof(*((type)0)),			\
		.maxactive	= 0,					\
	};								\
	static struct kretprobe * const __##name##_kretprobe __used	\
	__attribute__((section(".__kretprobe_template"))) =		\
		&name##_kretprobe;					\
									\
	static inline int __init name##_register(void)			\
	{								\
		int ret;						\
									\
		ret = register_kretprobe(&name##_kretprobe);		\
		if (ret < 0)						\
			pr_err("kretprobe register fail at %s+%x"	\
			       " returned %d\n", #name, off, ret);	\
		else							\
			pr_info("kretprobe register at %pS\n",		\
				name##_kretprobe.kp.addr);		\
		return ret;						\
	}								\
									\
	static inline void __exit name##_unregister(void)		\
	{								\
		int nmissed = name##_kretprobe.nmissed;			\
									\
		if (nmissed)						\
			pr_info("kretprobe missed probing %d instances"	\
				" of %pS\n", nmissed,			\
				name##_kretprobe.kp.addr);		\
		unregister_kretprobe(&name##_kretprobe);		\
		pr_info("kretprobe unregister at %pS\n",		\
			name##_kretprobe.kp.addr);			\
	}

#define __KRETPROBE_ENTRY_HANDLER_DEFINE_x(x, name, type, arg, ...)	\
	__KRETPROBE_ENTRY_HANDLER_DEFINE_COMM(name, type, 0)		\
	static inline int __se_##name##_entry_handler(type arg, 	\
			__KPROBE_MAP(x, __KPROBE_LONG, __VA_ARGS__));	\
	static inline int __do_##name##_entry_handler(type arg, 	\
			__KPROBE_MAP(x, __KPROBE_DECL, __VA_ARGS__));	\
	static int name##_entry_handler(struct kretprobe_instance *ri,	\
					struct pt_regs *regs)		\
	{								\
		return __se_##name##_entry_handler((type)ri->data,	\
				SC_ARCH_REGS_TO_ARGS(x, __VA_ARGS__));	\
	}								\
									\
	static inline int __se_##name##_entry_handler(type arg,		\
			__KPROBE_MAP(x, __KPROBE_LONG, __VA_ARGS__))	\
	{								\
		int ret = __do_##name##_entry_handler(arg,		\
				__KPROBE_MAP(x, __KPROBE_CAST,		\
					     __VA_ARGS__));		\
		__KPROBE_MAP(x, __KPROBE_TEST, __VA_ARGS__);		\
		return ret;						\
	}								\
	static inline int __do_##name##_entry_handler(type arg,		\
			__KPROBE_MAP(x, __KPROBE_DECL, __VA_ARGS__))

#define __KRETPROBE_RET_HANDLER_DEFINE(func, ...)			\
	static inline int __se_##func##_ret_handler(__KPROBE_MAP(2,	\
			__KPROBE_LONG, __VA_ARGS__));			\
	static inline int __do_##func##_ret_handler(__KPROBE_MAP(2,	\
			__KPROBE_DECL, __VA_ARGS__));			\
	static int func##_ret_handler(struct kretprobe_instance *ri,	\
				      struct pt_regs *regs)		\
	{								\
		return __se_##func##_ret_handler((long)ri->data,	\
				(long)regs_return_value(regs));		\
	}								\
									\
	static inline int __se_##func##_ret_handler(__KPROBE_MAP(2,	\
			__KPROBE_LONG, __VA_ARGS__))			\
	{								\
		int ret = __do_##func##_ret_handler(__KPROBE_MAP(2,	\
				__KPROBE_CAST, __VA_ARGS__));		\
		__KPROBE_MAP(2, __KPROBE_TEST, __VA_ARGS__);		\
		return ret;						\
	}								\
	static inline int __do_##func##_ret_handler(__KPROBE_MAP(2,	\
			__KPROBE_DECL, __VA_ARGS__))

#define __KRETPROBE_ENTRY_HANDLER_DEFINE_OFFSET(func, offset, type, arg, ...) \
	__KRETPROBE_ENTRY_HANDLER_DEFINE_COMM(func, type, offset)	\
	static inline int __se_##func##_entry_handler(type arg, 	\
			__KPROBE_MAP(1, __KPROBE_DECL, __VA_ARGS__));	\
	static inline int __do_##func##_entry_handler(type arg, 	\
			__KPROBE_MAP(1, __KPROBE_DECL, __VA_ARGS__));	\
	static int func##_entry_handler(struct kretprobe_instance *ri,	\
					struct pt_regs *regs)		\
	{								\
		return __se_##func##_entry_handler((type)ri->data,	\
						   regs);		\
	}								\
									\
	static inline int __se_##func##_entry_handler(type arg,		\
			__KPROBE_MAP(1, __KPROBE_DECL, __VA_ARGS__))	\
	{								\
		int ret = __do_##func##_entry_handler(arg,		\
				__KPROBE_MAP(1, __KPROBE_CAST,		\
					     __VA_ARGS__));		\
		__KPROBE_MAP(1, __KPROBE_TEST, __VA_ARGS__);		\
		return ret;						\
	}								\
	static inline int __do_##func##_entry_handler(type arg,		\
			__KPROBE_MAP(1, __KPROBE_DECL, __VA_ARGS__))

#define __KRETPROBE_ENTRY_HANDLER_DEFINE0(func, type, arg)		\
	__KRETPROBE_ENTRY_HANDLER_DEFINE_COMM(func, type)		\
	static inline int __do_##func##_entry_handler(type arg);	\
	static int func##_entry_handler(struct kretprobe_instance *ri,	\
					struct pt_regs *regs)		\
	{								\
		return __do_##func##_entry_handler((type)ri->data);	\
	}								\
									\
	static inline int __do_##func##_entry_handler(type arg)

/* tracepoint macro */
#define __TRACEPOINT_HANDLER_DEFINE(tracepoint, ...)			\
	static void tracepoint##_tp_handler(void *priv, __VA_ARGS__);	\
	static struct tracepoint_entry tracepoint##_tp = {		\
		.name		= #tracepoint,				\
		.handler	= tracepoint##_tp_handler,		\
		.priv		= NULL,					\
	};								\
	static struct tracepoint_entry * const __##tracepoint##_tp	\
	__used __attribute__((section(".__tracepoint_template"))) =	\
		&tracepoint##_tp;					\
	static void tracepoint##_tp_handler(void *priv, __VA_ARGS__)

/* The below is the kretprobe API for kernel module */
#define KRETPROBE_ENTRY_HANDLER_DEFINE0(func, type, arg)      \
	__KRETPROBE_ENTRY_HANDLER_DEFINE0(func, type, arg)
#define KRETPROBE_ENTRY_HANDLER_DEFINE1(func, type, arg, ...) \
	__KRETPROBE_ENTRY_HANDLER_DEFINE_x(1, func, type, arg, __VA_ARGS__)
#define KRETPROBE_ENTRY_HANDLER_DEFINE2(func, type, arg, ...) \
	__KRETPROBE_ENTRY_HANDLER_DEFINE_x(2, func, type, arg, __VA_ARGS__)
#define KRETPROBE_ENTRY_HANDLER_DEFINE3(func, type, arg, ...) \
	__KRETPROBE_ENTRY_HANDLER_DEFINE_x(3, func, type, arg, __VA_ARGS__)
#define KRETPROBE_ENTRY_HANDLER_DEFINE4(func, type, arg, ...) \
	__KRETPROBE_ENTRY_HANDLER_DEFINE_x(4, func, type, arg, __VA_ARGS__)
#define KRETPROBE_ENTRY_HANDLER_DEFINE5(func, type, arg, ...) \
	__KRETPROBE_ENTRY_HANDLER_DEFINE_x(5, func, type, arg, __VA_ARGS__)
#define KRETPROBE_ENTRY_HANDLER_DEFINE6(func, type, arg, ...) \
	__KRETPROBE_ENTRY_HANDLER_DEFINE_x(6, func, type, arg, __VA_ARGS__)

#ifdef CONFIG_ARM64
#define KRETPROBE_ENTRY_HANDLER_DEFINE7(func, type, arg, ...) \
	__KRETPROBE_ENTRY_HANDLER_DEFINE_x(7, func, type, arg, __VA_ARGS__)
#define KRETPROBE_ENTRY_HANDLER_DEFINE8(func, type, arg, ...) \
	__KRETPROBE_ENTRY_HANDLER_DEFINE_x(8, func, type, arg, __VA_ARGS__)
#endif

#define KRETPROBE_ENTRY_HANDLER_DEFINE_OFFSET(func, offset, type, arg, ...) \
	__KRETPROBE_ENTRY_HANDLER_DEFINE_OFFSET(func, offset, type, arg, __VA_ARGS__)

#define KRETPROBE_RET_HANDLER_DEFINE(func, ...) \
	__KRETPROBE_RET_HANDLER_DEFINE(func, __VA_ARGS__)

/* The below is the kprobe API for kernel module */
#define KPROBE_HANDLER_DEFINE0(function)      \
	__KPROBE_HANDLER_DEFINE0(function)
#define KPROBE_HANDLER_DEFINE1(function, ...) \
	__KPROBE_HANDLER_DEFINE_x(1, function, __VA_ARGS__)
#define KPROBE_HANDLER_DEFINE2(function, ...) \
	__KPROBE_HANDLER_DEFINE_x(2, function, __VA_ARGS__)
#define KPROBE_HANDLER_DEFINE3(function, ...) \
	__KPROBE_HANDLER_DEFINE_x(3, function, __VA_ARGS__)
#define KPROBE_HANDLER_DEFINE4(function, ...) \
	__KPROBE_HANDLER_DEFINE_x(4, function, __VA_ARGS__)
#define KPROBE_HANDLER_DEFINE5(function, ...) \
	__KPROBE_HANDLER_DEFINE_x(5, function, __VA_ARGS__)
#define KPROBE_HANDLER_DEFINE6(function, ...) \
	__KPROBE_HANDLER_DEFINE_x(6, function, __VA_ARGS__)

#ifdef CONFIG_ARM64
#define KPROBE_HANDLER_DEFINE7(function, ...) \
	__KPROBE_HANDLER_DEFINE_x(7, function, __VA_ARGS__)
#define KPROBE_HANDLER_DEFINE8(function, ...) \
	__KPROBE_HANDLER_DEFINE_x(8, function, __VA_ARGS__)
#endif

#define KPROBE_HANDLER_DEFINE_OFFSET(func, offset, ...) \
	__KPROBE_HANDLER_DEFINE_OFFSET(func, offset, __VA_ARGS__)

/* The below is the tracepoint API for kernel module */
#define TRACEPOINT_HANDLER_DEFINE(tracepoint, ...)	\
	__TRACEPOINT_HANDLER_DEFINE(tracepoint, __VA_ARGS__)

/*
 * printk() is the king of all debuggers, but it has a problem. If you
 * are debugging a high volume area such as the timer interrupt, the
 * scheduler, or the network, printk() can lead to bogging down the
 * system or can even create a live lock. It is also quite common to
 * see a bug "disappear" when adding a few printk()s. This is due to
 * the sheer overhead that printk() introduces.
 *
 * Ftrace introduces a new form of printk() called trace_printk(). It
 * can be used just like printk(), and can also be used in any context
 * (interrupt code, NMI code, and scheduler code). What is nice about
 * trace_printk() is that it does not output to the console. Instead it
 * writes to the ftrace ring buffer and can be read via the trace file.
 *
 * Note:
 * The trace_printk()s will only show the format and not their parameters.
 *     echo printk-msg-only > /sys/kernel/debug/tracing/trace_options
 *
 * Read the trace file.
 *     cat /sys/kernel/debug/tracing/trace_pipe
 */
#define kprobe_printk(fmt, ...)	\
	trace_printk(KBUILD_MODNAME ": " fmt, ##__VA_ARGS__)

struct kprobe_initcall {
	int (*init)(void);
	void (*exit)(void);
};

#define KPROBE_INITCALL(init_func, exit_func)				\
	static const struct kprobe_initcall init_func##_initcall = {	\
		.init	= init_func,					\
		.exit	= exit_func,					\
	};								\
									\
	static const struct kprobe_initcall * const __used		\
	__##init_func##_initcall					\
	__attribute__((section(".__kprobe_initcall"))) =		\
		&init_func##_initcall

#endif /* __KPROBE_TEMPLATE_H */

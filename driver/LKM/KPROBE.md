# kprobe-template

I usually use kprobe/kretprobe in a kernel module. But I usually do a lot of pointless things. A lot of CTRL+C and CTRL+V. I am fed up with these. So I want to use macro definitions to do these meaningless things. So this is why I did this. Enjoy yourself.

## Kernel configuration

In general, to use these features, the kernel should have been compiled with the following flags set:

```bash
CONFIG_HAVE_KPROBES=y
CONFIG_KPROBES=y
CONFIG_TRACEPOINTS=y
# [optional, for syscall tracepoint]
CONFIG_HAVE_SYSCALL_TRACEPOINTS=y
```

## How to install

```bash
git clone https://github.com/smcdef/kprobe-template.git
cd kprobe-template
make -j8
```

The `kprobes.ko`is the module name in the kprobe-template. Using the following command to install it.

```bash
make install
```

If the module is installed successfully, you can get the following message via the `dmesg`.

```bash
[ 3508.653292] kprobes: kprobe register at __close_fd+0x0/0xa0
[ 3508.659202] kprobes: kprobe register at do_sys_open+0x0/0x210
[ 3508.668907] kprobes: kretprobe register at inode_permission+0x0/0x180
[ 3508.668981] kprobes: tracepoint register at trace_signal_generate
```

If you want to uninstall the module, you can use the following command.

```bash
make remove
```

Also, the `dmesg` will output the following message.

```bash
[ 3508.672202] kprobes: tracepoint unregister at trace_signal_generate
[ 3508.672281] kprobes: kretprobe unregister at inode_permission+0x0/0x180
[ 3508.682470] kprobes: kprobe unregister at do_sys_open+0x0/0x210
[ 3508.699454] kprobes: kprobe unregister at __close_fd+0x0/0xa0
```

## How to use

The API is mainly divided into three categories, namely kprobe, kretprobe and tracepoint. First let's see how to use the kprobe APIs.

### kprobe

Now if you want to hook the `do_sys_open` function, what should you do. First of all, we can find the definition of the `do_sys_open` in the fs/open.c.

```c
long do_sys_open(int dfd, const char __user *filename,
                 int flags, umode_t mode);
```

In the [kprobe.h](./kprobe.h), there are seven APIs that we can use for kprobe.

```c
KPROBE_HANDLER_DEFINE0(function);
KPROBE_HANDLER_DEFINE1(function);
KPROBE_HANDLER_DEFINE2(function);
KPROBE_HANDLER_DEFINE3(function);
KPROBE_HANDLER_DEFINE4(function);
KPROBE_HANDLER_DEFINE5(function);
KPROBE_HANDLER_DEFINE6(function);

KPROBE_HANDLER_DEFINE_OFFSET(function, offset);
```

As you can see, the `do_sys_open` has four parameters. So we should use the `KPROBE_HANDLER_DEFINE4`. For the same reason, if the function has none parameter. You should use the `KPROBE_HANDLER_DEFINE0`. Then we should program as follows.

```c
#include "kprobe.h"

KPROBE_HANDLER_DEFINE4(do_sys_open,
                       int, dfd, const char __user *, filename,
                       int, flags, umode_t, mode)
{
        /* Now you get all parameters. */
        pr_info("mode: %x\n", mode);
        return 0;
}
```

### kprobe at offset

If you want to kprobe a function at the special offet(e.g. 0x5). Just like this.

```c
#include "kprobe.h"

KPROBE_HANDLER_DEFINE_OFFSET(do_sys_open, 0x5,
                             struct pt_regs *, regs)
{
        /*
         * The context registers are store in
         * the struct pt_regs.
         */
        return 0;
}
```

### kretprobe

In the [kprobe.h](./kprobe.h), there are seven APIs that we can use for kretprobe. Six of them are for entry handler, the other is for return handler.

```c
/* entry handler */
KRETPROBE_ENTRY_HANDLER_DEFINE0(func, type, arg);
KRETPROBE_ENTRY_HANDLER_DEFINE1(func, type, arg);
KRETPROBE_ENTRY_HANDLER_DEFINE2(func, type, arg);
KRETPROBE_ENTRY_HANDLER_DEFINE3(func, type, arg);
KRETPROBE_ENTRY_HANDLER_DEFINE4(func, type, arg);
KRETPROBE_ENTRY_HANDLER_DEFINE5(func, type, arg);
KRETPROBE_ENTRY_HANDLER_DEFINE6(func, type, arg);

/* return handler */
KRETPROBE_RET_HANDLER_DEFINE(func);
```

Suppose you want to trace `do_sys_open`, and you want to print the parameters passed by its caller only when `do_sys_open` returns an error. How to do that?

```c
#include "kprobe.h"

struct parameters {
        const char __user *filename;
        int flags;
};

/* do_sys_open entry handler */
KRETPROBE_ENTRY_HANDLER_DEFINE4(do_sys_open, struct parameters *, pars,
                                int, dfd, const char __user *, filename,
                                int, flags, umode_t, mode)
{
        if (!current->mm)
                return -1;	/* Skip kernel threads */

        pars->filename = filename;
        pars->flags = flags;

        return 0;
}

/* do_sys_open return handler */
KRETPROBE_RET_HANDLER_DEFINE(do_sys_open,
                             struct parameters *, pars, int, retval)
{
        if (retval < 0)
                pr_info("flags: 0x%x, retval: %d\n", pars->flags, retval);
        return 0;
}
```

The `do_sys_open` has four parameters, so you should use `KRETPROBE_ENTRY_HANDLER_DEFINE4`. The `struct parameters`is the your own private data structure. If you only want to store one parameter or other privata data(maybe timestamp or what else you want), you can just use a `long` type instead of a structure. The `KRETPROBE_RET_HANDLER_DEFINE` only has two parameters, one is the private data structure and the other is the `retval` which is the return value of the `do_sys_open` function. The `int` type is the `do_sys_open` function return type. If the function return type is a pointer type, here should be a pointer type.

### kretprobe at offset

The kretprobe does not support the specified offset except zero. So if you want to use the `KRETPROBE_ENTRY_HANDLER_DEFINE_OFFSET(func, offset, type, arg)` macro. The `offset` must be zero. Otherwise kretprobe will fail to register.

### tracepoint

There is only one API for tracepoint. Now if you want to trace signal via `trace_signal_generate`. You can use the `TRACEPOINT_HANDLER_DEFINE`. Just like this.

```c
#include "kprobe.h"

/* tracepoint signal_generate */
TRACEPOINT_HANDLER_DEFINE(signal_generate,
			  int sig, struct siginfo *info,
			  struct task_struct *task, int group, int result)
{
	static const char *result_name[] = {
		"deliverd",
		"ignored",
		"already_pending",
		"overflow_fail",
		"lose_info",
	};

	pr_info("%s(%d) send signal(%d) to %s %s(%d) with %s\n",
		current->comm, current->pid, sig, group ? "group" : "single",
		task->comm, task->pid, result_name[result]);
}
```

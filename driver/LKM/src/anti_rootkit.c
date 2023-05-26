//  SPDX-License-Identifier: GPL-2.0
/*
 *  anti_rootkit.c
 *  
 *  Anti Rootkit tool are mainly based on Nick Bulischeck's Tyton. Smith HIDS currently only includes
 *  hidding module, proc hidding, interrupt hijacking and system call hijacking checks. 
 *  From: https://github.com/nbulischeck/tyton
 *  Author: Nick Bulischeck <nbulisc@clemson.edu>
 */

#include "../include/kprobe.h"

#define ANTI_ROOTKIT_CHECK 1
#if ANTI_ROOTKIT_CHECK

#include "../include/util.h"
#include <linux/kthread.h>
#include "../include/anti_rootkit.h"
#define __SD_XFER_SE__
#include "../include/xfer.h"
#include "../include/anti_rootkit_print.h"

#define DEFERRED_CHECK_TIMEOUT (15 * 60)

static int (*ckt) (unsigned long addr) = NULL;

#ifdef CONFIG_X86
#include <asm/unistd.h>
static unsigned long *idt = NULL;
#endif

static unsigned long *sct = NULL;
static struct kset *mod_kset = NULL;
static struct mutex *mod_lock = NULL;
struct module *(*mod_find_module)(const char *name);
static struct module *(*get_module_from_addr)(unsigned long addr);

#define BETWEEN_PTR(x, y, z) ( \
    ((uintptr_t)x >= (uintptr_t)y) && \
    ((uintptr_t)x < ((uintptr_t)y+(uintptr_t)z)) \
)

static char *find_hidden_module(unsigned long addr)
{
    char *mod_name = NULL;
    struct kobject *cur;
    struct module_kobject *kobj;

    if (unlikely(!mod_kset))
        return NULL;

    spin_lock(&mod_kset->list_lock);
    list_for_each_entry(cur, &mod_kset->list, entry) {
        if (!kobject_name(cur))
            break;

        kobj = container_of(cur, struct module_kobject, kobj);
        if (!kobj || !kobj->mod)
            continue;

#if defined(KMOD_CORE_LAYOUT) || LINUX_VERSION_CODE >= KERNEL_VERSION(4, 5, 0)
		/*
		 * vanilla kernels (kernel.org): >= 4.5.0
		 * ubuntu kernels: >= 4.4.0
		 */
		if (BETWEEN_PTR(addr, kobj->mod->core_layout.base,
			kobj->mod->core_layout.size))
			mod_name = kobj->mod->name;
#else
		if (BETWEEN_PTR(addr, kobj->mod->module_core,
			kobj->mod->core_size))
			mod_name = kobj->mod->name;
#endif
    }
    spin_unlock(&mod_kset->list_lock);

    return mod_name;
}

static void module_list_lock(void)
{
    if (likely(mod_lock))
		mutex_lock(mod_lock);
}

static void module_list_unlock(void)
{
    if (likely(mod_lock))
		mutex_unlock(mod_lock);

}

static void analyze_syscalls(void)
{
    int i;
	unsigned long addr;
	struct module *mod;

	if (!sct || !ckt)
		return;

	
	for (i = 0; i < NR_syscalls; i++) {
		char *mod_name = "-1";
		addr = sct[i];
	
		if (!ckt(addr)) {
			module_list_lock();
			mod = get_module_from_addr(addr);
			if (mod) {
				mod_name = mod->name;
			} else {
				char* name = find_hidden_module(addr);
				if (IS_ERR_OR_NULL(name)) {
				    module_list_unlock();
				    continue;
				}

				mod_name = name;
			}
			
			syscall_print(mod_name, i);
			module_list_unlock();
		}
	}
}

static void analyze_interrupts(void)
{
#ifdef CONFIG_X86
	int i;
	unsigned long addr;
	struct module *mod;

	if (!idt || !ckt)
		return;

	for (i = 0; i < IDT_ENTRIES; i++) {
		char *mod_name = "-1";

		addr = idt[i];
		if (!ckt(addr)) {
			module_list_lock();

			mod = get_module_from_addr(addr);
			if (mod) {
				mod_name = mod->name;
			} else {
				char *name = find_hidden_module(addr);
				if (IS_ERR_OR_NULL(name)) {
				    module_list_unlock();
				    continue;
				}

				mod_name = name;
			}

			interrupts_print(mod_name, i);
			module_list_unlock();
		}
	}
#endif
}

static void analyze_modules(void)
{
    struct kobject *cur;
	struct module_kobject *kobj;

	if (unlikely(!mod_kset))
		return;

	spin_lock(&mod_kset->list_lock);
	list_for_each_entry(cur, &mod_kset->list, entry) {
		if (!kobject_name(cur)) {
			break;
		}

		kobj = container_of(cur, struct module_kobject, kobj);
		if (kobj && kobj->mod) {
			if (mod_find_module && !mod_find_module(kobj->mod->name))
				mod_print(kobj->mod->name);
		}
	}
	spin_unlock(&mod_kset->list_lock);
}

static void analyze_fops(void)
{
    struct module *mod = NULL;
    unsigned long addr;
	char *mod_name;
	struct file *fp;

	fp = filp_open("/proc", O_RDONLY, S_IRUSR);
	if (IS_ERR_OR_NULL(fp)) {
		printk(KERN_INFO "[ELKEID] open /proc error\n");
		return;
	}

	if (IS_ERR_OR_NULL(fp->f_op)) {
		printk(KERN_INFO "[ELKEID] /proc has no fops\n");
		filp_close(fp, NULL);
		return;
	}
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 11, 0)
	addr = (unsigned long)fp->f_op->iterate;
#else
	addr = (unsigned long)fp->f_op->readdir;
#endif

	if (!ckt(addr)) {
		module_list_lock();
		if (get_module_from_addr)
		    mod = get_module_from_addr(addr);
		mod_name = mod ? mod->name : find_hidden_module(addr);
		if (!IS_ERR_OR_NULL(mod_name))
			fops_print(mod_name);
		module_list_unlock();
	}
	filp_close(fp, NULL);
}

static void anti_rootkit_check(void)
{
	analyze_fops();
	analyze_syscalls();
	analyze_modules();
	analyze_interrupts();
}

static struct task_struct *g_worker_thread;
static int anti_rootkit_worker(void *argv)
{
    unsigned long timeout = msecs_to_jiffies(DEFERRED_CHECK_TIMEOUT * 1000);

    do {
        /* waiting 15 minutes, or being waken up */
        if (!schedule_timeout_interruptible(timeout)) {
            /* perform rootkit detection */
            anti_rootkit_check();
        }
    } while (!kthread_should_stop());

    /* kernen thread entry aka kernel() will finally call do_exit */
    return 0;
}

static int __init anti_rootkit_start(void)
{
    int rc = 0;

    g_worker_thread = kthread_create(anti_rootkit_worker, 0, "elkeid - antirootkit");
    if (IS_ERR(g_worker_thread)) {
        rc = g_worker_thread ? PTR_ERR(g_worker_thread) : -ENOMEM;
        printk("anti_rootkit_start: failed creating anti-rootkit worker: %d\n", rc);
        return rc;
    }

    /* wake up anti-rootkit worker thread */
    if (!wake_up_process(g_worker_thread)) {
        kthread_stop(g_worker_thread);
        g_worker_thread = NULL;
    }
    return rc;
}

static int __init anti_rootkit_init(void)
{
    struct kset **kset;

#ifdef CONFIG_X86
    idt = (void *)smith_kallsyms_lookup_name("idt_table");
#endif
    sct = (void *)smith_kallsyms_lookup_name("sys_call_table");
    ckt = (void *)smith_kallsyms_lookup_name("core_kernel_text");
	mod_lock = (void *)smith_kallsyms_lookup_name("module_lock");
	mod_find_module = (void *)smith_kallsyms_lookup_name("find_module");
    get_module_from_addr = (void *)smith_kallsyms_lookup_name("__module_address");
    kset = (void *)smith_kallsyms_lookup_name("module_kset");
    if (kset)
        mod_kset = *kset;

    /* start rootkit-detection worker thread */
    anti_rootkit_start();

    printk("[ELKEID] ANTI_ROOTKIT_CHECK: %d\n", ANTI_ROOTKIT_CHECK);
    return 0;
}

static void anti_rootkit_exit(void)
{
    /* kthread_stop will wait until worker thread exits */
    if (!IS_ERR_OR_NULL(g_worker_thread)) {
        kthread_stop(g_worker_thread);
    }
}

#else /* !ANTI_ROOTKIT_CHECK */

static int __init anti_rootkit_init(void)
{
	return 0;
}

static void anti_rootkit_exit(void)
{
    return;
}

#endif /* ANTI_ROOTKIT_CHECK */

KPROBE_INITCALL(anti_rootkit, anti_rootkit_init, anti_rootkit_exit);

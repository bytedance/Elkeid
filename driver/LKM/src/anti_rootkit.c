//  SPDX-License-Identifier: GPL-3.0
/*
 *  anti_rootkit.c
 *  
 *  Anti Rootkit tool are mainly based on Nick Bulischeck's Tyton. Smith HIDS currently only includes
 *  hidding module, proc hidding, interrupt hijacking and system call hijacking checks. 
 *  From: https://github.com/nbulischeck/tyton
 *  Author: Nick Bulischeck <nbulisc@clemson.edu>
 */

#include "../include/kprobe.h"
#include "../include/anti_rootkit.h"
#include "../include/util.h"

#define CREATE_PRINT_EVENT
#include "anti_rootkit_print.h"

#define ANTI_ROOTKIT_CHECK 1

#define DEFERRED_CHECK_TIMEOUT (15 * 60 * HZ)

static int (*ckt) (unsigned long addr) = NULL;

static unsigned long *idt = NULL;
static unsigned long *sct = NULL;
static struct kset *mod_kset = NULL;

static void work_func(struct work_struct *dummy);

static DECLARE_DELAYED_WORK(work, work_func);

#define BETWEEN_PTR(x, y, z) ( \
    ((uintptr_t)x >= (uintptr_t)y) && \
    ((uintptr_t)x < ((uintptr_t)y+(uintptr_t)z)) \
)

static struct module *get_module_from_addr(unsigned long addr)
{
    return __module_address(addr);
}

static const char *find_hidden_module(unsigned long addr)
{
    const char *mod_name = NULL;
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

#ifdef UBUNTU_CHECK
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 4, 0)
		if (BETWEEN_PTR
		    (addr, kobj->mod->core_layout.base,
		     kobj->mod->core_layout.size))
			mod_name = kobj->mod->name;
#else
		if (BETWEEN_PTR
		    (addr, kobj->mod->module_core, kobj->mod->core_size))
			mod_name = kobj->mod->name;
#endif
#else //UBUNTU_CHECK
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 5, 0)
        if (BETWEEN_PTR
		    (addr, kobj->mod->core_layout.base,
		     kobj->mod->core_layout.size))
			mod_name = kobj->mod->name;
#else
        if (BETWEEN_PTR
        (addr, kobj->mod->module_core, kobj->mod->core_size))
            mod_name = kobj->mod->name;
#endif
#endif // UBUNTU_CHECK
    }
    spin_unlock(&mod_kset->list_lock);

    return mod_name;
}


#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)

static void analyze_syscalls(void)
{
    int i;
	unsigned long addr;
	struct module *mod;

	if (!sct || !ckt)
		return;

	
	for (i = 0; i < NR_syscalls; i++) {
		const char *mod_name = "-1";
		addr = sct[i];
	
		if (!ckt(addr)) {
			mutex_lock(&module_mutex);
			mod = get_module_from_addr(addr);
			if (mod) {
				mod_name = mod->name;
			} else {
				const char* name = find_hidden_module(addr);
				if (IS_ERR_OR_NULL(name)) {
				    mutex_unlock(&module_mutex);
				    continue;
				}

				mod_name = name;
			}
			
			syscall_print(mod_name, i);
			mutex_unlock(&module_mutex);
		}
	}
}

static void analyze_interrupts(void)
{
    int i;
	unsigned long addr;
	struct module *mod;

	if (!idt || !ckt)
		return;

	for (i = 0; i < IDT_ENTRIES; i++) {
		const char *mod_name = "-1"; 

		addr = idt[i];
		if (!ckt(addr)) {
			mutex_lock(&module_mutex);

			mod = get_module_from_addr(addr);
			if (mod) {
				mod_name = mod->name;
			} else {
				const char *name = find_hidden_module(addr);
				if (IS_ERR_OR_NULL(name)) {
				    mutex_unlock(&module_mutex);
				    continue;
				}

				mod_name = name;
			}

			interrupts_print(mod_name, i);
			mutex_unlock(&module_mutex);
		}
	}
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
		if (kobj && kobj->mod && kobj->mod->name) {
			if (!find_module(kobj->mod->name))
				mod_print(kobj->mod->name);
		}
	}
	spin_unlock(&mod_kset->list_lock);
}

static void analyze_fops(void)
{
    unsigned long addr;
	const char *mod_name;
	struct file *fp;
	struct module *mod;

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
		mutex_lock(&module_mutex);
		mod = get_module_from_addr(addr);
		mod_name = mod ? mod->name : find_hidden_module(addr);
		if (!IS_ERR_OR_NULL(mod_name))
			fops_print(mod_name);
		mutex_unlock(&module_mutex);
	}
	filp_close(fp, NULL);
}

#endif // LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)


static void anti_rootkit_check(void)
{
    analyze_fops();
	analyze_syscalls();
	analyze_modules();
	analyze_interrupts();
}

static void work_func(struct work_struct *dummy)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
    anti_rootkit_check();
	schedule_delayed_work(&work, round_jiffies_relative(DEFERRED_CHECK_TIMEOUT));
#endif
}

static void init_del_workqueue(void)
{
    schedule_delayed_work(&work, 0);
}

static void exit_del_workqueue(void)
{
    cancel_delayed_work_sync(&work);
}

static int __init anti_rootkit_init(void)
{
    struct kset **kset;

    idt = (void *)smith_kallsyms_lookup_name("idt_table");
    sct = (void *)smith_kallsyms_lookup_name("sys_call_table");
    ckt = (void *)smith_kallsyms_lookup_name("core_kernel_text");
    kset = (void *)smith_kallsyms_lookup_name("module_kset");
    if (kset)
        mod_kset = *kset;
    init_del_workqueue();
    printk("[ELKEID] ANTI_ROOTKIT_CHECK: %d\n", ANTI_ROOTKIT_CHECK);
    return 0;
}

static void anti_rootkit_exit(void)
{
    exit_del_workqueue();
}

#if (ANTI_ROOTKIT_CHECK == 1 && LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0))
KPROBE_INITCALL(anti_rootkit_init, anti_rootkit_exit);
#endif

// SPDX-License-Identifier: GPL-2.0
/*
 * util.c
 *
 */
#include "../include/util.h"
#include <linux/version.h>
#include <linux/kallsyms.h>

#define PID_TREE_MATEDATA_LEN  32

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 7, 0)

static unsigned long (*kallsyms_lookup_name_sym)(const char *name);
static int dummy_kprobe_handler(struct kprobe *p, struct pt_regs *regs){
        return 0;
}

unsigned long get_kallsyms_func(void){
        struct kprobe probe;
        int ret;
        unsigned long addr;

        memset(&probe, 0, sizeof(probe));
        probe.pre_handler = dummy_kprobe_handler;
        probe.symbol_name = "kallsyms_lookup_name";
        ret = register_kprobe(&probe);
        if (ret)
                return 0;
        addr = (unsigned long)probe.addr;
        unregister_kprobe(&probe);
        return addr;
}


unsigned long smith_kallsyms_lookup_name(const char *name)
{
        /* singleton */
        if (!kallsyms_lookup_name_sym) {
                kallsyms_lookup_name_sym = (void *)get_kallsyms_func();
                if(!kallsyms_lookup_name_sym)
                        return 0;
        }
        return kallsyms_lookup_name_sym(name);
}

#else

unsigned long smith_kallsyms_lookup_name(const char *name)
{
    return kallsyms_lookup_name(name);
}

#endif

#ifdef CONFIG_X86
#if LINUX_VERSION_CODE > KERNEL_VERSION(4, 7, 0)
u64 GET_PPIN(void)
{
	int err;
	u64 res;
	res = paravirt_read_msr_safe(0x4f, &err);
	return res;
}
#else
u64 GET_PPIN(void)
{
	return 0;
}
#endif
#else

u64 GET_PPIN(void)
{
    return 0;
}

#endif


//get task exe file full path && only current can use it
char *get_exe_file(struct task_struct *task, char *buffer, int size)
{
    char *exe_file_str = "-1";

    if (!buffer || !task->mm)
        return exe_file_str;

    if (down_read_trylock(&task->mm->mmap_sem)) {
        if (task->mm->exe_file) {
            exe_file_str =
                    d_path(&task->mm->exe_file->f_path, buffer,
                           size);

            if (IS_ERR(exe_file_str))
                exe_file_str = "-1";
        }
        up_read(&task->mm->mmap_sem);
    }

    return exe_file_str;
}

//get pid tree
char *get_pid_tree(int limit)
{
    int real_data_len = PID_TREE_MATEDATA_LEN;
    int limit_index = 0;
    char *tmp_data = NULL;
    char pid[24];
    struct task_struct *task;
    struct task_struct *old_task;

    task = current;
    get_task_struct(task);

    //task->pid is int
    snprintf(pid, 24, "%d", task->pid);
    tmp_data = kzalloc(1024, GFP_ATOMIC);

    if (!tmp_data) {
        put_task_struct(task);
        return tmp_data;
    }

    strcat(tmp_data, pid);
    strcat(tmp_data, ".");
    strcat(tmp_data, current->comm);

    while (1) {
        limit_index = limit_index + 1;
        if (limit_index >= limit) {
            put_task_struct(task);
            break;
        }

        old_task = task;
        rcu_read_lock();
        task = rcu_dereference(task->real_parent);
        put_task_struct(old_task);
        if (!task || task->pid == 1) {
            rcu_read_unlock();
            break;
        }

        get_task_struct(task);
        rcu_read_unlock();

        real_data_len = real_data_len + PID_TREE_MATEDATA_LEN;
        if (real_data_len > 1024) {
            put_task_struct(task);
            break;
        }

        snprintf(pid, sizeof(size_t), "%d", task->pid);
        strcat(tmp_data, "<");
        strcat(tmp_data, pid);
        strcat(tmp_data, ".");
        strcat(tmp_data, task->comm);
    }

    return tmp_data;
}

int prepend(char **buffer, int *buflen, const char *str, int namelen)
{
    *buflen -= namelen;
    if (*buflen < 0)
        return -ENAMETOOLONG;
    *buffer -= namelen;
    memcpy(*buffer, str, namelen);
    return 0;
}

int prepend_name(char **buffer, int *buflen, struct qstr *name)
{
    return prepend(buffer, buflen, name->name, name->len);
}


//get file path from dentry struct
char *__dentry_path(struct dentry *dentry, char *buf, int buflen)
{
    char *end = buf + buflen;
    char *retval;

    prepend(&end, &buflen, "\0", 1);
    if (buflen < 1)
        goto Elong;
    retval = end - 1;
    *retval = '/';

    while (!IS_ROOT(dentry)) {
        struct dentry *parent = dentry->d_parent;
        int error;

        prefetch(parent);
        spin_lock(&dentry->d_lock);
        error = prepend_name(&end, &buflen, &dentry->d_name);
        spin_unlock(&dentry->d_lock);
        if (error != 0 || prepend(&end, &buflen, "/", 1) != 0)
            goto Elong;

        retval = end;
        dentry = parent;
    }
    return retval;
Elong:
    return ERR_PTR(-ENAMETOOLONG);
}

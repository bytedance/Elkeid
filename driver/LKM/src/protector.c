/**
 * \author lijie.byte<lijie.byte@bytedance.com>
 */

#include <linux/string.h>
#include <linux/kprobes.h>
#include <linux/mutex.h>
#include <linux/namei.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/fs_struct.h>
#include <linux/dcache.h>
#include <linux/version.h>

#include "struct_wrap.h"
#include "smith_hook.h"
#include "protector.h"

static int g_protector_switch = 0; // 1: enable, 0: disable
static int g_protector_status = 0;
static DEFINE_MUTEX(g_protector_lock);

static int smith_protect_enable(void);
static void smith_protect_disable(void);

static void smith_protect_switch(void) {
    mutex_lock(&g_protector_lock);
    if (g_protector_switch != g_protector_status) {
        if (g_protector_switch) { // enable self-protection
            if (smith_protect_enable() == 0) {
                g_protector_status = 1;
            } else { // enable failed
                smith_protect_disable();
                g_protector_status = 0;
            }
        } else { // disable self-protection
            smith_protect_disable();
            g_protector_status = 0;
        }
    }
    mutex_unlock(&g_protector_lock);
}

#if defined(module_param_cb)
#define K_PARAM_CONST const
#else
#define K_PARAM_CONST
#endif

static int protector_set_params(const char *val, K_PARAM_CONST struct kernel_param *kp) {
    if (strcmp(kp->name, "protector_switch") == 0) {
        int rc = param_set_bool(val, kp);
        if (!rc)
            smith_protect_switch();
        return rc;
    }
    return 0;
}

#if defined(module_param_cb)
const struct kernel_param_ops protector_param_ops = {
    .set = protector_set_params,
    .get = param_get_bool,
};
module_param_cb(protector_switch, &protector_param_ops, &g_protector_switch, 0600);
#elif defined(module_param_call)
module_param_call(protector_switch, protector_set_params, param_get_bool, &g_protector_switch, 0600);
#else
#warning "module_param_cb or module_param_call are not supported by target kernel"
#endif

MODULE_PARM_DESC(protector_switch, "Set to Y to enable self-protection, N otherwise");

static char *g_protected_dirs[] = {
        "/etc/elkeid/",
        "/etc/sysop/mongoosev3-agent/",
        NULL
};

struct protected_dir {
    struct dentry *dentry;
};

static struct protected_dir *g_dir_cache = NULL;
static int g_dir_cache_size = 0;

static int init_protected_dirs(void) {
    char **p = NULL;
    int count = 0;

    for (p = g_protected_dirs; *p != NULL; p++) count++;

    g_dir_cache = kcalloc(count, sizeof(struct protected_dir), GFP_KERNEL); // include memset
    if (!g_dir_cache) return -1;

    for (p = g_protected_dirs, count = 0; *p != NULL; p++, count++) {
        struct path path;
        if (kern_path(*p, LOOKUP_FOLLOW, &path) == 0) {
            g_dir_cache[count].dentry = dget(path.dentry);
            path_put(&path);
        } else {
            pr_debug("[ELKEID] Failed to resolve path: %s\n", *p);
        }
    }
    g_dir_cache_size = count;
    return 0;
}

static void destroy_protected_dirs(void) {
    int i;
    if (g_dir_cache) {
        for (i = 0; i < g_dir_cache_size; i++) {
            if (g_dir_cache[i].dentry) {
                dput(g_dir_cache[i].dentry);
            }
        }
        kfree(g_dir_cache);
        g_dir_cache = NULL;
        g_dir_cache_size = 0;
    }
}

/// Note: make sure dentry pointer is always here. Or it will cause panic.
static int check_dentry_under_protected_dentry(struct dentry *dentry, struct dentry *protected_dentry) {
    struct dentry *cur_dentry = dentry;
    struct dentry *parent = NULL;
    int ret = 0;

    if (IS_ERR_OR_NULL(dentry) || IS_ERR_OR_NULL(protected_dentry))
        return 0;

    while (cur_dentry) {
        if (cur_dentry == protected_dentry) {
            ret = 1; // 说明 dentry 是 protected_dentry 的子目录
            break;
        }

        parent = cur_dentry->d_parent;
        if (IS_ERR_OR_NULL(parent) || parent == cur_dentry) {
            break;
        }
        cur_dentry = parent;
    }
    return ret; // 1: protected, 0: not protected
}

static int check_dentry_is_protected(struct dentry *dentry) {
    int i, ret = 0;
    for (i = 0; i < g_dir_cache_size; i++) {
        struct dentry *protected_dentry = g_dir_cache[i].dentry;
        if (protected_dentry) {
            ret = check_dentry_under_protected_dentry(dentry, protected_dentry);
            if (ret) {
                break;
            }
        }
    }
    return ret; // 1: protected, 0: not protected
}

/// If we match directories based on dentry, we need to manage dentry carefully. Another limitation
/// is that we can't use dput during kretprobe, therefore make sure dentry pointer valid is very difficult.
/// The simplest way is to match directories based on string matching.

static __always_inline size_t smith_str_has_prefix(const char *str, const char *prefix)
{
    size_t len = strlen(prefix);
    return strncmp(str, prefix, len) == 0 ? len : 0;
}

int check_exe_path_is_protected(const char *exe_path) {
    char **p = NULL;
    for (p = g_protected_dirs; *p != NULL; p++) {
        if (smith_str_has_prefix(exe_path, *p)) {
            return 1; // protected
        }
    }
    return 0; // not protected
}

static int check_task_is_protected_by_tid(struct task_struct *task) {
    int ret = 0;
    struct smith_tid *tid = NULL;

    if (IS_ERR_OR_NULL(task))
        return 0;

    if (task->pid == 0)
        return 1;

    tid = smith_lookup_tid(task);
    if (tid) {
        ret = tid->protected;
        smith_put_tid(tid);
    }
    return ret; // 1: protected, 0: not protected
}

static int check_current_has_privilege(void) {
    return check_task_is_protected_by_tid(current); // 1: protected, 0: not protected
}

static int do_register_kretprobe(struct kretprobe *krp, int *state) {
    int ret, active;

    if (*state > 0) return 0; // already hooked

    active = max_t(int, 32, 2 * num_present_cpus());
    if (krp->maxactive < active)
        krp->maxactive = active;

    if ((ret = register_kretprobe(krp)) < 0) {
        *state = 0;
    } else {
        *state = 1;
    }
    return ret; // 0: success, <0: error
}

static void do_unregister_kretprobe(struct kretprobe *krp, int *state) {
    if (*state > 0) {
        unregister_kretprobe(krp);
        *state = 0;
    }
}

struct krp_common_data {
    int block;
};

static int krp_do_block_ret_handler(struct kretprobe_instance *ri, struct pt_regs *regs) {
    struct krp_common_data *data = (struct krp_common_data *)ri->data;

    if (data->block) {
        smith_regs_set_return_value(regs, -EPERM); // Operation not permitted
    }
    return 0;
}

/// int security_task_kill(struct task_struct *p, struct kernel_siginfo *info,
///                        int sig, const struct cred *cred);
///
/// @p: target process
/// @info: signal information
/// @sig: signal value
/// @cred: credentials of the signal sender, NULL if @current

static int krp_kill_entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs) {
    struct krp_common_data *data = (struct krp_common_data *)ri->data;
    struct task_struct *target = (struct task_struct *)p_regs_get_arg1(regs); // regs->di

    data->block = 0;
    if (target && check_task_is_protected_by_tid(target)) {
        if (check_current_has_privilege()) {
            return 0;
        }
        data->block = 1;
        //pr_debug("Block kill/ptrace attempt on %d -> %d\n", current->pid, target->pid);
    }
    return 0;
}

static struct kretprobe krp_kill;
static int hook_krp_kill_state = 0; // 1: hooked, 0: not hooked

static int register_kretprobe_task_kill(void) {
    struct kretprobe *krp = &krp_kill;
    memset(krp, 0, sizeof(struct kretprobe)); // it's necessary

    krp->kp.symbol_name = "security_task_kill";
    krp->handler = krp_do_block_ret_handler;
    krp->entry_handler = krp_kill_entry_handler;
    krp->data_size = sizeof(struct krp_common_data);
    return do_register_kretprobe(krp, &hook_krp_kill_state);
}

static void unregister_kretprobe_task_kill(void) {
    do_unregister_kretprobe(&krp_kill, &hook_krp_kill_state);
}

/// int security_ptrace_access_check(struct task_struct *child, unsigned int mode);
///
/// @child: target process
/// @mode: PTRACE_MODE flags

static struct kretprobe krp_ptrace;
static int hook_krp_ptrace_state = 0; // 1: hooked, 0: not hooked

static int register_kretprobe_ptrace(void) {
    struct kretprobe *krp = &krp_ptrace;
    memset(krp, 0, sizeof(struct kretprobe)); // it's necessary

    krp->kp.symbol_name = "security_ptrace_access_check";
    krp->handler = krp_do_block_ret_handler;
    krp->entry_handler = krp_kill_entry_handler;
    krp->data_size = sizeof(struct krp_common_data);
    return do_register_kretprobe(krp, &hook_krp_ptrace_state);
}

static void unregister_kretprobe_ptrace(void) {
    do_unregister_kretprobe(&krp_ptrace, &hook_krp_ptrace_state);
}

/// int security_path_link(struct dentry *old_dentry, const struct path *new_dir,
///                        struct dentry *new_dentry);
///
/// @old_dentry: existing file
/// @new_dir: new parent directory
/// @new_dentry: new link

static int krp_path_link_entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs) {
    struct krp_common_data *data = (struct krp_common_data *)ri->data;
    struct dentry *dentry = (struct dentry *)p_regs_get_arg1(regs); // regs->di

    data->block = 0;
    if (dentry && check_dentry_is_protected(dentry)) {
        if (check_current_has_privilege()) {
            return 0;
        }
        data->block = 1;
        //pr_debug("Block hard link called from %d\n", current->pid);
    }
    return 0;
}

static struct kretprobe krp_path_link;
static int hook_krp_path_link_state = 0; // 1: hooked, 0: not hooked

static int register_kretprobe_path_link(void) {
    struct kretprobe *krp = &krp_path_link;
    memset(krp, 0, sizeof(struct kretprobe)); // it's necessary

    krp->kp.symbol_name = "security_path_link";
    krp->handler = krp_do_block_ret_handler;
    krp->entry_handler = krp_path_link_entry_handler;
    krp->data_size = sizeof(struct krp_common_data);
    return do_register_kretprobe(krp, &hook_krp_path_link_state);
}

static void unregister_kretprobe_path_link(void) {
    do_unregister_kretprobe(&krp_path_link, &hook_krp_path_link_state);
}

/// int security_inode_unlink(struct inode *dir, struct dentry *dentry);
///
/// @dir: parent directory
/// @dentry: file

static int krp_unlink_entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs) {
    struct krp_common_data *data = (struct krp_common_data *)ri->data;
    struct dentry *dentry = (struct dentry *)p_regs_get_arg2(regs); // regs->si

    data->block = 0;
    if (dentry && check_dentry_is_protected(dentry)) {
        if (check_current_has_privilege()) {
            return 0;
        }
        data->block = 1;
        //pr_debug("Block rmdir/unlink/rename called from %d\n", current->pid);
    }
    return 0;
}

static struct kretprobe krp_unlink;
static int hook_krp_unlink_state = 0; // 1: hooked, 0: not hooked

static int register_kretprobe_inode_unlink(void) {
    struct kretprobe *krp = &krp_unlink;
    memset(krp, 0, sizeof(struct kretprobe)); // it's necessary

    krp->kp.symbol_name = "security_inode_unlink";
    krp->handler = krp_do_block_ret_handler;
    krp->entry_handler = krp_unlink_entry_handler;
    krp->data_size = sizeof(struct krp_common_data);
    return do_register_kretprobe(krp, &hook_krp_unlink_state);
}

static void unregister_kretprobe_inode_unlink(void) {
    do_unregister_kretprobe(&krp_unlink, &hook_krp_unlink_state);
}

/// int security_inode_rmdir(struct inode *dir, struct dentry *dentry);
///
/// @dir: parent directory
/// @dentry: directory to be removed

static struct kretprobe krp_rmdir;
static int hook_krp_rmdir_state = 0;

static int register_kretprobe_inode_rmdir(void) {
    struct kretprobe *krp = &krp_rmdir;
    memset(krp, 0, sizeof(struct kretprobe));

    krp->kp.symbol_name = "security_inode_rmdir";
    krp->handler = krp_do_block_ret_handler;
    krp->entry_handler = krp_unlink_entry_handler; // reused here
    krp->data_size = sizeof(struct krp_common_data);
    return do_register_kretprobe(krp, &hook_krp_rmdir_state);
}

static void unregister_kretprobe_inode_rmdir(void) {
    do_unregister_kretprobe(&krp_rmdir, &hook_krp_rmdir_state);
}

/// int security_inode_rename(struct inode *old_dir, struct dentry *old_dentry,
///                           struct inode *new_dir, struct dentry *new_dentry,
///                           unsigned int flags);
///
/// @old_dir: parent directory of the old file
/// @old_dentry: the old file
/// @new_dir: parent directory of the new file
/// @new_dentry: the new file
/// @flags: flags

static struct kretprobe krp_rename;
static int hook_krp_rename_state = 0;

static int register_kretprobe_inode_rename(void) {
    struct kretprobe *krp = &krp_rename;
    memset(krp, 0, sizeof(struct kretprobe));

    krp->kp.symbol_name = "security_inode_rename";
    krp->handler = krp_do_block_ret_handler;
    krp->entry_handler = krp_unlink_entry_handler; // reused here
    krp->data_size = sizeof(struct krp_common_data);
    return do_register_kretprobe(krp, &hook_krp_rename_state);
}

static void unregister_kretprobe_inode_rename(void) {
    do_unregister_kretprobe(&krp_rename, &hook_krp_rename_state);
}

/// int security_file_open(struct file *file);

static int krp_open_entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs) {
    struct krp_common_data *data = (struct krp_common_data *)ri->data;
    const struct file *file = (const struct file *)p_regs_get_arg1(regs); // regs->di

    data->block = 0;
    if (file && file->f_path.dentry && (file->f_mode & FMODE_WRITE)) {
        if (check_dentry_is_protected(file->f_path.dentry)) {
            if (check_current_has_privilege()) {
                return 0;
            }
            data->block = 1;
            //pr_debug("Block file open called from %d\n", current->pid);
        }
    }
    return 0;
}

static struct kretprobe krp_open;
static int hook_krp_open_state = 0;

static int register_kretprobe_file_open(void) {
    struct kretprobe *krp = &krp_open;
    memset(krp, 0, sizeof(struct kretprobe)); // it's necessary

    krp->kp.symbol_name = "security_file_open";
    krp->handler = krp_do_block_ret_handler;
    krp->entry_handler = krp_open_entry_handler;
    krp->data_size = sizeof(struct krp_common_data);
    return do_register_kretprobe(krp, &hook_krp_open_state);
}

static void unregister_kretprobe_file_open(void) {
    do_unregister_kretprobe(&krp_open, &hook_krp_open_state);
}

/// Enable or disable self-protection

static int smith_protect_enable(void) {
    int ret;
    if ((ret = register_kretprobe_task_kill()) < 0) {
        pr_err("[ELKEID] Failed to register kretprobe for kill: %d\n", ret);
        return ret;
    }
    if ((ret = register_kretprobe_ptrace()) < 0) {
        pr_err("[ELKEID] Failed to register kretprobe for ptrace: %d\n", ret);
        return ret;
    }
    if ((ret = register_kretprobe_path_link()) < 0) {
        pr_err("[ELKEID] Failed to register kretprobe for link: %d\n", ret);
        return ret;
    }
    if ((ret = register_kretprobe_inode_unlink()) < 0) {
        pr_err("[ELKEID] Failed to register kretprobe for unlink: %d\n", ret);
        return ret;
    }
    if ((ret = register_kretprobe_inode_rmdir()) < 0) {
        pr_err("[ELKEID] Failed to register kretprobe for rmdir: %d\n", ret);
        return ret;
    }
    if ((ret = register_kretprobe_inode_rename()) < 0) {
        pr_err("[ELKEID] Failed to register kretprobe for rename: %d\n", ret);
        return ret;
    }
    if ((ret = register_kretprobe_file_open()) < 0) {
        pr_err("[ELKEID] Failed to register kretprobe for open: %d\n", ret);
        return ret;
    }

    pr_info("[ELKEID] register_kretprobe: kill: %d, ptrace: %d, link: %d, unlink: %d, rmdir: %d, rename: %d, open: %d\n",
            hook_krp_kill_state, hook_krp_ptrace_state, hook_krp_path_link_state, hook_krp_unlink_state,
            hook_krp_rmdir_state, hook_krp_rename_state, hook_krp_open_state);
    return 0;
}

static void smith_protect_disable(void) {
    unregister_kretprobe_task_kill();
    unregister_kretprobe_ptrace();
    unregister_kretprobe_path_link();
    unregister_kretprobe_inode_unlink();
    unregister_kretprobe_inode_rmdir();
    unregister_kretprobe_inode_rename();
    unregister_kretprobe_file_open();

    pr_info("[ELKEID] unregister_kretprobe: kill: %d, ptrace: %d, link: %d, unlink: %d, rmdir: %d, rename: %d, open: %d\n",
            hook_krp_kill_state, hook_krp_ptrace_state, hook_krp_path_link_state, hook_krp_unlink_state,
            hook_krp_rmdir_state, hook_krp_rename_state, hook_krp_open_state);
}

void smith_protect_init(void) {
    int ret;
    if ((ret = init_protected_dirs()) < 0) {
        pr_err("[ELKEID] Failed to init protected dirs: %d\n", ret);
    }
}

void smith_protect_destroy(void) {
    mutex_lock(&g_protector_lock);
    if (g_protector_status) {
        smith_protect_disable();
        g_protector_status = 0;
    }
    mutex_unlock(&g_protector_lock);
    destroy_protected_dirs();
}
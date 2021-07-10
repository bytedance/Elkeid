from rasp.common import already_hook_check, set_hook_flag, load_hook_config, set_action, clear_action
from rasp.common import debug


def hook():
    if already_hook_check():
        return False
    hook_list = load_hook_config()
    set_action("HOOK")
    for hook_type in hook_list:
        debug("set hook from hook_list: {}".format(hook_type))
        try:
            exec("from rasp.py3.pyr import hook_{}".format(hook_type))
        except ImportError as e:
            debug("import hook failed: {} {}".format(hook_type, e))
        except Exception as e:
            debug("set hook failed: {} {}".format(hook_type, e))
    clear_action()
    set_hook_flag(True)


def free():
    if not already_hook_check():
        return False
    hook_list = load_hook_config()
    set_action("FREE")
    for hook_type in hook_list:
        exec("from rasp.py3.pyr import hook_{}".format(hook_type))
    clear_action()
    set_hook_flag(False)

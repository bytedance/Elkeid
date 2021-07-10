# -*- coding: UTF-8 -*-
import sys
import traceback
from rasp.common.var import RASP, RASP_HOOK_CONFIG

import gc


def debug(s, trace=False):
    if not RASP.get("DEBUG"):
        return
    print(s)
    if trace:
        traceback.print_exc()
    sys.stdout.flush()


def hook():
    try:
        if sys.version_info >= (3, 0):
            from rasp.py3 import hook as real_hook
        elif sys.version_info <= (3, 0):
            from rasp.py2 import hook as real_hook
        else:
            raise NotImplementedError()
    except ImportError as e:
        debug("RASP import failed: {}".format(e), True)
        real_hook = None
    except NotImplementedError as _:
        debug(
            "RASP not compatible with version: {}".format(
                sys.version_info), True)
        real_hook = None

    try:
        debug("hook start")
        if not real_hook:
            return
        # set attach flag
        if not check_attach_flag():
            set_attach_flag(True)
        # start hook
        real_hook()
        debug("hook end")
    except Exception as hook_failed:
        debug("hook_failed".format(hook_failed), trace=True)


def free():
    try:
        if sys.version_info >= (3, 0):
            from rasp.py3 import free as real_free
        elif sys.version_info <= (3, 0):
            from rasp.py2 import free as real_free
        else:
            raise NotImplementedError()
    except ImportError as e:
        debug("RASP import failed: {}".format(e), True)
        real_free = None
    except NotImplementedError as _:
        debug(
            "RASP not compatible with version: {}".format(
                sys.version_info), True)
        real_free = None

    try:
        if not check_attach_flag():
            return
        debug("free start")
        if not real_free:
            return
        real_free()
        debug("free end")
    except Exception as free_failed:
        debug("free failed: {}".format(free_failed), trace=True)


class RASPException(Exception):
    pass


def check_attach_flag():
    # create namespace RASP in globals()
    if isinstance(RASP.get("ATTACH_FLAG", None), type(None)):
        return False
    return True


def set_attach_flag(flag):
    RASP["ATTACH_FLAG"] = flag


def already_hook_check():
    """
    :rtype: bool
    :return:
    """
    # print(globals().get("RASP", False))
    return RASP.get("HOOK_FLAG", False)


def set_hook_flag(flag):
    """

    :param flag:
    :type flag: bool
    :return:
    :rtype: bool
    """
    RASP["HOOK_FLAG"] = flag


def set_action(action):
    RASP["ACTION"] = action


def clear_action():
    RASP["ACTION"] = None


def load_hook_config():
    """

    :return:
    :rtype: list
    """
    # TODO: @Gaba load file from disk
    hook_list = []
    for hook_point, hook_point_config in RASP_HOOK_CONFIG.items():
        hook_point_type = hook_point_config.get("type", "BOTH")
        IAST_SWITCH = RASP.get("IAST", False)
        if hook_point_type == "BOTH":
            hook_list.append(hook_point)
        elif hook_point_type == "IAST":
            if IAST_SWITCH:
                hook_list.append(hook_point)
    return hook_list


def search_object(tp):
    # WARN this is kind of GC hacking for traverse all object in interpreter
    # the code behind gc.get_object got various implication
    # for the current newest CPythonversion:
    # ![](https://github.com/python/cpython/blob/master/Modules/gcmodule.c)
    """
    ...
    PyThreadState *tstate = _PyThreadState_GET();
    ...
    GCState *gcstate = &tstate->interp->gc;
    ...
    GEN_HEAD(gcstate, i)
    """
    # for CPython 3.8
    """
    ...
    struct _gc_runtime_state *state = &_PyRuntime.gc;
    ...
    GEN_HEAD(state, generation)
    """

    for obj in gc.get_objects():
        if isinstance(obj, (tp,)):
            yield obj

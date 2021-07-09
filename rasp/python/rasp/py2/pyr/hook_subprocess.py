# -*- coding: UTF-8 -*-
import traceback
import sys
import subprocess
try:
    from rasp.common.detect.utils.logger import Log
except ImportError:
    pass

from rasp.common.common_hook import InstallFcnHook
from rasp.common import RASP, RASPException, search_object
from rasp.common.report import message


class _CustomGetAttribute:
    def __getattribute__(self, name):
        if name == "_execute_child":
            return object.__getattribute__(self, "_hooked_execute_child")
        return object.__getattribute__(self, name)


class SubprocessMeta(type):
    def __new__(meta, name, bases, dct):
        bases = (_CustomGetAttribute,) + bases + \
                (sys.modules["subprocess"].Popen,)
        return type.__new__(meta, name, bases, dct)


class HookedSubprocess:
    __metaclass__ = SubprocessMeta

    def _hooked_execute_child(self, *args, **kwargs):
        hook_message = message.make_rasp_message(
            "subprocess", "popen", args, kwargs)
        message.handle_message(hook_message)
        return object.__getattribute__(self, "_execute_child")(*args, **kwargs)


# class _HookedExecuteChild(InstallFcnHook):
#     def pre_hook(self, *args, **kwargs):
#         hook_message = message.make_rasp_message("subprocess", "popen", args, kwargs)
#         message.handle_message(hook_message)


action = RASP["ACTION"]
if action == "HOOK":
    # for popen_object in search_object(subprocess.Popen):
    #     popen_object._execute_child = _HookedExecuteChild(popen_object._execute_child)
    subprocess_module = sys.modules.get("subprocess", None)
    if subprocess_module:
        setattr(subprocess_module, "origin_popen", subprocess_module.Popen)
        subprocess_module.Popen = HookedSubprocess

elif action == "FREE":
    # for popen_object in search_object(subprocess.Popen):
    #     popen_object._execute_child = popen_object._execute_child.__origin__()
    subprocess_module = sys.modules.get("subprocess", None)
    if subprocess_module:
        subprocess_module.Popen = getattr(subprocess_module, "origin_popen")

else:
    raise RASPException("wrong action")

# -*- coding: UTF-8 -*-

import __builtin__
from rasp.common.common_hook import InstallFcnHookExportLocal
from rasp.common import RASP, RASPException
from rasp.common.report import message
try:
    from rasp.common.detect.normal_check import Check
except ImportError:
    pass

class BuiltinsHook(InstallFcnHookExportLocal):
    def post_hook(self, ret_val, *args, **kwargs):
        if self.ret_hook:
            hook_message = message.make_rasp_message(
                "builtins", self._fcn.__name__, args, kwargs, ret_val)
            message.handle_message(hook_message)

    def pre_hook(self, *args, **kwargs):
        if not self.ret_hook:
            hook_message = message.make_rasp_message(
                "builtins", self._fcn.__name__, args, kwargs)
            message.handle_message(hook_message)
        if not self.IAST:
            return
        Check(args, 'code_exc').detect()


action = RASP["ACTION"]
if action == "HOOK":
    __builtin__.eval = BuiltinsHook(__builtin__.eval)
    # __builtin__.exec = BuiltinsHook(__builtin__.exec)
    __builtin__.compile = BuiltinsHook(__builtin__.compile)

elif action == "FREE":
    __builtin__.eval = __builtin__.eval.__origin__()
    # __builtin__.exec = __builtin__.exec.__origin__()
    __builtin__.compile = __builtin__.compile.__origin__()

else:
    raise RASPException("wrong action")

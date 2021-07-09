# -*- coding: UTF-8 -*-
import __builtin__
from rasp.common.common_hook import InstallFcnHook
from rasp.common import RASP, RASPException
from rasp.common.report import message
try:
    from rasp.common.detect.normal_check import Check
except ImportError:
    pass


class BuiltinsOpenHook(InstallFcnHook):
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
        Check(args, 'readFile').detect()


action = RASP["ACTION"]
if action == "HOOK":
    __builtin__.open = BuiltinsOpenHook(__builtin__.open)

elif action == "FREE":
    __builtin__.open = __builtin__.eval.__origin__()

else:
    raise RASPException("wrong action")

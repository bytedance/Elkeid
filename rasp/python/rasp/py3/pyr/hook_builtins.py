# -*- coding: UTF-8 -*-
import builtins
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
    builtins.eval = BuiltinsHook(builtins.eval)
    builtins.exec = BuiltinsHook(builtins.exec)
    builtins.compile = BuiltinsHook(builtins.compile)

elif action == "FREE":
    builtins.eval = builtins.eval.__origin__()
    builtins.exec = builtins.exec.__origin__()
    builtins.compile = builtins.compile.__origin__()

else:
    raise RASPException("wrong action")

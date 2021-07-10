# -*- coding: UTF-8 -*-
import os
from rasp.common.common_hook import InstallFcnHook
from rasp.common import RASP, RASPException
# RASP
from rasp.common.report import message
# IAST
try:
    from rasp.common.detect.normal_check import Check
    from rasp.common.detect.utils.track import Track
except ImportError:
    pass


class OSHook(InstallFcnHook):
    def post_hook(self, ret_val, *args, **kwargs):
        if self.ret_hook:
            hook_message = message.make_rasp_message(
                "os", self._fcn.__name__, args, kwargs, ret_val)
            message.handle_message(hook_message)
        # print("hook message: {}".format(hook_message))

    def pre_hook(self, *args, **kwargs):
        if not self.ret_hook:
            hook_message = message.make_rasp_message(
                "os", self._fcn.__name__, args, kwargs)
            message.handle_message(hook_message)
        if not self.IAST:
            return
        if self._fcn.__name__ == 'setdefault' or self._fcn.__name__ == 'items':
            pwd_path = os.environ.get('PWD')
            django_setting = os.environ.get('DJANGO_SETTINGS_MODULE')
            if django_setting:
                Track(args).set_django_setting(
                    django_setting, pwd_path)
        Check(args, 'command').detect()


action = RASP["ACTION"]
if action == "HOOK":
    os.system = OSHook(os.system)
    os.popen = OSHook(os.popen)
    os.execl = OSHook(os.execl)
    os.execle = OSHook(os.execle)
    os.execlp = OSHook(os.execlp)
    os.execlpe = OSHook(os.execlpe)
    os.execv = OSHook(os.execv)
    os.execve = OSHook(os.execve)
    os.execvp = OSHook(os.execvp)
    os.execvpe = OSHook(os.execvpe)
    os.spawnl = OSHook(os.spawnl)
    os.spawnle = OSHook(os.spawnle)
    os.spawnlp = OSHook(os.spawnlp)
    os.spawnlpe = OSHook(os.spawnlpe)
    os.spawnv = OSHook(os.spawnv)
    os.spawnve = OSHook(os.spawnve)
    os.spawnvp = OSHook(os.spawnvp)
    os.spawnvpe = OSHook(os.spawnvpe)
    os.environ.setdefault = OSHook(os.environ.setdefault)
    os.environ.items = OSHook(os.environ.items)
elif action == "FREE":
    os.system = os.system.__origin__()
    os.popen = os.popen.__origin__()
    os.execl = os.execl.__origin__()
    os.execle = os.execle.__origin__()
    os.execlp = os.execlp.__origin__()
    os.execlpe = os.execlpe.__origin__()
    os.execv = os.execv.__origin__()
    os.execve = os.execve.__origin__()
    os.execvp = os.execvp.__origin__()
    os.execvpe = os.execvpe.__origin__()
    os.spawnl = os.spawnl.__origin__()
    os.spawnle = os.spawnle.__origin__()
    os.spawnlp = os.spawnlp.__origin__()
    os.spawnlpe = os.spawnlpe.__origin__()
    os.spawnv = os.spawnv.__origin__()
    os.spawnve = os.spawnve.__origin__()
    os.spawnvp = os.spawnvp.__origin__()
    os.spawnvpe = os.spawnvpe.__origin__()
    os.environ.setdefault = os.environ.setdefault.__origin__()
    os.environ.items = os.environ.items.__origin__()

else:
    raise RASPException()

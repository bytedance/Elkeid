import inspect

from rasp.common import debug
from rasp.common.var import RASP


class InstallFcnHook(object):
    """
    replace function with this class:
    ```
    >>> import os
    >>> os.system
    <function posix.system(command)>
    >>> os.system = InstallFncHook(os.system)
    >>> os.system
    <rasp.common.common_hook.InstallFcnHook at 0x7fc5d804b0b8>
    ```
    """

    def __init__(self, fcn, ret_hook=False):
        self.debug = RASP["DEBUG"]
        if self.debug:
            debug("install hook point: {} ret hook: {}".format(fcn, ret_hook))
        self.IAST = RASP["IAST"]
        self.ret_hook = ret_hook
        self._fcn = fcn

    def __origin__(self):
        return self._fcn

    def __call__(self, *args, **kwargs):
        _hook_args = args
        _hook_kwargs = kwargs
        # pre hook
        self.pre_hook(*args, **kwargs)
        # call origin function
        ret_val = self._fcn(*_hook_args, **_hook_kwargs)
        # post hook
        self.post_hook(ret_val, *args, **kwargs)
        return ret_val

    def pre_hook(self, *args, **kwargs):
        pass

    def post_hook(self, ret_val, *args, **kwargs):
        pass

class InstallFcnHookExportLocal(object):
    """
    replace function with this class:
    ```
    >>> import os
    >>> os.system
    <function posix.system(command)>
    >>> os.system = InstallFncHook(os.system)
    >>> os.system
    <rasp.common.common_hook.InstallFcnHook at 0x7fc5d804b0b8>
    ```
    """

    def __init__(self, fcn, ret_hook=False):
        self.debug = RASP["DEBUG"]
        if self.debug:
            debug("install hook point: {} ret hook: {}".format(fcn, ret_hook))
        self.IAST = RASP["IAST"]
        self.ret_hook = ret_hook
        self._fcn = fcn

    def __origin__(self):
        return self._fcn

    def __call__(self, *args, **kwargs):
        frame = inspect.currentframe()
        try:
            upper_locals = frame.f_back.f_locals
            locals().update(upper_locals)
        finally:
            del frame
        _hook_args = args
        _hook_kwargs = kwargs
        # pre hook
        self.pre_hook(*args, **kwargs)
        # call origin function
        ret_val = self._fcn(*_hook_args, **_hook_kwargs)
        # post hook
        self.post_hook(ret_val, *args, **kwargs)
        return ret_val

    def pre_hook(self, *args, **kwargs):
        pass

    def post_hook(self, ret_val, *args, **kwargs):
        pass

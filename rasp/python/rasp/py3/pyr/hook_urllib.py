try:
    import requests
except ImportError as e:
    raise ImportError(e)

import urllib

from rasp.common.common_hook import InstallFcnHook
from rasp.common import RASP, RASPException
from rasp.common.report import message
try:
    from rasp.common.detect.ssrf_check import check_args, check_kwargs
    from rasp.common.detect.utils.config import DetFeature
except ImportError:
    pass


class UrllibHook(InstallFcnHook):
    def post_hook(self, ret_val, *args, **kwargs):
        if self.ret_hook:
            hook_message = message.make_rasp_message(
                "urllib", self._fcn.__name__, args, kwargs, ret_val)
            message.handle_message(hook_message)

    def pre_hook(self, *args, **kwargs):
        if not self.ret_hook:
            hook_message = message.make_rasp_message(
                "urllib", self._fcn.__name__, args, kwargs)
            message.handle_message(hook_message)
        if not self.IAST:
            return
        features = DetFeature.ssrf_feature
        if args:
            check_args(features, args)
        if kwargs:
            check_kwargs(features, kwargs)


action = RASP["ACTION"]
if action == "HOOK":
    urllib.request.urlopen = UrllibHook(urllib.request.urlopen)
elif action == "FREE":
    urllib.request.urlopen.get = requests.get.__origin__()
else:
    raise RASPException("wrong action")

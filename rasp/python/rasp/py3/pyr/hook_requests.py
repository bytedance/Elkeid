# -*- coding: UTF-8 -*-
from rasp.common import RASP, RASPException

try:
    import requests
except ImportError as e:
    raise RASPException("import requests failed")

from rasp.common.common_hook import InstallFcnHook
# RASP
from rasp.common.report import message
# IAST
try:
    from rasp.common.detect.ssrf_check import check_args, check_kwargs
    from rasp.common.detect.utils.config import DetFeature
except ImportError:
    pass


class RequestsHook(InstallFcnHook):
    def post_hook(self, ret_val, *args, **kwargs):
        if self.ret_hook:
            hook_message = message.make_rasp_message(
                "requests", self._fcn.__name__, args, kwargs, ret_val)
            message.handle_message(hook_message)

    def pre_hook(self, *args, **kwargs):
        if not self.ret_hook:
            hook_message = message.make_rasp_message(
                "requests", self._fcn.__name__, args, kwargs)
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
    requests.get = RequestsHook(requests.get)
    requests.post = RequestsHook(requests.post)
    requests.put = RequestsHook(requests.put)
    requests.head = RequestsHook(requests.head)
    requests.delete = RequestsHook(requests.delete)
    requests.options = RequestsHook(requests.options)
    requests.request = RequestsHook(requests.request)
    requests.patch = RequestsHook(requests.patch)

elif action == "FREE":
    requests.get = requests.get.__origin__()
    requests.post = requests.post.__origin__()
    requests.put = requests.put.__origin__()
    requests.head = requests.head.__origin__()
    requests.delete = requests.delete.__origin__()
    requests.options = requests.options.__origin__()
    requests.request = requests.request.__origin__()
    requests.patch = requests.patch.__origin__()
else:
    raise RASPException("wrong action")

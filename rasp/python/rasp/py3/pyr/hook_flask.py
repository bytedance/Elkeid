# -*- coding: UTF-8 -*-
import traceback
try:
    from rasp.common.detect.utils.logger import Log
except ImportError:
    pass

try:
    import flask
    from flask import _request_ctx_stack
except ImportError as e:
    Log('error').warning(
        "File:{0} \r\n  Error: {1}    \r\n track:{2} ".format(
            __file__, e, traceback.format_exc()))
    raise Exception("")
try:
    from rasp.common.detect.utils.request_context import ReqContext
except ImportError:
    pass

from rasp.common.common_hook import InstallFcnHook
from rasp.common import RASP, RASPException, search_object
from rasp.common.report import message


class DispatchRequestHook(InstallFcnHook):
    def post_hook(self, ret_val, *args, **kwargs):
        if self.ret_hook:
            hook_message = message.make_rasp_message(
                "flask", self._fcn.__name__, args, kwargs, ret_val)
            message.handle_message(hook_message)

    def pre_hook(self, *args, **kwargs):
        if not self.ret_hook:
            hook_message = message.make_rasp_message(
                "flask", self._fcn.__name__, args, kwargs)
            message.handle_message(hook_message)
        if not self.IAST:
            return
        self.exception = (
            AttributeError,
            ImportError,
            NameError,
            UnboundLocalError,
            EnvironmentError,
            IOError,
            RuntimeError)
        try:
            ReqContext.set_request(_request_ctx_stack.top.request)
        except self.exception as e:
            Log('error').warning(
                "File:{0} \r\n  Error: {1}    \r\n track:{2} ".format(
                    __file__, e, traceback.format_exc()))


action = RASP["ACTION"]
if action == "HOOK":
    for flask_object in search_object(flask.Flask):
        flask_object.dispatch_request = DispatchRequestHook(
            flask_object.dispatch_request)
elif action == "FREE":
    for flask_object in search_object(flask.Flask):
        flask_object.dispatch_request = flask_object.dispatch_request.__origin__()
else:
    raise RASPException("wrong action")

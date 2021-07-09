# -*- coding: UTF-8 -*-
import traceback
from rasp.py2.utils.logger import Log

try:
    from django.utils.deprecation import MiddlewareMixin
except Exception as e:
    Log('error').warning(
        "File:{0} \r\n  Error: {1}    \r\n track:{2} ".format(
            __file__, e, traceback.format_exc()))
from rasp.py2.utils.RequestContext import ReqContext


class HookRequest(MiddlewareMixin):

    @staticmethod
    def process_request(request):
        ReqContext.set_request(request)

# -*- coding: UTF-8 -*-
try:
    from django.utils.deprecation import MiddlewareMixin
except ImportError as e:
    raise ImportError(e)

from rasp.common.detect.utils.request_context import ReqContext


class HookRequest(MiddlewareMixin):

    @staticmethod
    def process_request(request):
        ReqContext.set_request(request)

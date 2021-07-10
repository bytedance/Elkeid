# -*- coding: UTF-8 -*-
try:
    from django.utils.deprecation import MiddlewareMixin
except ImportError as e:
    raise ImportError(e)

try:
    from rasp.common.detect.utils.request_context import ReqContext
excpet ImportError:
    pass


class HookRequest(MiddlewareMixin):

    @staticmethod
    def process_request(request):
        ReqContext.set_request(request)

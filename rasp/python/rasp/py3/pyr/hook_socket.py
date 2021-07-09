# -*- coding: UTF-8 -*-
import sys
from rasp.common.common_hook import InstallFcnHook
from rasp.common import RASP

# IAST
from rasp.common.detect.utils.config import DetFeature
from rasp.common.detect.sqli_check import check_sqli
from rasp.common.detect.ssrf_check import ssrf_socket_check


class _CustomGetAttribute:
    def __getattribute__(self, name):
        if name == "sendall":
            return object.__getattribute__(self, "_hooked_sendall")
        return object.__getattribute__(self, name)


class SocketMeta(type):
    def __new__(meta, name, bases, dct):
        bases = (_CustomGetAttribute,) + bases + \
                (sys.modules["socket"].socket,)
        return type.__new__(meta, name, bases, dct)


class HookedSocket(metaclass=SocketMeta):
    def _hooked_sendall(self, *args, **kwargs):
        for modify_param in args:
            socket_size = len(modify_param)
            # python2的requests&urllib2不会分段传输，但是鉴于_check_ssrf速度较快，因此SOCKET_SIZE设得较大
            if socket_size < DetFeature.MAX_CHECK_SSRF_SOCKET_SIZE:
                ssrf_socket_check(modify_param)
            # SQL语句的检查速度较慢，因此SOCKET_SIZE设得较小
            if socket_size < DetFeature.MAX_CHECK_SQL_SOCKET_SIZE:
                check_sqli(modify_param)
        return object.__getattribute__(self, "sendall")(*args, **kwargs)


class SendAllHook(InstallFcnHook):
    def pre_hook(self, *args, **kwargs):
        if not self.IAST:
            return
        for modify_param in args:
            socket_size = len(modify_param)
            # python2的requests&urllib2不会分段传输，但是鉴于_check_ssrf速度较快，因此SOCKET_SIZE设得较大
            if socket_size < DetFeature.MAX_CHECK_SSRF_SOCKET_SIZE:
                ssrf_socket_check(modify_param)
            # SQL语句的检查速度较慢，因此SOCKET_SIZE设得较小
            if socket_size < DetFeature.MAX_CHECK_SQL_SOCKET_SIZE:
                check_sqli(modify_param)


action = RASP["ACTION"]
if action == "HOOK":
    socket_module = sys.modules.get("socket", None)
    if socket_module:
        setattr(socket_module, "origin_socket", socket_module.socket)
        socket_module.socket = HookedSocket

elif action == "FREE":
    socket_module = sys.modules.get("socket", None)
    if socket_module:
        socket_module.socket = getattr(socket_module, "origin_socket")

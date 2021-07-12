# -*- coding: UTF-8 -*-
import sys

from rasp.common import RASP
# IAST
try:
    from rasp.common.detect.utils.config import DetFeature
    from rasp.common.detect.sqli_check import check_sqli
    from rasp.common.detect.ssrf_check import ssrf_socket_check
except ImportError:
    pass


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


class HookedSocket():
    __metaclass__ = SocketMeta

    def _hooked_sendall(self, *args, **kwargs):
        if not self.IAST:
            return object.__getattribute__(self, 'sendall')(*args, **kwargs)
        # custom code
        return object.__getattribute__(self, 'sendall')(*args, **kwargs)


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

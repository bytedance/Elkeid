import json
import platform

from rasp.common import var, hook, free
from rasp.common import RASPException, debug

from ctypes import CDLL, create_string_buffer
import pkg_resources


def parse_recv_message(recv_message):
    recv_data = recv_message.get("data", None)
    if not recv_data:
        return
    config = recv_data.get("config", None)
    action = recv_data.get("action", None)
    if config:
        update_config = json.loads(config)
        free()
        var.RASP_HOOK_CONFIG = update_config
        hook()
    if action and action in [1, 2]:
        if action == 0:
            # free
            free()
        elif action == 1:
            # hook
            hook()


class RASPClient(object):
    def __init__(self):
        """

        :param python_version: python verion (3,8)
        :type python_version: tuple
        """
        self.python_version = platform.python_version()
        try:
            # 1. load client so
            if not pkg_resources.resource_exists(
                    "rasp", "resource/libsmith_client.so"):
                raise Exception("can not find libsmith_client.so")
            lib_path = pkg_resources.resource_filename(
                "rasp", "resource/libsmith_client.so")
            self.client = CDLL(lib_path)
        except OSError as e:
            raise RASPException(e)
        except Exception as e:
            raise RASPException(e)

        # send count
        self.send_count = 0

    def setup(self):
        try:
            # 2. try connect to local sock
            ret_val = self.client.init(self.python_version.encode("utf-8"))
            if ret_val != 0:
                raise Exception("client init failed: {}".format(ret_val))
        except Exception as e:
            raise RASPException(e)

    def send_py3(self, message):
        """

        :param message:
        :type message: bytes
        """
        try:
            ret_val = self.client.post_message(message)
            if ret_val != 0:
                raise Exception(
                    "client post message failed: {}".format(ret_val))
        except Exception as e:
            raise RASPException(e)
        self.send_count += 1
        if self.send_count >= 100:
            self.recv()
            self.send_count = 0

    def send_py2(self, message):
        """

        :param message:
        :type message: str
        """
        try:
            ret_val = self.client.post_message(message)
            if ret_val != 0:
                raise Exception(
                    "client post message failed: {}".format(ret_val))
        except Exception as e:
            raise RASPException(e)
        self.send_count += 1
        if self.send_count >= 100:
            self.recv()
            self.send_count = 0

    def recv(self):
        try:
            buffer = create_string_buffer(10240)
            ret_val = self.client.pop_message(buffer)
            if ret_val != 0:
                raise Exception(
                    "client pop message failed: {}".format(ret_val))
            if buffer.raw[0] == 0:
                return
            debug(buffer.raw)
            recv_message = json.loads(buffer.raw.decode("utf-8"))
            parse_recv_message(recv_message)
        except Exception as e:
            raise RASPException(e)

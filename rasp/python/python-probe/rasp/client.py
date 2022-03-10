import errno
import json
import os
import platform
import select
import socket
import struct
import sys
import threading
import time

if sys.version_info >= (3, 0):
    import queue
else:
    import Queue as queue

from rasp.log import logger

_HEADER_SIZE = 4
_RECONNECT_DELAY = 60
_DEFAULT_QUEUE_SIZE = 1000
_DEFAULT_EPOLL_TIMEOUT = 1

_SOCKET_PATH = '/var/run/smith_agent.sock'

EXIT_OPERATE = 0
HEARTBEAT_OPERATE = 1
TRACE_OPERATE = 2
CONFIG_OPERATE = 3
CONTROL_OPERATE = 4
DETECT_OPERATE = 5
FILTER_OPERATE = 6
BLOCK_OPERATE = 7
LIMIT_OPERATE = 8


class SmithClient(object):
    def __init__(self, notify):
        self._notify = notify
        self._pid = os.getpid()
        self._version = platform.python_version()

        self._queue = queue.Queue(_DEFAULT_QUEUE_SIZE)
        self._thread = threading.Thread(target=self._loop)

    def reset(self):
        self._pid = os.getpid()

        self._queue = queue.Queue(_DEFAULT_QUEUE_SIZE)
        self._thread = threading.Thread(target=self._loop)

    def start(self):
        self._thread.daemon = True
        self._thread.start()

    def _loop(self):
        while True:
            try:
                s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                s.connect(_SOCKET_PATH)
                s.setblocking(False)

                epoll = select.epoll()
                epoll.register(s.fileno(), select.EPOLLIN)

                cache = b''
                remain = b''
                timeout = _DEFAULT_EPOLL_TIMEOUT

                while True:
                    try:
                        events = epoll.poll(timeout)

                        if events:
                            fd, event = events[0]

                            if event & select.EPOLLIN:
                                buffer = s.recv(1024)

                                if not buffer:
                                    s.close()
                                    break

                                cache += buffer

                                while True:
                                    if len(cache) < _HEADER_SIZE:
                                        break

                                    length = struct.Struct(">i").unpack(cache[:_HEADER_SIZE])[0]

                                    if len(cache) < _HEADER_SIZE + length:
                                        break

                                    message = cache[_HEADER_SIZE:_HEADER_SIZE + length]
                                    self._notify(json.loads(message.decode('utf8')))

                                    cache = cache[_HEADER_SIZE + length:]

                            if event & select.EPOLLOUT:
                                while True:
                                    try:
                                        buffer = remain if remain else self._queue.get_nowait()

                                        try:
                                            n = s.send(buffer)

                                            if n != len(buffer):
                                                remain = buffer[n:]
                                                break

                                        except socket.error as e:
                                            if e.errno != errno.EAGAIN:
                                                raise

                                            remain = buffer
                                            break

                                        remain = b''

                                    except queue.Empty:
                                        timeout = _DEFAULT_EPOLL_TIMEOUT
                                        epoll.modify(s.fileno(), select.EPOLLIN)
                                        break

                        if timeout != -1 and not self._queue.empty():
                            timeout = -1
                            epoll.modify(s.fileno(), select.EPOLLIN | select.EPOLLOUT)

                    except (OSError, IOError) as e:
                        if e.errno != errno.EINTR:
                            raise

                        continue

                epoll.close()

            except socket.error as e:
                logger.error("socket error: %s", e)

            time.sleep(_RECONNECT_DELAY)

    def post_message(self, operate, data):
        message = {
            'pid': self._pid,
            'runtime': 'CPython',
            'runtime_version': self._version,
            'time': int(time.time()),
            'message_type': operate,
            'probe_version': '1.0.0',
            'data': data
        }

        payload = json.dumps(message)
        buffer = struct.Struct(">i").pack(len(payload)) + payload.encode('utf8')

        try:
            self._queue.put_nowait(buffer)
        except queue.Full:
            pass

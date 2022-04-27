import inspect
import os
import re
import sys
import traceback

from rasp.client import SmithClient, TRACE_OPERATE, HEARTBEAT_OPERATE, DETECT_OPERATE, FILTER_OPERATE, BLOCK_OPERATE
from rasp.log import logger

_blocks = {}
_filters = {}


def _on_message(message):
    logger.info("message %s", message)

    message_type = message.get('message_type', 0)
    data = message.get('data', {})

    if message_type == HEARTBEAT_OPERATE:
        logger.info("heartbeat message")
    elif message_type == DETECT_OPERATE:
        logger.info("detect message")
    elif message_type == FILTER_OPERATE:
        logger.info("filter message")

        _filters.clear()

        for i in data.get('filters', []):
            _filters[(i['class_id'], i['method_id'])] = i

    elif message_type == BLOCK_OPERATE:
        logger.info("block message")

        _blocks.clear()

        for i in data.get('blocks', []):
            _blocks[(i['class_id'], i['method_id'])] = i


_client = SmithClient(_on_message)
_client.start()


def smith_hook(func, class_id, method_id, constructor=False, can_block=False, check_recursion=False):
    def smith_wrapper(*args, **kwargs):
        if check_recursion:
            current = inspect.currentframe().f_back

            while current:
                if current.f_code.co_name == smith_wrapper.__name__ and current.f_locals.get('func') == func:
                    return func(*args, **kwargs)

                current = current.f_back

        def stringify(obj):
            if sys.version_info < (3, 0):
                if isinstance(obj, str) or isinstance(obj, buffer):
                    return unicode(obj, encoding='utf8', errors='replace')

                return unicode(obj)

            return str(obj)

        smith_trace = {
            'class_id': class_id,
            'method_id': method_id,
            'blocked': False,
            'args': [stringify(i) for i in args[int(constructor):]],
            'kwargs': {key: stringify(value) for key, value in kwargs.items()},
            'stack_trace': [
                '{}({}:{})'.format(frame[2], frame[0], frame[1])
                if isinstance(frame, tuple) else
                '{}({}:{})'.format(frame.name, frame.filename, frame.lineno)
                for frame in reversed(traceback.extract_stack())
            ]
        }

        def pred(rule):
            if rule['index'] >= len(smith_trace['args']):
                return False

            return re.search(rule['regex'], smith_trace['args'][rule['index']]) is not None

        if can_block:
            _block = _blocks.get((class_id, method_id), None)

            if _block and any(pred(rule) for rule in _block['rules']):
                smith_trace['blocked'] = True
                _client.post_message(TRACE_OPERATE, smith_trace)
                raise RuntimeError('API blocked by RASP')

        _filter = _filters.get((class_id, method_id), None)

        if not _filter:
            _client.post_message(TRACE_OPERATE, smith_trace)
            return func(*args, **kwargs)

        include = _filter['include']
        exclude = _filter['exclude']

        if len(include) > 0 and not any(pred(rule) for rule in include):
            return func(*args, **kwargs)

        if len(exclude) > 0 and any(pred(rule) for rule in exclude):
            return func(*args, **kwargs)

        _client.post_message(TRACE_OPERATE, smith_trace)

        return func(*args, **kwargs)

    return smith_wrapper


def _after_fork():
    logger.info("after fork")

    _client.reset()
    _client.start()


if sys.version_info >= (3, 7):
    os.register_at_fork(after_in_child=_after_fork)
else:
    fork = os.fork
    forkpty = os.forkpty

    def fork_wrapper():
        pid = fork()

        if pid == 0:
            _after_fork()

        return pid

    def forkpty_wrapper():
        pid, fd = forkpty()

        if pid == 0:
            _after_fork()

        return pid, fd

    os.fork = fork_wrapper
    os.forkpty = forkpty_wrapper

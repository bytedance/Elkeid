import os
import sys
import time
import json
import traceback
import platform

from rasp.common import RASPException, debug
from rasp.common.var import trans_id

RASP_CLIENT = None
MESSAGE = {
    "pid": os.getpid(),
    "message_type": 2,
    "runtime": "CPython",
    "runtime_version": platform.python_version(),
    "probe_version": "",
}


def make_rasp_message(
        class_id,
        method_id,
        func_args,
        func_kwargs,
        ret_value=None):
    debug((class_id, method_id))
    cid, mid = trans_id(class_id, method_id)
    stack_trace = []
    if sys.version_info >= (3, 0):
        frame_summary_list = traceback.extract_stack()
    elif sys.version_info <= (3, 0):
        frame_summary_list = py2_extract_stack_no_line()
    else:
        raise NotImplementedError()
    for frame_summary in frame_summary_list[:-2]:
        if isinstance(frame_summary, tuple):
            stack_trace.append(json.dumps({
                "filename": frame_summary[0],
                "lineno": frame_summary[1],
                "name": frame_summary[2],
                "line": frame_summary[3]
            }))
        else:
            stack_trace.append(json.dumps({
                "filename": frame_summary.filename,
                "lineno": frame_summary.lineno,
                "name": frame_summary.name,
                "line": frame_summary.line
            }))
    probe_data = {
        "time": time.time(),
        "data": {
            "class_id": cid,
            "method_id": mid,
            "args": func_args_modify(func_args),
            "kwargs": func_kwargs_modify(func_kwargs),
            "stack_trace": stack_trace
        }
    }
    probe_data.update(MESSAGE)
    return probe_data


def func_args_modify(func_args):
    """

    :param func_args:
    :type func_args: list
    :return:
    """
    new_func_args = []
    for arg in func_args:
        try:
            if hasattr(arg, "__str__"):
                new_func_args.append(str(arg))
            elif hasattr(arg, "__repr__"):
                new_func_args.append(repr(arg))
            else:
                new_func_args.append(str(type(arg)))
        except Exception as e:
            debug("modify args failed: {} {}".format(e, arg))
            new_func_args.append("<unknown>")

    return new_func_args


def func_kwargs_modify(func_kwargs):
    new_func_kwargs = []
    for name, value in func_kwargs.items():
        try:
            if hasattr(value, "__str__"):
                new_func_kwargs.append({name: str(value)})
            elif hasattr(value, "__repr__"):
                new_func_kwargs.append({name: repr(value)})
            else:
                new_func_kwargs.append({name: str(type(value))})
        except Exception as e:
            debug("modify kwargs failed: {} {}={}".format(e, name, value))
            new_func_kwargs.append({"name", "<unknown>"})
    return new_func_kwargs


class OmniJSONEncoder(json.JSONEncoder):
    def default(self, o):
        if not isinstance(
            o,
            (dict,
             list,
             tuple,
             str,
             int,
             float,
             bool,
             type(None))
        ):
            return str(o)


def handle_message(message):
    """

    :param message:
    :type message: dict
    :return:
    """
    # debug("MESSAGE: {}".format(message))
    try:
        try:
            message_json = json.dumps(message, default=OmniJSONEncoder)
        except RecursionError as e:
            raise RASPException("dumps message json failed: {}".format(e))
        except TypeError as e:
            raise RASPException("dumps message json failed: {}".format(e))
        # debug("MESSAGE JSON: {}".format(message_json))
        if RASP_CLIENT:
            if sys.version_info >= (3, 0):
                RASP_CLIENT.send_py3(message_json.encode("utf-8"))
            elif sys.version_info <= (3, 0):
                RASP_CLIENT.send_py2(message_json)
            else:
                raise NotImplementedError()
    except Exception as e:
        debug(e)


def py2_extract_stack_no_line(f=None, limit=None):
    """
    """
    """Extract the raw traceback from the current stack frame.

    The return value has the same format as for extract_tb().  The
    optional 'f' and 'limit' arguments have the same meaning as for
    print_stack().  Each item in the list is a quadruple (filename,
    line number, function name, text), and the entries are in order
    from oldest to newest stack frame.
    """
    if f is None:
        try:
            raise ZeroDivisionError
        except ZeroDivisionError:
            f = sys.exc_info()[2].tb_frame.f_back
    if limit is None:
        if hasattr(sys, 'tracebacklimit'):
            limit = sys.tracebacklimit
    list = []
    n = 0
    while f is not None and (limit is None or n < limit):
        lineno = f.f_lineno
        co = f.f_code
        filename = co.co_filename
        name = co.co_name
        line = None
        list.append((filename, lineno, name, line))
        f = f.f_back
        n = n + 1
    list.reverse()
    return list

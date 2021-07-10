import os
import sys

package_path = "/etc/elkeid/plugin/RASP/rasp/python/rasp/__init__.py"


class RASPEntryException(Exception):
    pass


def load_module(module_name, module_path):
    rasp = None
    try:
        if sys.version_info[0] == 3:
            if sys.version_info[1] <= 4:
                from importlib.machinery import SourceFileLoader
                rasp = SourceFileLoader(module_name, module_path).load_module()
            elif sys.version_info[1] >= 5:
                from importlib.machinery import SourceFileLoader
                rasp = SourceFileLoader(module_name, module_path).load_module()
            else:
                # not support version
                pass
        elif sys.version_info[0] == 2:
            if sys.version_info[1] == 7:
                from imp import load_module as lm
                rasp = lm(module_name, None, os.path.dirname(module_path), ('','',5))
            else:
                # not support version
                pass
        else:
            # not support version
            pass
    except BaseException:
        raise RASPEntryException()
    return rasp


def start_rasp(rasp_module, iast=False, debug_switch=False):
    try:
        # setup var
        rasp_module.setup_var(iast=iast, debug_switch=debug_switch)
        # setup client
        rasp_module.setup_client()
        # execute hook
        rasp_module.hook()
    except BaseException:
        raise RASPEntryException()


# entry here
try:
    # 1. load module
    rasp = load_module("rasp", package_path)
    start_rasp(rasp)
except RASPEntryException:
    # ignore every Exception
    pass

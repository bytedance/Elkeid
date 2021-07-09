# -*- coding: UTF-8 -*-
# careful using
RASP_HOOK_CONFIG = {
    "builtins": {"type": "BOTH", "class_id": 0, "method_id": {
        "eval": 0,
        "exec": 1,
        "compile": 2,
        "open": 3,
    }},

    "os": {"type": "BOTH", "class_id": 1, "method_id": {
        "system": 1,
        "popen": 2,
        "execl": 3,
        "execle": 4,
        "execlp": 5,
        "execlpe": 6,
        "execv": 7,
        "execve": 8,
        "execvp": 9,
        "execvpe": 10,
        "spawnl": 11,
        "spawnle": 12,
        "spawnlp": 13,
        "spawnlpe": 14,
        "spawnv": 15,
        "spawnve": 16,
        "spawnvp": 17,
        "spawnvpe": 18,
    }},
    "open": {"type": "BOTH", "class_id": 2, "method_id": {
        "open": 0
    }},
    "requests": {"type": "IAST", "class_id": 3, "method_id": {
        "get": 0,
        "post": 1,
        "put": 2,
        "head": 3,
        "delete": 4,
        "options": 5,
        "request": 6,
        "patch": 7,
    }},
    "socket": {"type": "IAST", "class_id": 4, "method_id": {
        "sendall": 0,
    }},
    "flask": {"type": "IAST", "class_id": 5, "method_id": {
        "dispatch_request": 0,
    }},
    "urllib": {"type": "IAST", "class_id": 6, "method_id": {
        "urlopen": 0,
    }},
    # "subprocess": {"type": "BOTH", "class_id": 7, "method_id": {
    #    "popen": 1
    # }},

}

RASP = {"IAST": False, "DEBUG": False}


def trans_id(class_name, method_name):
    """

    :param class_name:
    :type class_name: str
    :param method_name:
    :type method_name: str
    :return:
    :rtype: tuple[int, int]
    """
    class_dict = RASP_HOOK_CONFIG.get(class_name, None)
    if not class_dict:
        raise KeyError("can not found key: {} in config".format(class_name))
    class_id = class_dict.get("class_id", -1)
    method_dict = class_dict.get("method_id", None)
    if not method_dict:
        raise KeyError("can not found method_id in config")
    method_id = method_dict.get(method_name, -1)
    return class_id, method_id

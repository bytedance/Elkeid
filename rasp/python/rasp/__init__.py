import argparse

import sysconfig
from rasp.common import check_attach_flag, set_attach_flag, hook, free
from rasp.common import debug
from rasp.common.report import message
from rasp.common.report.client import RASPClient
from rasp.common.var import RASP


def parse_arg():
    parser = argparse.ArgumentParser(description='')
    parser.add_argument(
        '--IAST', dest='IAST', action='store_const',
        const=True, default=False,
        help='IAST switch'
    )
    parser.add_argument(
        '--DEBUG', dest='DEBUG', action='store_const',
        const=True, default=False,
        help='DEBUG switch'
    )
    parser.add_argument(
        '--CLIENT', dest='CLIENT', action='store_const',
        const=True, default=False,
        help='CLIENT switch'
    )
    args = parser.parse_args()
    return args.IAST, args.DEBUG, args.CLIENT


def setup_var(iast=False, debug_switch=False):
    RASP["IAST"] = iast
    RASP["DEBUG"] = debug_switch


def setup_client():
    message.RASP_CLIENT = RASPClient()
    message.RASP_CLIENT.setup()


def rasp_static_attach():
    iast, debug_switch, client = parse_arg()
    the_attach_python_code = "import rasp;rasp.setup_var({}, {});".format(
        iast, debug_switch)
    if client:
        the_attach_python_code += "rasp.setup_client();"
    the_attach_python_code += "rasp.hook()"
    stdlib_path = sysconfig.get_paths()["stdlib"]
    try:
        write_at_line(
            "{}/site.py".format(stdlib_path),
            the_attach_python_code
        )
    except Exception as write_error:
        print("inject code failed: {}".format(write_error))
        exit(1)


def rasp_static_detach():
    stdlib_path = sysconfig.get_paths()["stdlib"]
    try:
        delete_at_line(
            "{}/site.py".format(stdlib_path),
        )
    except Exception as delete_error:
        print("inject code failed: {}".format(delete_error))
        exit(1)


def rasp_dynamic_attach():
    iast, debug_switch, client = parse_arg()
    the_attach_python_code = "import rasp;rasp.set_var({}, {});".format(
        iast, debug_switch)
    if client:
        the_attach_python_code += "rasp.setup_client();"
    the_attach_python_code += "rasp.hook()"

    print("{}".format(the_attach_python_code))


def rasp_dynamic_detach():
    code = "import rasp;rasp.free()"
    print("{}".format(code))


def write_at_line(file, content):
    with open(file, "r") as site_file:
        site_file_content = site_file.readlines()
    with open(file, "w") as site_file:
        site_file_content.append(content)
        site_file.writelines(site_file_content)


def delete_at_line(file):
    with open(file, "r") as site_file:
        site_file_content = site_file.readlines()
    with open(file, "w") as site_file:
        site_file.writelines(site_file_content[:-1])

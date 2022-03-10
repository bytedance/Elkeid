import os
import socket
import subprocess
import sys

from rasp.log import logger
from rasp.smith import smith_hook

if sys.version_info >= (3, 0):
    import builtins
else:
    import __builtin__ as builtins

logger.info("python probe start")

subprocess.Popen.__init__ = smith_hook(subprocess.Popen.__init__, 0, 0, constructor=True, can_block=True)

os.system = smith_hook(os.system, 0, 1, can_block=True)
os.execv = smith_hook(os.execv, 0, 2, can_block=True)
os.execve = smith_hook(os.execve, 0, 3, can_block=True)
os.spawnv = smith_hook(os.spawnv, 0, 4, can_block=True)
os.spawnve = smith_hook(os.spawnve, 0, 5, can_block=True)
os.spawnvp = smith_hook(os.spawnvp, 0, 6, can_block=True)
os.spawnvpe = smith_hook(os.spawnvpe, 0, 7, can_block=True)

if sys.version_info < (3, 0):
    os.popen = smith_hook(os.popen, 0, 8, can_block=True)

builtins.open = smith_hook(builtins.open, 1, 0, check_recursion=True)

os.open = smith_hook(os.open, 1, 1)
os.remove = smith_hook(os.remove, 1, 2)
os.rmdir = smith_hook(os.rmdir, 1, 3)
os.rename = smith_hook(os.rename, 1, 4)
os.listdir = smith_hook(os.listdir, 1, 5)

if sys.version_info >= (3, 5):
    os.scandir = smith_hook(os.scandir, 1, 6)

socket.socket.connect = smith_hook(socket.socket.connect, 2, 0)

socket.getaddrinfo = smith_hook(socket.getaddrinfo, 3,  0)
socket.gethostbyname = smith_hook(socket.gethostbyname, 3, 1)

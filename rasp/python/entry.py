import os
import sys

name = 'rasp'
path = '/etc/elkeid/plugin/rasp/python/rasp/__init__.py'

if sys.version_info >= (3, 3):
    from importlib.machinery import SourceFileLoader
    SourceFileLoader(name, path).load_module()
elif sys.version_info >= (2, 7):
    import imp
    imp.load_module(name, None, os.path.dirname(path), ('', '', imp.PKG_DIRECTORY))

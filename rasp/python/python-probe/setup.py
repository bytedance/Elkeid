import multiprocessing
import os
import sysconfig

import setuptools
from setuptools import Extension
from setuptools.command.build_ext import build_ext

CMAKE_SOURCE_PATH = 'rasp/probe'
CMAKE_BUILD_PATH = os.path.join(CMAKE_SOURCE_PATH, 'build')
CMAKE_OUTPUT_FILE = os.path.join(CMAKE_SOURCE_PATH, 'lib', 'libpython_probe.so')
PYTHON_INCLUDE_PATH = sysconfig.get_config_var('INCLUDEPY')


class CMakeExtension(Extension):
    def __init__(self, name):
        super().__init__(name, sources=[])


class CMakeBuildExt(build_ext):
    def run(self):
        for ext in self.extensions:
            if isinstance(ext, CMakeExtension):
                self.build_cmake(ext)

        super().run()

    def build_cmake(self, ext):
        if not os.path.exists(CMAKE_BUILD_PATH):
            os.makedirs(CMAKE_BUILD_PATH)

        self.spawn([
            'cmake',
            CMAKE_SOURCE_PATH,
            '-B',
            CMAKE_BUILD_PATH,
            '-D',
            'STATIC_BUILD=ON',
            '-D',
            'Python_INCLUDE_DIRS=%s' % PYTHON_INCLUDE_PATH
        ])

        self.spawn([
            'cmake',
            '--build',
            CMAKE_BUILD_PATH,
            '-j%d' % multiprocessing.cpu_count()
        ])

        os.rename(CMAKE_OUTPUT_FILE, self.get_ext_fullpath(ext.name))


extra = dict(
    ext_modules=[CMakeExtension("rasp.probe")],
    cmdclass={"build_ext": CMakeBuildExt}
) if not os.getenv("PREBUILT") else dict(
    package_data={'rasp': ['probe.so', 'probe.abi3.so']},
)

setuptools.setup(
    name='rasp',
    version='1.0.0',
    author='bytedance',
    author_email='elkeid@bytedance.com',
    description="CPython RASP framework",
    url="https://github.com/bytedance/Elkeid",
    license='Apache-2.0',
    packages=setuptools.find_packages(),
    python_requires='>=2.7',
    **extra
)

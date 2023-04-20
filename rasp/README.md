# Elkeid RASP


### Introduction

* Analyze the runtime used by the process.
* The following probes are supported for dynamic attach to process:
  * CPython
  * Golang
  * JVM
  * NodeJS
  * PHP
* Compatible with Elkeid stack.


### Install

* build manually: [GUIDE](./INSTALL)
  1. CMake 3.17+
  2. GCC 8+
  3. MUSL toolcahin 1.2.2 (download via CDN: [link](https://sf1-cdn-tos.douyinstatic.com/obj/eden-cn/laahweh7uhwbps/x86_64-linux-musl-1.2.2.tar.gz))
  4. RUST toolchain 1.40+
  5. JDK 11+(for Java probe)
  6. Python2 + Python3 + pip + wheel + header files (for python probe)
  7. PHP header files
  8. make and install

```bash=
git submodule update --recursive --init

make -j$(nproc) build \
    STATIC=TRUE \
    PY_PREBUILT=TRUE \
    CC=/opt/x86_64-linux-musl-1.2.2/bin/x86_64-linux-musl-gcc \
    CXX=/opt/x86_64-linux-musl-1.2.2/bin/x86_64-linux-musl-g++ \
    LD=/opt/x86_64-linux-musl-1.2.2/bin/x86_64-linux-musl-ld \
    CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER=/opt/x86_64-linux-musl-1.2.2/bin/x86_64-linux-musl-ld \
    GNU_CC=/opt/gcc-10.4.0/bin/gcc \
    GNU_CXX=/opt/gcc-10.4.0/bin/g++ \
    PHP_HEADERS=/path/to/php-headers \
    PYTHON2_INCLUDE=/path/to/include/python2.7 \
    PYTHON3_INCLUDE=/path/to/include/python3 \
    VERSION=0.0.0.1

sudo make install
```

* build with docker:

```bash=
curl -fsSL https://lf3-static.bytednsdoc.com/obj/eden-cn/laahweh7uhwbps/php-headers.tar.gz | tar -xz -C rasp/php

docker run --rm -v $(pwd):/Elkeid \
    -v /tmp/cache/gradle:/root/.gradle \
    -v /tmp/cache/librasp:/Elkeid/rasp/librasp/target \
    -v /tmp/cache/rasp_server:/Elkeid/rasp/rasp_server/target \
    -v /tmp/cache/plugin:/Elkeid/rasp/plugin/target \
    -e MAKEFLAGS="-j$(nproc)" hackerl/rasp-toolchain \
    make -C /Elkeid/rasp build \
    STATIC=TRUE \
    PY_PREBUILT=TRUE \
    CC=/opt/x86_64-linux-musl-1.2.2/bin/x86_64-linux-musl-gcc \
    CXX=/opt/x86_64-linux-musl-1.2.2/bin/x86_64-linux-musl-g++ \
    LD=/opt/x86_64-linux-musl-1.2.2/bin/x86_64-linux-musl-ld \
    CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER=/opt/x86_64-linux-musl-1.2.2/bin/x86_64-linux-musl-ld \
    GNU_CC=/opt/gcc-10.4.0/bin/gcc GNU_CXX=/opt/gcc-10.4.0/bin/g++ \
    PHP_HEADERS=/Elkeid/rasp/php/php-headers \
    PYTHON2_INCLUDE=/usr/local/include/python2.7 \
    PYTHON3_INCLUDE=/usr/local/include/python3 \
    VERSION=0.0.0.1
```

### Run

* for single process inject
```=
sudo env RUST_LOG=<loglevel> /etc/elkeid/plugin/RASP/elkeid_rasp -p <pid>
```

* with Elkied Agent (multi target)

> Documentation is being written.

## License
Elkeid RASP are distributed under the Apache-2.0 license.

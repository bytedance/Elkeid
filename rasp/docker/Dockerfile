FROM hackerl/centos-cpp:latest

RUN yum install -y unzip openssl-devel vim-common libtool automake bison gettext && yum clean all

RUN curl -fsSL https://www.python.org/ftp/python/3.6.15/Python-3.6.15.tgz | tar -xz -C /tmp && cd /tmp/Python-3.6.15 && ./configure && make -j$(nproc) && make install && pip3 install wheel && rm -rf /tmp/Python-3.6.15
RUN curl -fsSL http://ftp.gnu.org/gnu/autoconf/autoconf-2.71.tar.gz | tar -xz -C /tmp && cd /tmp/autoconf-2.71 && ./configure && make -j$(nproc) && make install && rm -rf /tmp/autoconf-2.71
RUN curl -fsSL https://sf1-cdn-tos.douyinstatic.com/obj/eden-cn/laahweh7uhwbps/x86_64-linux-musl-1.2.2.tar.gz | tar -xz -C /opt
RUN curl -fsSL https://download.java.net/java/GA/jdk14.0.2/205943a0976c4ed48cb16f1043c5c647/12/GPL/openjdk-14.0.2_linux-x64_bin.tar.gz | tar -xz -C /opt
RUN curl -fsSL https://sh.rustup.rs | sh -s -- -y --no-modify-path -t x86_64-unknown-linux-musl

ENV PATH=/root/.cargo/bin:$PATH
ENV PATH=/opt/jdk-14.0.2/bin:$PATH

COPY . /Elkeid
WORKDIR /Elkeid/rasp/php

RUN curl -fsSL https://lf3-static.bytednsdoc.com/obj/eden-cn/laahweh7uhwbps/php-headers.tar.gz | tar -xz
RUN mkdir -p output build; for header in php-headers/*; do cmake -B build -DSTATIC_BUILD=ON -DPHP_EXTENSIONS_INCLUDE_DIR=$header && cmake --build build -j$(nproc) && cp lib/libphp_probe.so output/libphp_probe-$(basename $header).so; done

WORKDIR /Elkeid/rasp

RUN CC=/opt/x86_64-linux-musl-1.2.2/bin/x86_64-linux-musl-gcc CXX=/opt/x86_64-linux-musl-1.2.2/bin/x86_64-linux-musl-g++ LD=/opt/x86_64-linux-musl-1.2.2/bin/x86_64-linux-musl-ld CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER=/opt/x86_64-linux-musl-1.2.2/bin/x86_64-linux-musl-ld make build STATIC=TRUE PHP_LIB=php/output -j$(nproc)
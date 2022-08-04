FROM hackerl/centos-cpp:latest

COPY . /Elkeid
WORKDIR /Elkeid/rasp/php

RUN curl -fsSL https://lf3-static.bytednsdoc.com/obj/eden-cn/laahweh7uhwbps/php-headers.tar.gz | tar -xz
RUN mkdir -p output build; for header in php-headers/*; do cmake -B build -DSTATIC_BUILD=ON -DPHP_EXTENSIONS_INCLUDE_DIR=$header && cmake --build build -j$(nproc) && cp lib/libphp_probe.so output/libphp_probe-$(basename $header).so; done

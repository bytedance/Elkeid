FROM debian:bullseye as scanner_clamav_compiler
RUN apt update
RUN apt-get install -y apt-transport-https ca-certificates debian-archive-keyring
RUN apt-get install -y bison autoconf gettext curl unzip git wget curl
RUN apt-get install -y python3.9 python3-pip python3.9-dev libc-dev
RUN apt-get install -y clang llvm flex ninja-build 
RUN apt-get install -y libstdc++-10-dev cmake

ARG DEBIAN_FRONTEND=noninteractive
ENV PATH=/root/.cargo/bin:$PATH

RUN python3 -m pip install mussels wheel

RUN apt-get clean all


RUN curl https://sf1-cdn-tos.douyinstatic.com/obj/eden-cn/laahweh7uhwbps/x86_64-linux-musl-1.2.2.tar.gz | tar -xzv -C /opt
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --no-modify-path -t x86_64-unknown-linux-musl

ADD . /Elkeid
WORKDIR /Elkeid/plugins/scanner_clamav

RUN bash ./libclamav.sh

ARG CC=/opt/x86_64-linux-musl-1.2.2/bin/x86_64-linux-musl-gcc
ARG CXX=/opt/x86_64-linux-musl-1.2.2/bin/x86_64-linux-musl-g++
ARG STDLIBCXX_STATIC_PATH='/usr/lib/gcc/x86_64-linux-gnu/10/'
ARG RUSTFLAGS='-C target-feature=+crt-static ' 
RUN cargo build --release --bin scanner_plugin --target x86_64-unknown-linux-gnu

RUN mkdir /Elkeid/plugins/scanner_clamav/output
WORKDIR /Elkeid/plugins/scanner_clamav/output
RUN cp /Elkeid/plugins/scanner_clamav/target/x86_64-unknown-linux-gnu/release/scanner_plugin /Elkeid/plugins/scanner_clamav/output/scanner_clamav
RUN mkdir tmp
RUN wget http://lf9-elkeid.bytetos.com/obj/elkeid-download/18249e0cbe7c6aca231f047cb31d753fa4604434fcb79f484ea477f6009303c3/archive_db_default_20220414.zip
RUN mv archive_db_default_20220414.zip ./tmp
RUN tar zcvf scanner_clamav.tar.gz scanner_clamav tmp
RUN rm -rf tmp scanner_clamav
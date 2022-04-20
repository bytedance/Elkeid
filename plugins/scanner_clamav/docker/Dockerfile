FROM debian:bullseye as scanner_clamav_compiler

RUN echo 'deb http://mirrors.tuna.tsinghua.edu.cn/debian/ bullseye main contrib non-free\n\
deb http://mirrors.tuna.tsinghua.edu.cn/debian/ bullseye-updates main contrib non-free\n\
deb http://mirrors.tuna.tsinghua.edu.cn/debian/ bullseye-backports main contrib non-free\n\
deb https://mirrors.tuna.tsinghua.edu.cn/debian-security bullseye-security main contrib non-free\n\
' > /etc/apt/sources.list;
RUN apt update
RUN apt-get install -y apt-transport-https ca-certificates debian-archive-keyring

RUN echo 'deb https://mirrors.tuna.tsinghua.edu.cn/debian/ bullseye main contrib non-free\n\
deb https://mirrors.tuna.tsinghua.edu.cn/debian/ bullseye-updates main contrib non-free\n\
deb https://mirrors.tuna.tsinghua.edu.cn/debian/ bullseye-backports main contrib non-free\n\
deb https://mirrors.tuna.tsinghua.edu.cn/debian-security bullseye-security main contrib non-free\n\
' > /etc/apt/sources.list;
RUN apt update

ARG DEBIAN_FRONTEND=noninteractive
ARG CC=/opt/x86_64-linux-musl-1.2.2/bin/x86_64-linux-musl-gcc
ARG CXX=/opt/x86_64-linux-musl-1.2.2/bin/x86_64-linux-musl-g++
ENV PATH=/root/.cargo/bin:$PATH

RUN apt update
RUN apt-get install -y bison autoconf gettext curl unzip git wget curl
RUN apt-get install -y python3.9 python3-pip python3.9-dev libc-dev
RUN apt-get install -y clang llvm flex ninja-build 
RUN apt-get install -y libstdc++-10-dev cmake

RUN python3 -m pip install mussels wheel

RUN apt-get clean all


RUN curl https://sf1-cdn-tos.douyinstatic.com/obj/eden-cn/laahweh7uhwbps/x86_64-linux-musl-1.2.2.tar.gz | tar -xzv -C /opt
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --no-modify-path -t x86_64-unknown-linux-musl

ADD . /Elkeid
WORKDIR /Elkeid/plugins/scanner_clamav

RUN bash ./libclamav.sh
ARG STDLIBCXX_STATIC_PATH='/usr/lib/gcc/x86_64-linux-gnu/10/'
ARG RUSTFLAGS='-C target-feature=+crt-static ' 
RUN cargo build --release --bin scanner_plugin --target x86_64-unknown-linux-gnu

COPY --from=scanner_clamav_compiler /Elkeid/plugins/scanner_clamav/target/x86_64-unknown-linux-gnu/release/scanner_plugin .
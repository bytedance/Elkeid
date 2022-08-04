FROM debian:bullseye

ARG DEBIAN_FRONTEND=noninteractive
ARG CC=/opt/x86_64-linux-musl-1.2.2/bin/x86_64-linux-musl-gcc
ARG CXX=/opt/x86_64-linux-musl-1.2.2/bin/x86_64-linux-musl-g++
ENV PATH=/root/.cargo/bin:$PATH

RUN apt update
RUN apt install -y pkg-config libtool-bin bison autoconf gettext autopoint curl unzip python3 python3-pip git cmake xxd openjdk-11-jdk
RUN apt-get clean all

RUN pip3 install wheel

RUN curl https://sf1-cdn-tos.douyinstatic.com/obj/eden-cn/laahweh7uhwbps/x86_64-linux-musl-1.2.2.tar.gz | tar -xzv -C /opt
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --no-modify-path -t x86_64-unknown-linux-musl

COPY . /Elkeid
WORKDIR /Elkeid/rasp

RUN make build STATIC=TRUE -j$(nproc)

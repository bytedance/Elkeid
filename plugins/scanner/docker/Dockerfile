FROM debian:bullseye as scanner_compiler

SHELL ["/bin/bash", "-c"]

RUN apt update
RUN apt-get install -y apt-transport-https ca-certificates debian-archive-keyring
RUN apt-get install -y bison autoconf gettext curl unzip git wget curl
RUN apt-get install -y python3.9 python3-pip python3.9-dev libc-dev
RUN apt-get install -y clang llvm flex ninja-build lsb-release
RUN apt-get install -y libstdc++-10-dev cmake make libpcre2-dev

ARG DEBIAN_FRONTEND=noninteractive
ENV PATH=/root/.cargo/bin:$PATH

RUN python3 -m pip install mussels wheel

RUN apt-get clean all

RUN curl -O https://musl.cc/x86_64-linux-musl-cross.tgz
RUN tar zxvf x86_64-linux-musl-cross.tgz
RUN mv x86_64-linux-musl-cross /opt/x86_64-linux-musl
RUN rm -f x86_64-linux-musl-cross.tgz

ENV RUSTUP_HOME=/opt/rust
ENV CARGO_HOME=/opt/rust

RUN echo 'export PATH=/opt/rust/bin:$PATH' >> /etc/profile
RUN echo 'export PATH=/opt/x86_64-linux-musl/bin:$PATH' >> /etc/profile
RUN echo 'export RUSTUP_HOME=/opt/rust' >> /etc/profile

RUN echo 'export PATH=/opt/rust/bin:$PATH' >> /root/.bashrc
RUN echo 'export PATH=/opt/x86_64-linux-musl/bin:$PATH' >>  /root/.bashrc
RUN echo 'export RUSTUP_HOME=/opt/rust' >> /root/.bashrc

RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --no-modify-path -t x86_64-unknown-linux-musl

ADD . /Elkeid
WORKDIR /Elkeid/plugins/scanner

RUN bash ./libclamav.sh

RUN source /opt/rust/env
RUN source ~/.bashrc
RUN rustup target add x86_64-unknown-linux-musl
RUN CC="x86_64-linux-musl-gcc" CXX="x86_64-linux-musl-c++" RUSTFLAGS='-C target-feature=+crt-static' cargo build --release --bin scanner_plugin --target x86_64-unknown-linux-musl
RUN cp -r tools/* ./output/.

RUN mkdir /Elkeid/plugins/scanner/output
WORKDIR /Elkeid/plugins/scanner/output
RUN cp /Elkeid/plugins/scanner/target/x86_64-unknown-linux-musl/release/scanner_plugin /Elkeid/plugins/scanner/output/scanner
RUN mkdir tmp
RUN wget http://lf9-elkeid.bytetos.com/obj/elkeid-download/18249e0cbe7c6aca231f047cb31d753fa4604434fcb79f484ea477f6009303c3/archive_db_default_20220607.zip
RUN mv archive_db_default_20220607.zip ./tmp
RUN tar zcvf scanner.tar.gz scanner tmp elkeid_targets
RUN rm -rf tmp scanner

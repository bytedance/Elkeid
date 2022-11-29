#!/bin/bash
set -e
if [ -z "${BUILD_VERSION}" ];then
        echo 'please set BUILD_VERSION'
        exit 1
fi
mkdir -p output
RUSTFLAGS='-C link-arg=-s' cargo build --target x86_64-unknown-linux-musl --release
RUSTFLAGS='-C link-arg=-s' cargo build --target aarch64-unknown-linux-musl --release
cp target/x86_64-unknown-linux-musl/release/journal_watcher output/journal_watcher-linux-amd64-${BUILD_VERSION}.plg
cp target/aarch64-unknown-linux-musl/release/journal_watcher output/journal_watcher-linux-arm64-${BUILD_VERSION}.plg

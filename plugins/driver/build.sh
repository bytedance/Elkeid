#!/bin/bash
set -e
mkdir -p output
export RUSTFLAGS='-C link-arg=-s'
cargo build --target x86_64-unknown-linux-musl --release
cargo build --target aarch64-unknown-linux-musl --release
cp target/x86_64-unknown-linux-musl/release/driver output/driver-default-x86_64-${BUILD_VERSION}.plg
cp target/aarch64-unknown-linux-musl/release/driver output/driver-default-aarch64-${BUILD_VERSION}.plg

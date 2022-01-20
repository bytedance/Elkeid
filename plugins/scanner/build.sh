#!/bin/bash

rustup target add x86_64-unknown-linux-musl
cargo build --release --target x86_64-unknown-linux-musl

if [ $? -ne 0 ]; then
    echo "Elkeid plugin build failed"
    exit -1
else
    echo "Elkeid plugin build succeed"
fi

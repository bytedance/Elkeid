#!/bin/bash

RUSTFLAGS='-C target-feature=+crt-static' cargo build --release --target x86_64-unknown-linux-gnu

if [ $? -ne 0 ]; then
    echo "Elkeid plugin build failed"
    exit -1
else
    echo "Elkeid plugin build succeed"
fi

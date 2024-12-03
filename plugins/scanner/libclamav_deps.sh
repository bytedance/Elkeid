#!/bin/bash

if [ -z "$TARGET_ARCH" ]; then
    echo "TARGET_ARCH set default: x86_64"
    export TARGET_ARCH="x86_64"
fi

rm -rf clamav-mussels-cookbook
git clone https://github.com/kulukami/clamav-mussels-cookbook.git

if [ "$TARGET_ARCH" == "x86_64" ]; then
    echo "build x86_64"
else
    echo "change TARGET_ARCH into :$TARGET_ARCH"
    sed -i "s|x86_64-linux-musl|$TARGET_ARCH-linux-musl|gi" ` grep -rl x86_64-linux-musl ./clamav-mussels-cookbook`
fi

cd clamav-mussels-cookbook
rm -rf  mussels/* &> /dev/null
mkdir mussels &> /dev/null

msl build libclamav_deps -t host-musl-$TARGET_ARCH -w mussels/work -i mussels/install

if [ $? -ne 0 ]; then
    echo "mussels clamav_deps build failed"
    exit -1
else
    echo "mussels clamav_deps build succeed"
fi

cd -
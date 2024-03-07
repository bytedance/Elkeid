#!/bin/bash
rm -rf /ko_output || true
mkdir -p /ko_output
BUILD_VERSION=$(cat LKM/include/kprobe.h | grep SMITH_VERSION | awk -F '"' '{print $2}')
KO_NAME=$(grep "MODULE_NAME" ./LKM/Makefile | grep -m 1 ":=" | awk '{print $3}')


enableGcc11(){
    export CC=/opt/rh/gcc-toolset-11/root/usr/bin/gcc
    export CPP=/opt/rh/gcc-toolset-11/root/usr/bin/cpp
    export CXX=/opt/rh/gcc-toolset-11/root/usr/bin/c++
}

enableGcc11

echo "this is centos"
for f in /usr/src/kernels/*
do
    set -e
    set -o xtrace
    KV="$(basename -- $f)"
    echo "Processing $KV file..."
    $CC --version
    KVERSION=$KV  make -C ./LKM clean || true
    BATCH=true KVERSION=$KV make -C ./LKM -j all | tee /ko_output/${KO_NAME}_${BUILD_VERSION}_${KV}_amd64.log || true 
    sha256sum  ./LKM/${KO_NAME}.ko | awk '{print $1}' > /ko_output/${KO_NAME}_${BUILD_VERSION}_${KV}_amd64.sign  || true  

    if [ -s /ko_output/${KO_NAME}_${BUILD_VERSION}_${KV}_amd64.sign ]; then
            # The file is not-empty.
            echo ok > /dev/null
    else
            # The file is empty.
            rm -f /ko_output/${KO_NAME}_${BUILD_VERSION}_${KV}_amd64.sign
    fi
    mv ./LKM/${KO_NAME}.ko /ko_output/${KO_NAME}_${BUILD_VERSION}_${KV}_amd64.ko || true
    KVERSION=$KV  make -C ./LKM clean || true
done
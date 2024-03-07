#!/bin/bash
rm -rf /ko_output || true
mkdir -p /ko_output
BUILD_VERSION=$(cat LKM/include/kprobe.h | grep SMITH_VERSION | awk -F '"' '{print $2}')
KO_NAME=$(grep "MODULE_NAME" ./LKM/Makefile | grep -m 1 ":=" | awk '{print $3}')

enableGcc8(){
    export CC=/opt/rh/devtoolset-8/root/usr/bin/gcc
    export CPP=/opt/rh/devtoolset-8/root/usr/bin/cpp
    export CXX=/opt/rh/devtoolset-8/root/usr/bin/c++
}

disableGcc8(){
    unset CC
    unset CPP
    unset CXX
}

echo "BUILD_VERSION=" $BUILD_VERSION

for each_tag in `yum --showduplicates list kernel-devel --enablerepo=C7.{3.4,5,6,7,8,9}.* | grep kernel-devel | awk -c '{print $2}'`
do 
    yum remove -y kernel-devel kernel-tools kernel-tools-libs &> /dev/null
    yum install -y --enablerepo=C7.{3.4,5,6,7,8,9}.*  kernel-devel-$each_tag.aarch64 kernel-tools-$each_tag.aarch64 kernel-tools-libs-$each_tag.aarch64 &> /dev/null

    KV=$each_tag.aarch64

    disableGcc8
    if [[ $each_tag == 4.18* ]]; then
        enableGcc8
    fi
    
    KVERSION=$KV make -C ./LKM clean || true 
    if [ -z $CC ];then
        export CC=gcc
    fi
    echo "$CC --version =>"
    $CC --version
    BATCH=true KVERSION=$KV make -C ./LKM -j all | tee /ko_output/${KO_NAME}_${BUILD_VERSION}_${KV}_arm64.log || true 
    sha256sum  ./LKM/${KO_NAME}.ko | awk '{print $1}' > /ko_output/${KO_NAME}_${BUILD_VERSION}_${KV}_arm64.sign  || true  

    if [ -s /ko_output/${KO_NAME}_${BUILD_VERSION}_${KV}_arm64.sign ]; then
        # The file is not-empty.
        echo ok > /dev/null
    else
        # The file is empty.
        rm -f /ko_output/${KO_NAME}_${BUILD_VERSION}_${KV}_arm64.sign
    fi

    mv ./LKM/${KO_NAME}.ko /ko_output/${KO_NAME}_${BUILD_VERSION}_${KV}_arm64.ko || true 
    KVERSION=$KV  make -C ./LKM clean || true

done

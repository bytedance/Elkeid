#!/bin/bash
mkdir -p /ko_output
BUILD_VERSION=$(cat LKM/src/init.c | grep MODULE_VERSION | awk -F '"' '{print $2}')
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

for each_tag in `yum --showduplicates list kernel-devel | grep kernel-devel | awk -c '{print $2}'`
do 
    yumdownloader  --destdir /root/headers kernel-devel-$each_tag.aarch64 > /dev/null
    rpm --force -i /root/headers/kernel-devel-$each_tag.aarch64.rpm || true
    KV=$each_tag.aarch64

    disableGcc8
    if [[ $each_tag == 4.18*]]; then
        enableGcc8
    fi
    
    KVERSION=$KV make -C ./LKM clean || true 
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

    rpm --force -e kernel-devel-$each_tag.aarch64 > /dev/null || true
    rm -f /root/headers/*.rpm
done


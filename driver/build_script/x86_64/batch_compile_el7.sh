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

enableGcc9(){
    export CC=/opt/rh/devtoolset-9/root/usr/bin/gcc
    export CPP=/opt/rh/devtoolset-9/root/usr/bin/cpp
    export CXX=/opt/rh/devtoolset-9/root/usr/bin/c++
}

enableGcc10(){
    export CC=/opt/rh/devtoolset-10/root/usr/bin/gcc
    export CPP=/opt/rh/devtoolset-10/root/usr/bin/cpp
    export CXX=/opt/rh/devtoolset-10/root/usr/bin/c++
}

disableGcc(){
    unset CC
    unset CPP
    unset CXX
}

for each_tag in `yum --showduplicates list kernel-devel | grep kernel-devel | awk -c '{print $2}'`
do 
    yumdownloader  --destdir /root/headers kernel-devel-$each_tag.x86_64 > /dev/null
    rpm --force -i /root/headers/kernel-devel-$each_tag.x86_64.rpm || true
    KV=$each_tag.x86_64

    disableGcc
    if [[ $each_tag == 4.18* || $each_tag == 4.19*  ||  $each_tag == 4.20* || $each_tag == 5.* ]]; then
        enableGcc8
    fi

    if [[ $each_tag == 5.10.* || $each_tag == 5.11.*  ||  $each_tag == 5.12.*  ||  $each_tag == 5.13.*  ||  $each_tag == 5.14.*  ||  $each_tag == 5.15.*  ||  $each_tag == 5.16.*  ||  $each_tag == 5.17.*  || $each_tag == 5.18.*  ||  $each_tag == 5.19.*  ||  $each_tag == 5.20.* ]] ; then
        enableGcc9
    fi

    if [[ $each_tag == 6.* ]]; then
        enableGcc10
    fi
    
    KVERSION=$KV make -C ./LKM clean || true 
    if [ -z $CC ];then
        export CC=gcc
    fi
    echo "$CC --version =>"
    $CC --version
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

    rpm --force -e kernel-devel-$each_tag.x86_64 > /dev/null || true
    rm -f /root/headers/*.rpm
done
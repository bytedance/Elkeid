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


for each_tag in `yum --disablerepo=* --enablerepo=centosplus --showduplicates list kernel-plus-devel | grep kernel-plus-devel | awk -c '{print $2}'`
do 
    yum remove -y kernel-plus-devel kernel-plus-tools kernel-plus-tools-libs kernel-devel kernel-tools kernel-tools-libs &> /dev/null
    yumdownloader  --disablerepo=* --enablerepo=centosplus --destdir /root/headers kernel-plus-devel-$each_tag.x86_64 kernel-plus-tools-$each_tag.x86_64 kernel-plus-tools-libs-$each_tag.x86_64 > /dev/null

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

    rpm --force -i /root/headers/kernel-plus-*.rpm || true
    KV=$each_tag.x86_64
    
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

    rm -f /root/headers/*.rpm
done
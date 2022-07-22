#!/bin/bash
mkdir -p /ko_output
BUILD_VERSION=$(cat LKM/src/init.c | grep MODULE_VERSION | awk -F '"' '{print $2}')
KO_NAME=$(grep "MODULE_NAME" ./LKM/Makefile | grep -m 1 ":=" | awk '{print $3}')


for each_tag in `yum --disablerepo=* --enablerepo=centosplus --showduplicates list kernel-plus-devel | grep kernel-plus-devel | awk -c '{print $2}'`
do 
    yum remove -y kernel-plus-devel kernel-plus-tools kernel-plus-tools-libs kernel-devel kernel-tools kernel-tools-libs
    yumdownloader  --disablerepo=* --enablerepo=centosplus --destdir /root/headers kernel-plus-devel-$each_tag.x86_64 kernel-plus-tools-$each_tag.x86_64 kernel-plus-tools-libs-$each_tag.x86_64

    rpm --force -ivh /root/headers/kernel-plus-*.rpm || true
    KV=$each_tag.x86_64
    
    KVERSION=$KV make -C ./LKM clean || true 
    BATCH=true KVERSION=$KV make -C ./LKM -j all || true 
     sha256sum  ./LKM/${KO_NAME}.ko | awk '{print $1}' > /ko_output/${KO_NAME}_${BUILD_VERSION}_${KV}_amd64.sign  || true  
    mv ./LKM/${KO_NAME}.ko /ko_output/${KO_NAME}_${BUILD_VERSION}_${KV}_amd64.ko || true 
    KVERSION=$KV  make -C ./LKM clean || true

    rm -f /root/headers/*.rpm
done
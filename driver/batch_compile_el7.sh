#!/bin/bash
mkdir -p /ko_output
BUILD_VERSION=$(cat LKM/src/init.c | grep MODULE_VERSION | awk -F '"' '{print $2}')
KO_NAME=$(grep "MODULE_NAME" ./LKM/Makefile | grep -m 1 ":=" | awk '{print $3}')


for each_tag in `yum --showduplicates list kernel-devel | grep kernel-devel | awk -c '{print $2}'`
do 
    yumdownloader  --destdir /root/headers kernel-devel-$each_tag.x86_64 > /dev/null
    rpm --force -i /root/headers/kernel-devel-$each_tag.x86_64.rpm || true
    KV=$each_tag.x86_64
    
    KVERSION=$KV make -C ./LKM clean || true 
    BATCH=true KVERSION=$KV make -C ./LKM -j all || true 
     sha256sum  ./LKM/${KO_NAME}.ko | awk '{print $1}' > /ko_output/${KO_NAME}_${BUILD_VERSION}_${KV}_amd64.sign  || true  
    mv ./LKM/${KO_NAME}.ko /ko_output/${KO_NAME}_${BUILD_VERSION}_${KV}_amd64.ko || true 
    KVERSION=$KV  make -C ./LKM clean || true

    rpm --force -e kernel-devel-$each_tag.x86_64 > /dev/null || true
    rm -f /root/headers/*.rpm
done
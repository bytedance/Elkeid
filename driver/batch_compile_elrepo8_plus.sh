#!/bin/bash
mkdir -p /ko_output
BUILD_VERSION=$(cat LKM/src/init.c | grep MODULE_VERSION | awk -F '"' '{print $2}')
KO_NAME=$(grep "MODULE_NAME" ./LKM/Makefile | grep -m 1 ":=" | awk '{print $3}')

for each_lt_version in `ls /root/headers/kernel-plus* | grep kernel-plus-devel | sed -r 's/kernel-plus-devel-([^"]+).el8.elrepo.x86_64.rpm/\1/g'`
do 
    yum remove -y kernel-devel kernel-plus-devel
    yum remove -y kernel-tools kernel-plus-tools
    yum remove -y kernel-tools-libs kernel-plus-tools-libs

    rpm -ivh --force /root/headers/{kernel-plus-devel-$each_lt_version.el8.elrepo.x86_64.rpm,kernel-plus-devel-$each_lt_version.el8.elrepo.x86_64.rpm,kernel-plus-devel-$each_lt_version.el8.elrepo.x86_64.rpm}

    rm -f /root/headers/{kernel-plus-devel-$each_lt_version.el8.elrepo.x86_64.rpm,kernel-plus-devel-$each_lt_version.el8.elrepo.x86_64.rpm,kernel-plus-devel-$each_lt_version.el8.elrepo.x86_64.rpm}
    KV=$each_lt_version.el8.elrepo.x86_64
    KVERSION=$KV make -C ./LKM clean || true 
    BATCH=true KVERSION=$KV make -C ./LKM -j all || true 
     sha256sum  ./LKM/${KO_NAME}.ko | awk '{print $1}' > /ko_output/${KO_NAME}_${BUILD_VERSION}_${KV}_amd64.sign  || true  
    mv ./LKM/${KO_NAME}.ko /ko_output/${KO_NAME}_${BUILD_VERSION}_${KV}_amd64.ko || true 
    KVERSION=$KV  make -C ./LKM clean || true
done
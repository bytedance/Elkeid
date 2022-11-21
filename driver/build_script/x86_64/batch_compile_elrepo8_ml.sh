#!/bin/bash
mkdir -p /ko_output
BUILD_VERSION=$(cat LKM/src/init.c | grep MODULE_VERSION | awk -F '"' '{print $2}')
KO_NAME=$(grep "MODULE_NAME" ./LKM/Makefile | grep -m 1 ":=" | awk '{print $3}')

for each_ml_version in `curl https://mirrors.portworx.com/mirrors/http/mirrors.coreix.net/elrepo-archive-archive/kernel/el8/x86_64/RPMS/ | grep el8.elrepo.x86_64.rpm | grep kernel-ml-devel | sed -r 's/.*href="([^"]+).*/\1/g' | sed -r 's/kernel-ml-devel-([^"]+).el8.elrepo.x86_64.rpm/\1/g'`
do 
    wget -q "https://mirrors.portworx.com/mirrors/http/mirrors.coreix.net/elrepo-archive-archive/kernel/el8/x86_64/RPMS/kernel-ml-devel"-$each_ml_version.el8.elrepo.x86_64.rpm
    wget -q "https://mirrors.portworx.com/mirrors/http/mirrors.coreix.net/elrepo-archive-archive/kernel/el8/x86_64/RPMS/kernel-ml-tools"-$each_ml_version.el8.elrepo.x86_64.rpm
    wget -q "https://mirrors.portworx.com/mirrors/http/mirrors.coreix.net/elrepo-archive-archive/kernel/el8/x86_64/RPMS/kernel-ml-tools-libs"-$each_ml_version.el8.elrepo.x86_64.rpm
    
    yum remove -y kernel-devel kernel-lt-devel kernel-ml-devel &> /dev/null
    yum remove -y kernel-tools kernel-lt-tools kernel-ml-tools &> /dev/null
    yum remove -y kernel-tools-libs kernel-lt-tools-libs kernel-ml-tools-libs &> /dev/null

    rpm -i --force ./kernel*.rpm
    rm -f ./kernel*.rpm 
    KV=$each_ml_version.el8.elrepo.x86_64
    KVERSION=$KV make -C ./LKM clean || true 
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
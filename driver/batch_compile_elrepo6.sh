#!/bin/bash
mkdir -p /ko_output
BUILD_VERSION=$(cat LKM/src/init.c | grep MODULE_VERSION | awk -F '"' '{print $2}')
KO_NAME=$(grep "MODULE_NAME" ./LKM/Makefile | grep -m 1 ":=" | awk '{print $3}')

for each_ml_version in `curl http://mirrors.coreix.net/elrepo-archive-archive/kernel/el6/x86_64/RPMS/ | grep el6.elrepo.x86_64.rpm | grep kernel-ml-devel | sed -r 's/.*href="([^"]+).*/\1/g' | sed -r 's/kernel-ml-devel-([^"]+).el6.elrepo.x86_64.rpm/\1/g'`
do 
    wget -q "http://mirrors.coreix.net/elrepo-archive-archive/kernel/el6/x86_64/RPMS/kernel-ml-devel"-$each_ml_version.el6.elrepo.x86_64.rpm
    
    yum remove -y kernel-devel kernel-ml-devel kernel-lt-devel &> /dev/null
    
    rpm -i --force ./kernel*.rpm 
    rm -f ./kernel*.rpm 
    KV=$each_ml_version.el6.elrepo.x86_64
    KVERSION=$KV make -C ./LKM clean || true 
    BATCH=true KVERSION=$KV make -C ./LKM -j all || true 
     sha256sum  ./LKM/${KO_NAME}.ko | awk '{print $1}' > /ko_output/${KO_NAME}_${BUILD_VERSION}_${KV}_amd64.sign  || true  
    mv ./LKM/${KO_NAME}.ko /ko_output/${KO_NAME}_${BUILD_VERSION}_${KV}_amd64.ko || true 
    KVERSION=$KV  make -C ./LKM clean || true
done

for each_lt_version in `curl http://mirrors.coreix.net/elrepo-archive-archive/kernel/el6/x86_64/RPMS/ | grep el6.elrepo.x86_64.rpm | grep kernel-lt-devel | sed -r 's/.*href="([^"]+).*/\1/g' | sed -r 's/kernel-lt-devel-([^"]+).el6.elrepo.x86_64.rpm/\1/g'`
do 
    wget "http://mirrors.coreix.net/elrepo-archive-archive/kernel/el6/x86_64/RPMS/kernel-lt-devel"-$each_lt_version.el6.elrepo.x86_64.rpm
    
    yum remove -y kernel-devel kernel-ml-devel kernel-lt-devel
    rpm -ivh --force ./kernel*.rpm 

    rm -f ./kernel*.rpm 
    KV=$each_lt_version.el6.elrepo.x86_64
    KVERSION=$KV make -C ./LKM clean || true 
    BATCH=true KVERSION=$KV make -C ./LKM -j all || true 
     sha256sum  ./LKM/${KO_NAME}.ko | awk '{print $1}' > /ko_output/${KO_NAME}_${BUILD_VERSION}_${KV}_amd64.sign  || true  
    mv ./LKM/${KO_NAME}.ko /ko_output/${KO_NAME}_${BUILD_VERSION}_${KV}_amd64.ko || true 
    KVERSION=$KV  make -C ./LKM clean || true
done
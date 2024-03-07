#!/bin/bash
rm -rf /ko_output || true
mkdir -p /ko_output
BUILD_VERSION=$(cat LKM/include/kprobe.h | grep SMITH_VERSION | awk -F '"' '{print $2}')
KO_NAME=$(grep "MODULE_NAME" ./LKM/Makefile | grep -m 1 ":=" | awk '{print $3}')

cd /root
wget https://mirrors.portworx.com/mirrors/http/mirrors.coreix.net/elrepo-archive-archive/kernel/el6/x86_64/RPMS/kernel-ml-devel-4.15.4-1.el6.elrepo.x86_64.rpm
rpm -i --force ./kernel-ml-devel-4.15.4-1.el6.elrepo.x86_64.rpm
cp /usr/src/kernels/4.15.4-1.el6.elrepo.x86_64/tools/objtool/objtool /usr/bin/objtool
cp /usr/bin/objtool /bin/objtool
cd -

SPECS_VERSION="4.15."

for each_ml_version in `curl https://mirrors.portworx.com/mirrors/http/mirrors.coreix.net/elrepo-archive-archive/kernel/el6/x86_64/RPMS/ | grep el6.elrepo.x86_64.rpm | grep kernel-ml-devel | sed -r 's/.*href="([^"]+).*/\1/g' | sed -r 's/kernel-ml-devel-([^"]+).el6.elrepo.x86_64.rpm/\1/g'`
do 
    wget -q "https://mirrors.portworx.com/mirrors/http/mirrors.coreix.net/elrepo-archive-archive/kernel/el6/x86_64/RPMS/kernel-ml-devel"-$each_ml_version.el6.elrepo.x86_64.rpm
    
    yum remove -y kernel-devel kernel-ml-devel kernel-lt-devel &> /dev/null
    
    rpm -i --force ./kernel*.rpm 
    rm -f ./kernel*.rpm 

    if [[ $each_ml_version =~ $SPECS_VERSION ]]
    then
        cp /usr/bin/objtool /usr/src/kernels/$each_ml_version.el6.elrepo.x86_64/tools/objtool/objtool 
    fi

    KV=$each_ml_version.el6.elrepo.x86_64
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
done

for each_lt_version in `curl https://mirrors.portworx.com/mirrors/http/mirrors.coreix.net/elrepo-archive-archive/kernel/el6/x86_64/RPMS/ | grep el6.elrepo.x86_64.rpm | grep kernel-lt-devel | sed -r 's/.*href="([^"]+).*/\1/g' | sed -r 's/kernel-lt-devel-([^"]+).el6.elrepo.x86_64.rpm/\1/g'`
do 
    wget "https://mirrors.portworx.com/mirrors/http/mirrors.coreix.net/elrepo-archive-archive/kernel/el6/x86_64/RPMS/kernel-lt-devel"-$each_lt_version.el6.elrepo.x86_64.rpm
    
    yum remove -y kernel-devel kernel-ml-devel kernel-lt-devel
    rpm -i --force ./kernel*.rpm 

    rm -f ./kernel*.rpm 
    KV=$each_lt_version.el6.elrepo.x86_64
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
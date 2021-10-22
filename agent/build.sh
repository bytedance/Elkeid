#!/bin/bash
set -e

AGENT_PACKAGE="github.com/bytedance/Elkeid"
WORKDIR=${PWD}

if [ -z "${BUILD_VERSION}" ];then
        echo 'Please set BUILD_VERSION.'
        exit 1
fi

if ! nfpm -v > /dev/null 2>&1;then
    echo "Installing nfpm..."
    cd /tmp
    git clone https://github.com/Serinalice/nfpm.git
    cd nfpm
    make build
    sudo cp nfpm /usr/local/bin
    hash -r
fi


cd ${WORKDIR}
mkdir -p build output
go build -tags product -ldflags "-X ${AGENT_PACKAGE}/agent.Version=${BUILD_VERSION}" -o build/elkeid-agent
echo "Binary build done."
cp -r depoly/* build
cd build
sed -i 's/1.6.0.0/'${BUILD_VERSION}'/g' nfpm.yaml
nfpm package -p deb
nfpm package -p rpm
cd ../
cp build/*.deb build/*.rpm output
rm -rf build
#!/bin/bash
set -e

BUILD_VERSION="1.7.0.2"
AGENT_PACKAGE="github.com/bytedance/Elkeid/agent/agent"

WORKDIR=${PWD}

if ! nfpm -v > /dev/null 2>&1;then
    go install github.com/goreleaser/nfpm/v2/cmd/nfpm@latest
fi

cd ${WORKDIR}
mkdir -p build output
cd deploy/control && go build -o ../../build/elkeidctl
cd ${WORKDIR}
go build -tags product -ldflags "-X ${AGENT_PACKAGE}.Version=${BUILD_VERSION}" -o build/elkeid-agent
echo "Binary build done."
cp -r deploy/* build
cd build
sed -i 's/1.7.0.0/'${BUILD_VERSION}'/g' nfpm.yaml
nfpm package -p deb
nfpm package -p rpm
cd ../
cp build/*.deb build/*.rpm output
rm -rf build
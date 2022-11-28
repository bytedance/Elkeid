#!/bin/bash
set -e

export AGENT_PACKAGE="github.com/bytedance/Elkeid/agent/agent"
export WORKDIR=${PWD}

if ! nfpm -v > /dev/null 2>&1;then
    go install github.com/goreleaser/nfpm/v2/cmd/nfpm@latest
fi

rm -rf output build
mkdir -p output build

for arch in amd64 arm64; do
    export GOARCH=${arch}
    cd ${WORKDIR}
    cd deploy/control && go build -o ../../build/elkeidctl
    cd ${WORKDIR}
    go build -tags product -ldflags "-X ${AGENT_PACKAGE}.Version=${BUILD_VERSION}" -o build/elkeid-agent
    echo "binary build done."
    cp -r deploy/* build
    cd build
    sed -i 's/version:.*$/version: '${BUILD_VERSION}'/g' nfpm.yaml
    sed -i 's/arch:.*$/arch: '${arch}'/g' nfpm.yaml
    nfpm package -p deb
    nfpm package -p rpm
    cd ../
    cp build/*.deb build/*.rpm output
    rm -rf build
done
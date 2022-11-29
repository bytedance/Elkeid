#!/bin/bash
set -e
if [ -z "${BUILD_VERSION}" ];then
        echo 'Please set BUILD_VERSION.'
        exit 1
fi
mkdir -p output
GOARCH=amd64 go build -o output/collector-linux-amd64-${BUILD_VERSION}.plg
GOARCH=arm64 go build -o output/collector-linux-arm64-${BUILD_VERSION}.plg
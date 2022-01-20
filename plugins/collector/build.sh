#!/bin/bash
set -e
BUILD_VERSION="1.0.0.81"
mkdir -p output
go build -o output/collector-linux-amd64-${BUILD_VERSION}.plg
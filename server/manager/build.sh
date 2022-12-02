#!/bin/bash

if ! type go >/dev/null 2>&1; then
    echo 'go not installed';
    exit 1
fi

ELKEID_BUILD=$(date "+%Y%m%d%H%M")

rm -rf output
mkdir -p output/
rm -rf static/frontend/*
cp -r ../web_console/* static/frontend/

go mod download
go build \
  -ldflags "-s -w" \
  -ldflags "-X github.com/bytedance/Elkeid/server/manager/biz.Version=1.9.1_community -X github.com/bytedance/Elkeid/server/manager/biz.Build=$ELKEID_BUILD" \
  -o ./output/manager main.go
go build -ldflags "-s -w" -o ./output/init cmd/inittools/init.go

cd output
cp -r ../conf ./
rm -f conf/svr.yml
tar zcvf bin.tar.gz ./*
rm -f manager
rm -f init
rm -rf conf

cd ../
rm -rf static/frontend/*

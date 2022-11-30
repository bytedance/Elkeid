#!/bin/bash

if ! type go >/dev/null 2>&1; then
    echo 'go not installed';
    exit 1
fi

rm -rf output
mkdir -p output/
go mod download
go build -ldflags "-s -w" -o ./output/agent_center main.go

cd output
tar zcvf bin.tar.gz ./*
rm -f agent_center
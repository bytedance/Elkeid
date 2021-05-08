#!/usr/bin/env bash
# usage:
# run this script at the directory where the .proto file locate
# codegen.sh protofilename.proto

if [ $# != 1 ] ; then
  echo "USAGE: $0 protofilename.proto"
  exit 1;
fi

proto=$1
protoc --gofast_out=plugins=grpc:. $proto

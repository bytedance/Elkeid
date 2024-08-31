#!/usr/bin/env bash

# usage:
# Run this script in the directory where the .proto file is located
# ./codegen.sh protofilename.proto

# This script depends on protoc-gen-gogofast. Install it using the following commands:
#   go install github.com/gogo/protobuf/protoc-gen-gogofast@latest
#   export PATH=$PATH:$HOME/go/bin

# Check if the correct number of arguments is provided
if [ $# -ne 1 ]; then
  echo "USAGE: $0 protofilename.proto"
  exit 1
fi

# Check if the provided file exists
proto=$1
if [ ! -f "$proto" ]; then
  echo "Error: File '$proto' not found!"
  exit 1
fi

# Check if protoc is installed
if ! command -v protoc &> /dev/null; then
  echo "Error: protoc is not installed. Please install it first."
  exit 1
fi

# Check if protoc-gen-gogofast is installed
if ! command -v protoc-gen-gogofast &> /dev/null; then
  echo "Error: protoc-gen-gogofast is not installed."
  echo "Install it by running: go install github.com/gogo/protobuf/protoc-gen-gogofast@latest"
  exit 1
fi

# Set GOPATH if not already set
if [ -z "$GOPATH" ]; then
  GOPATH=$(go env GOPATH)
fi

# Generate Go code from the .proto file
protoc --proto_path=. --proto_path="$GOPATH/src" --gogofast_out=plugins=grpc:. "$proto"

# Check if the protoc command was successful
if [ $? -eq 0 ]; then
  echo "Code generation successful!"
else
  echo "Error: Code generation failed."
  exit 1
fi

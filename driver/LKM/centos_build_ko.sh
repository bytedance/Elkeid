#!/bin/bash
set -e
set -o xtrace
FILES=/usr/src/kernels/*
for f in $FILES
do
KV="$(basename -- $f)"
echo "Processing $KV file..."
# take action on each file. $f store current file name
KVERSION=$KV make clean
KVERSION=$KV make
cp smith.ko /opt/result/smith.${KV}.ko
done
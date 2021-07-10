#!/bin/bash
ROOT_DIR=$(cd "$(dirname "$0")"; pwd)

set -e

# mkdir
mkdir -p "$ROOT_DIR/output"

# build
"$ROOT_DIR/gradlew" proguard

cp "$ROOT_DIR/build/libs/JVMProbe-1.0-SNAPSHOT-pro.jar" "$ROOT_DIR/output/SmithAgent.jar"

#!/bin/bash

# make static lib for clamav deps
apt-get update 
apt-get install build-essential clang llvm 
apt-get install libstdc++6 libstdc++-6-dev
apt-get install -y flex bison python3-dev pkg-config ninja-build
python3 -m pip install mussels

git clone --depth 1 https://github.com/Cisco-Talos/clamav-mussels-cookbook.git
cd clamav-mussels-cookbook
rm -rf  mussels/* &> /dev/null
mkdir mussels &> /dev/null
msl build libclamav_deps -t host-static -w mussels/work -i mussels/install
cd -

# make get clamav source code
git clone https://github.com/Cisco-Talos/clamav.git
cd clamav
git checkout clamav-0.104.0
cd -
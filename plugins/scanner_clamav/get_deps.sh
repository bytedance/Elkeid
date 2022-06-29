

#!/bin/bash

# make static lib for clamav deps
apt-get update 
apt-get install -y build-essential clang llvm cmake
apt-get install -y libstdc++6 libstdc++-6-dev
apt-get install -y flex bison python3-dev pkg-config ninja-build python3-pip
python3 -m pip install mussels
#!/bin/bash

# TARGET_ARCH="aarch64"
if [ -z "$TARGET_ARCH" ]; then
    echo "TARGET_ARCH set default: x86_64"
    export TARGET_ARCH="x86_64"
fi

if [ "$TARGET_ARCH" == "x86_64" ]; then
    echo "build x86_64"
else
    echo "change TARGET_ARCH into :$TARGET_ARCH"
    sed -i "s|x86_64-linux-musl|$TARGET_ARCH-linux-musl|gi" ` grep -rl x86_64-linux-musl ./clamav-mussels-cookbook`
fi


if [ -d clamav ]; then 
    cd clamav
        rm -rf  ./build/* &> /dev/null
        git pull 
        git checkout rel/0.104
    cd ..
else 
    git clone https://github.com/kulukami/clamav.git
    cd clamav
        git checkout rel/0.104
    cd ..

fi

cd clamav
    mkdir build &> /dev/null
cd -

export CLAMAV_DEPENDENCIES="$(pwd)/clamav-mussels-cookbook/mussels/install/" 

cd clamav/build 

cmake .. -G Ninja                                                      \
    -DCMAKE_BUILD_TYPE="RelWithDebInfo"                                \
    -DCMAKE_C_COMPILER=$TARGET_ARCH-linux-musl-gcc                           \
    -DCMAKE_CXX_COMPILER=$TARGET_ARCH-linux-musl-g++                         \
    -DJSONC_INCLUDE_DIR="$CLAMAV_DEPENDENCIES/include/json-c"          \
    -DJSONC_LIBRARY="$CLAMAV_DEPENDENCIES/lib/libjson-c.a"             \
    -DBZIP2_INCLUDE_DIR="$CLAMAV_DEPENDENCIES/include"                 \
    -DBZIP2_LIBRARY_RELEASE="$CLAMAV_DEPENDENCIES/lib/libbz2_static.a" \
    -DOPENSSL_ROOT_DIR="$CLAMAV_DEPENDENCIES"                          \
    -DOPENSSL_INCLUDE_DIR="$CLAMAV_DEPENDENCIES/include"               \
    -DOPENSSL_CRYPTO_LIBRARY="$CLAMAV_DEPENDENCIES/lib/libcrypto.a"    \
    -DOPENSSL_SSL_LIBRARY="$CLAMAV_DEPENDENCIES/lib/libssl.a"          \
    -DLIBXML2_INCLUDE_DIR="$CLAMAV_DEPENDENCIES/include/libxml2"       \
    -DLIBXML2_LIBRARY="$CLAMAV_DEPENDENCIES/lib/libxml2.a"             \
    -DPCRE2_INCLUDE_DIR="$CLAMAV_DEPENDENCIES/include"                 \
    -DPCRE2_LIBRARY="$CLAMAV_DEPENDENCIES/lib/libpcre2-8.a"            \
    -DZLIB_INCLUDE_DIR="$CLAMAV_DEPENDENCIES/include"                  \
    -DZLIB_LIBRARY="$CLAMAV_DEPENDENCIES/lib/libz.a"                   \
    -DIconv_INCLUDE_DIR="$CLAMAV_DEPENDENCIES/include"                 \
    -DIconv_LIBRARY="$CLAMAV_DEPENDENCIES/lib/libiconv.a"              \
    -DENABLE_JSON_SHARED=OFF                                           \
    -DENABLE_STATIC_LIB=ON                                             \
    -DENABLE_SYSTEMD=OFF                                               \
    -DENABLE_TESTS=OFF                                                 \
    -DENABLE_LIBCLAMAV_ONLY=ON                                         \
    -DENABLE_UNRAR=ON                                                  \
    -DENABLE_SHARED_LIB=OFF                                            \
    -DDATABASE_DIRECTORY=/var/lib/clamav                               \
    -DAPP_CONFIG_DIRECTORY=/etc/clamav                                 \
    -DBYTECODE_RUNTIME=none                                            \
    -DENABLE_FUZZ=OFF                                                  \
    -DENABLE_APP=OFF                                                   \
    -DENABLE_CLAMONACC=OFF                                             \
    -DENABLE_MILTER=OFF                                                \
    -DENABLE_MAN_PAGES=OFF                                             \
    -DCMAKE_INSTALL_PREFIX=install 

if [ $? -ne 0 ]; then
    echo "libclamav cmake failed"
    exit -1
fi

cmake --build .

if [ $? -ne 0 ]; then
    echo "libclamav build failed"
    exit -1
fi

cd -

rm -rf ./lib/*
mkdir lib &> /dev/null
cp clamav/build/libclamav/libclamav_static.a ./lib
cp clamav/build/libclammspack/libclammspack_static.a ./lib
cp clamav/build/libclamunrar/libclamunrar_static.a ./lib
cp clamav/build/libclamunrar_iface/libclamunrar_iface_static.a ./lib

cp "$CLAMAV_DEPENDENCIES/lib/"*.a ./lib


rm -rf ./include/*
mkdir include &> /dev/null
cp clamav/build/*.h ./include
cp clamav/libclamav/clamav.h ./include
cp clamav/libclamav/matcher.h ./include
cp clamav/libclamav/matcher-ac.h ./include
cp clamav/libclamav/others.h ./include

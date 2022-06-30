#!/bin/bash
cd clamav-mussels-cookbook
rm -rf  mussels/* &> /dev/null
mkdir mussels &> /dev/null
msl build libclamav_deps -t host-static -w mussels/work -i mussels/install
cd -

if [ $? -ne 0 ]; then
    echo "mussels clamav_deps build failed"
    exit -1
else
    echo "mussels clamav_deps build succeed"
fi


# make get clamav source code
git clone https://github.com/kulukami/clamav.git
cd clamav
git checkout rel/0.104

rm -rf  ./build/* &> /dev/null
mkdir build &> /dev/null
cd -
export CLAMAV_DEPENDENCIES="$(pwd)/clamav-mussels-cookbook/mussels/install/" 

cd clamav/build 

cmake .. -G Ninja                                                      \
    -DCMAKE_BUILD_TYPE="RelWithDebInfo"                                       \
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
    -DMAINTAINER_MODE=ON                                               \
    -DRUST_COMPILER_TARGET="x86_64-unknown-linux-gnu"                  \
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

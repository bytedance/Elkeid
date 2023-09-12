export VCPKG_DEFAULT_TRIPLET="arm64-linux-static"
export RUSTC_TARGET="aarch64-unknown-linux-gnu"
export TARGET_ARCH="arm64"
export VCPKG_FORCE_SYSTEM_BINARIES=0
sudo apt-get install g++ gcc -y

rustup target add $RUSTC_TARGET

git clone https://github.com/kulukami/vcpkg.git
export VCPKG_ROOT="$(pwd)/vcpkg"
export VCPKG_INSTALLATION_ROOT="$(pwd)/vcpkg"

bash ./vcpkg/bootstrap-vcpkg.sh

$VCPKG_ROOT/vcpkg install \
openssl:$VCPKG_DEFAULT_TRIPLET \
json-c:$VCPKG_DEFAULT_TRIPLET \
pcre2:$VCPKG_DEFAULT_TRIPLET \
zlib:$VCPKG_DEFAULT_TRIPLET \
bzip2:$VCPKG_DEFAULT_TRIPLET \
libiconv:$VCPKG_DEFAULT_TRIPLET \
libxml2:$VCPKG_DEFAULT_TRIPLET 

export VCPKG_INSTALL_PATH="$VCPKG_ROOT/installed/$VCPKG_DEFAULT_TRIPLET"

git clone https://github.com/kulukami/clamav -b  rel/1.1_yara_hit

cd clamav
mkdir build
cd build
cmake .. \
  -D CMAKE_TOOLCHAIN_FILE="$VCPKG_ROOT/scripts/buildsystems/vcpkg.cmake" \
  -D VCPKG_TARGET_TRIPLET="$VCPKG_DEFAULT_TRIPLET"                       \
  -D VCPKG_TARGET_ARCHITECTURE="$TARGET_ARCH"                            \
  -D RUST_COMPILER_TARGET="$RUSTC_TARGET"                                \
  -D ENABLE_TESTS=OFF                                                    \
  -D ENABLE_STATIC_LIB=ON                                                \
  -D ENABLE_LIBCLAMAV_ONLY=ON                                            \
  -D ENABLE_SYSTEMD=OFF                                                  \
  -D ENABLE_SHARED_LIB=OFF                                               \
  -D BYTECODE_RUNTIME=none                                               \
  -D ENABLE_UNRAR=ON                                                     \
  -D ENABLE_FUZZ=OFF                                                     \
  -D ENABLE_APP=OFF                                                      \
  -D ENABLE_CLAMONACC=OFF                                                \
  -D ENABLE_MILTER=OFF                                                   \
  -D ENABLE_MAN_PAGES=OFF                                                \
  -D CMAKE_INSTALL_PREFIX="install"

cmake --build . --config Release --target install -j2

cd ../..

rm -rf lib || true
mkdir lib

cp clamav/build/libclamav/libclamav_static.a ./lib
cp clamav/build/libclammspack/libclammspack_static.a ./lib
cp clamav/build/libclamunrar/libclamunrar_static.a ./lib
cp clamav/build/libclamunrar_iface/libclamunrar_iface_static.a ./lib
cp clamav/build/$RUSTC_TARGET/release/libclamav_rust.a ./lib
cp clamav/build/*.a ./lib

cp $VCPKG_ROOT/installed/$VCPKG_DEFAULT_TRIPLET/lib/*.a ./lib

rm -rf ./include/* || true
mkdir include 
cp clamav/build/*.h ./include
cp clamav/libclamav/clamav.h ./include
cp clamav/libclamav/matcher.h ./include
cp clamav/libclamav/matcher-ac.h ./include
cp clamav/libclamav/others.h ./include
cp -r $VCPKG_ROOT/installed/$VCPKG_DEFAULT_TRIPLET/include/* ./include

mkdir output
mv include output
mv lib output
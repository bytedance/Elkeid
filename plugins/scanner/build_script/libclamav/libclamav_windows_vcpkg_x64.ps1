$VCPKG_DEFAULT_TRIPLET="x64-windows-static"
$RUSTC_TARGET="x86_64-pc-windows-msvc"
$TARGET_ARCH="x64"

rustup target add $RUSTC_TARGET
$env:VCPKG_DEFAULT_TRIPLET=$VCPKG_DEFAULT_TRIPLET

vcpkg install `
curl[openssl]:$VCPKG_DEFAULT_TRIPLET `
json-c:$VCPKG_DEFAULT_TRIPLET `
libxml2:$VCPKG_DEFAULT_TRIPLET `
pcre2:$VCPKG_DEFAULT_TRIPLET `
pthreads:$VCPKG_DEFAULT_TRIPLET `
zlib:$VCPKG_DEFAULT_TRIPLET `
pdcurses:$VCPKG_DEFAULT_TRIPLET  `
bzip2:$VCPKG_DEFAULT_TRIPLET `
check:$VCPKG_DEFAULT_TRIPLET

$VCPKG_ROOT="C:\vcpkg"
$VCPKG_INSTALL_PATH="$VCPKG_ROOT\installed\$VCPKG_DEFAULT_TRIPLET"
$env:VCPKG_INSTALL_PATH="$VCPKG_INSTALL_PATH"
$env:VCPKGRS_DYNAMIC=0

git clone https://github.com/kulukami/clamav -b rel/1.1_yara_hit

cd clamav
mkdir build
cd build
cmake .. -A x64 `
  -D CMAKE_TOOLCHAIN_FILE="$VCPKG_ROOT\scripts\buildsystems\vcpkg.cmake" `
  -D VCPKG_TARGET_TRIPLET="$VCPKG_DEFAULT_TRIPLET"                       `
  -D VCPKG_TARGET_ARCHITECTURE="$TARGET_ARCH"                            `
  -D RUST_COMPILER_TARGET="$RUSTC_TARGET"                                `
  -D CMAKE_MSVC_RUNTIME_LIBRARY=MultiThreaded                            `
  -D ENABLE_TESTS=OFF                                                    `
  -D ENABLE_STATIC_LIB=ON                                                `
  -D ENABLE_LIBCLAMAV_ONLY=ON                                            `
  -D ENABLE_SYSTEMD=OFF                                                  `
  -D ENABLE_SHARED_LIB=OFF                                               `
  -D BYTECODE_RUNTIME=none                                               `
  -D ENABLE_UNRAR=ON                                                     `
  -D ENABLE_FUZZ=OFF                                                     `
  -D ENABLE_APP=OFF                                                      `
  -D ENABLE_CLAMONACC=OFF                                                `
  -D ENABLE_MILTER=OFF                                                   `
  -D ENABLE_MAN_PAGES=OFF                                                `
  -D CMAKE_INSTALL_PREFIX="install"


cmake --build . --config Release --target install -j2


cd ../..
mkdir lib
cp clamav\build\libclamav\Release\libclamav_static.lib .\lib
cp clamav\build\libclammspack\Release\libclammspack_static.lib .\lib
cp clamav\build\libclamunrar\Release\libclamunrar_static.lib .\lib
cp clamav\build\libclamunrar_iface\Release\libclamunrar_iface_static.lib .\lib
cp clamav\build\win32\compat\Release\libwin32_compat.lib .\lib
cp clamav\build\install\*.dll .\lib
cp clamav\build\install\*.lib .\lib
cp $VCPKG_INSTALL_PATH\lib\*.lib .\lib

mkdir include 
cp clamav\libclamav\clamav.h .\include
cp clamav\libclamav\matcher.h .\include
cp clamav\libclamav\matcher-ac.h .\include
cp clamav\libclamav\others.h .\include
cp clamav\build\install\include\*.h .\include
cp -r C:\vcpkg\installed\x64-windows-static\include\* .\include

mkdir output
mv include output
mv lib output
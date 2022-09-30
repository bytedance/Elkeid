
#!/bin/bash


if [[ -z ${STDLIBCXX_STATIC_PATH} ]]; then
    echo 'please export STDLIBCXX_STATIC_PATH="/path/to/libstdc++.a"'
    exit -1
fi

if [[ -z ${TARGET_ARCH} ]]; then
    echo "TARGET_ARCH set to x86_64"
    TARGET_ARCH="x86_64"
else
    echo "TARGET_ARCH set to $TARGET_ARCH"
    sed -i "s/x86_64/$TARGET_ARCH/gi" .cargo/config.toml
    sed -i "s/x86_64/$TARGET_ARCH/gi" build.rs
fi

./get_deps.sh
./libclamav.sh

rm -rf output/* &> /dev/null
mkdir output &> /dev/null

# build plugin
CC="$TARGET_ARCH-linux-musl-gcc" CXX="$TARGET_ARCH-linux-musl-c++" RUSTFLAGS='-C target-feature=+crt-static' cargo build --release --bin scanner_plugin --target $TARGET_ARCH-unknown-linux-musl


if [ $? -ne 0 ]; then
    echo "etrace cli build failed"
    exit -1
else
    echo "etrace cli build succeed"
fi

cp  target/$TARGET_ARCH-unknown-linux-musl/release/scanner_plugin  ./output/scanner
strip ./output/scanner

# build cli
CC="$TARGET_ARCH-linux-musl-gcc" CXX="$TARGET_ARCH-linux-musl-c++" RUSTFLAGS='-C target-feature=+crt-static'  cargo build --release --bin scanner_cli --target $TARGET_ARCH-unknown-linux-musl

if [ $? -ne 0 ]; then
    echo "etrace cli build failed"
    exit -1
else
    echo "etrace cli build succeed"
fi

cp  target/$TARGET_ARCH-unknown-linux-musl/release/scanner_cli  ./output/scanner_cli
strip ./output/scanner_cli

cp -r tools/* ./output/.


cd ./output 
mkdir tmp 
wget http://lf9-elkeid.bytetos.com/obj/elkeid-download/18249e0cbe7c6aca231f047cb31d753fa4604434fcb79f484ea477f6009303c3/archive_db_default_20220930.zip
mv archive_db_default_20220930.zip ./tmp
tar zcvf scanner-$TARGET_ARCH.tar.gz scanner tmp elkeid_targets

cd - 



#!/bin/bash

if [[ -z ${STDLIBCXX_STATIC_PATH} ]]; then
    echo 'please export STDLIBCXX_STATIC_PATH="/path/to/libstdc++.a"'
    exit -1
fi

./get_deps.sh
./libclamav.sh

rm -rf output/* &> /dev/null
mkdir output &> /dev/null

# build plugin
RUSTFLAGS='-C target-feature=+crt-static ' cargo build --release --bin scanner_plugin --target x86_64-unknown-linux-gnu

if [ $? -ne 0 ]; then
    echo "etrace cli build failed"
    exit -1
else
    echo "etrace cli build succeed"
fi

cp  target/x86_64-unknown-linux-gnu/release/scanner_plugin  ./output/scanner_clamav
strip ./output/scanner_clamav

# build cli
RUSTFLAGS='-C target-feature=+crt-static ' cargo build --release --bin scanner_cli --target x86_64-unknown-linux-gnu

if [ $? -ne 0 ]; then
    echo "etrace cli build failed"
    exit -1
else
    echo "etrace cli build succeed"
fi

cp  target/x86_64-unknown-linux-gnu/release/scanner_cli  ./output/scanner_clamav_cli
strip ./output/scanner_clamav_cli

cd ./output 
mkdir tmp 
wget http://lf9-elkeid.bytetos.com/obj/elkeid-download/18249e0cbe7c6aca231f047cb31d753fa4604434fcb79f484ea477f6009303c3/archive_db_default.zip
mv archive_db_default.zip ./tmp
tar zcvf scanner_clamav.tar.gz scanner_clamav tmp
cd - 


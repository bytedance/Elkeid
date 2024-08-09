#!/bin/bash

cd /Elkeid/plugins/scanner
rm -rf clamav clamav-mussels-cookbook lib include

mv /LibClamavDocker/clamav .
mv /LibClamavDocker/clamav-mussels-cookbook .
mv /LibClamavDocker/lib .
mv /LibClamavDocker/include .
rustup target add aarch64-unknown-linux-musl

CC="aarch64-linux-musl-gcc" CXX="aarch64-linux-musl-c++" RUSTFLAGS='-C target-feature=+crt-static' cargo build --release --bin scanner_plugin --target aarch64-unknown-linux-musl

mkdir -p output/tmp
cp -r tools/* ./output/.
cp settings.toml ./output/.

cp target/aarch64-unknown-linux-musl/release/scanner_plugin output/scanner
strip output/scanner

wget http://lf9-elkeid.bytetos.com/obj/elkeid-download/18249e0cbe7c6aca231f047cb31d753fa4604434fcb79f484ea477f6009303c3/archive_db_default_20221206.zip
mv archive_db_default_20221206.zip ./output/tmp

cd output && tar zcvf scanner-aarch64.tar.gz scanner tmp elkeid_targets settings.toml && cd -
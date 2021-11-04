English | [简体中文](README-zh_CN.md)
## About Yara Scanner Plugin
Yara Scanner is a Elkied plugin for scanning static files (using yara rules).


## Supported Platforms
Same as [Elkeid Agent](../README.md#supported-platforms).


Reasons for not providing static link based on musl-libc : Seen Known Errors & Bugs

## Config
In `config.rs`, there are the following constants. In order to avoid occupying too much system resources, it is recommended to use the default parameters.

### Plugin Config
```
const SOCKET_PATH:&str = ../../plugin.sock";
const NAME:&str = "scanner";
const VERSION:&str = "0.0.0.0";
```
These can be configured as required, but remember those constants need to be consistent with the [agent's parameters ](../README.md#parameters-and-options) and [agent's config.yaml](../README.md#config-file).

### Scan config
* `SCAN_DIR_CONFIG` define the scan directory list and recursion depth
* `SCAN_DIR_FILTER` define the filter directory list matched by prefix

### Performance limit config
* `LOAD_MMAP_MAX_SIZE` define the maximum file size of scanned files (skip large files)
* `WAIT_INTERVAL_DAILY` define the interval of each round of scanning
* `WAIT_INTERVAL_DIR_SCAN` define the interval between scanning directories
* `WAIT_INTERVAL_PROC_SCAN` define the interval between scanning processes


### [Yara Rules](https://yara.readthedocs.io/en/stable/writingrules.html)
`RULES_SET` define the yara rule string.

Current rules for reference:
* UPX-elf
* miner stratum elf/script
* suspicious script


More Yara rules [Ref](https://github.com/InQuest/awesome-yara)
* https://github.com/godaddy/yara-rules
* https://github.com/Yara-Rules/rules
* https://github.com/fireeye/red_team_tool_countermeasures
* https://github.com/x64dbg/yarasigs
...


## Compilation Environment Requirements

* Requirements
```bash
llvm
musl-gcc
libclang >= 3.9 (requried by rust-bindgen)
gcc >= 6.3 (suggested gcc 6.3.0 which is the default version in debian 9)
```

* Build-essential
```bash
# debian & ubuntu
apt-get install build-essential clang llvm
# centos & rhel
yum groupinstall "Development Tools" && yum install clang llvm
```
Optional - [musl tool-chain](https://www.musl-libc.org/how.html)

* Rust 1.56 +

Please install [rust](https://www.rust-lang.org/tools/install) environment:
```
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
# add build target x86_64-unknown-linux-gnu
rustup target add x86_64-unknown-linux-gnu

# add build target x86_64-unknown-linux-musl
rustup target add x86_64-unknown-linux-musl
```

## Building
Just run:
```
chmod +x build.sh && ./build.sh
```
or
```
RUSTFLAGS='-C target-feature=+crt-static' cargo build --release --target x86_64-unknown-linux-gnu
```
You will find the scanner binary file under `target/x86_64-unknown-linux-gnu/release/`.


musl style:
```
cargo build --release --target x86_64-unknown-linux-musl
```
You will find the scanner binary file under `target/x86_64-unknown-linux-musl/release/`.


## check static binary

```
ldd ./target/x86_64-unknown-linux-gnu/release/scanner
#output
   not a dynamic executable
```

## Pre-compiled binary

sha256 = e216470f52601b5268b248e4bb60e2f6b0e8b0a86bd18a799057461526c81a4b

```bash
"https://lf3-elkeid.bytetos.com/obj/elkeid-download/plugin/scanner/scanner-0.0.0.2.pkg",
"https://lf6-elkeid.bytetos.com/obj/elkeid-download/plugin/scanner/scanner-0.0.0.2.pkg",
"https://lf9-elkeid.bytetos.com/obj/elkeid-download/plugin/scanner/scanner-0.0.0.2.pkg",
"https://lf26-elkeid.bytetos.com/obj/elkeid-download/plugin/scanner/scanner-0.0.0.2.pkg"
```

## Known Errors & Bugs
* Creation time / birth_time is not available for some filesystems
```bash
error: "creation time is not available for the filesystem
```
* Centos7 default compile tool-chains didn't work,  high version of tool-chains needed.

## License
Yara Scanner Plugin is distributed under the Apache-2.0 license.

English | [简体中文](README-zh_CN.md)
## About Driver Plugin
The Driver Plugin is used to manage the kernel module (install/uninstall/update).

It can receive and parse the data from the kernel module, enrich the data flow, and then forward it to the Agent.

## Supported Platforms
Same as [ByteDance-HIDS Agent](../README.md#supported-platforms)

## Compilation Environment Requirements
* Rust 1.48.0

Please Install [rust](https://www.rust-lang.org/tools/install) environment:
```
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

## Building
Just run:
```
make build
```
or
```
cargo build --release
```
You will find the driver binary file under `target/release/`.

If you want to get a fully statically linked binary plugin (easier to distribute), do the following:
```
make build-musl
```
or
```
cargo build --release --target x86_64-unknown-linux-musl
```
You will find the driver binary file under `target/x86_64-unknown-linux-musl/release/`.

For details, please refer to:
https://doc.rust-lang.org/edition-guide/rust-2018/platform-and-target-support/musl-support-for-fully-static-binaries.html

## Template Generation
According to the [data definition in Driver](../../driver), we use code generation to build parser. The structures is defined in the [template.toml](template.toml).

The `metadata` field defines the [LKM](../../driver) version and the maintenance members of this template. The `config` field defines the download address of the ko distribution (if needed), the pipe path of the [LKM](../../driver), the name of the ko file to be managed, and the socket path of the Agent.

Please note: The socket path must be consistent with the [parameters in the Agent](../README.md#parameters-and-options).

The `structures` field describes various data types, please modify as needed. For more details, please refer to:https://github.com/toml-lang/toml

## Distribute ko
You can put ko files of different kernel versions on a file server for easy distribution. Please rename each ko file according to the following requirements:

The file name consists of three parts: `NAME-VERSION-KERNEL_VERSION.ko`.

`NAME` needs to be consistent with the `config.name` field in `template.toml`, `VERSION` and `config.version` fields should be consistent (that is, the [LKM](../../driver) version), and `KERNEL_VERSION` should be consistent with `uname -r`.

In addition, for each ko file, a text file named `NAME-VERSION-KERNEL_VERSION.sha256` should be uploaded together, which contains the `sha256` hex encoding value of the `NAME-VERSION-KERNEL_VERSION.ko` file. E.g:
```
cat hids_driver-1.0.0.0-4.14-amd64.sha256
3ca9eb8143e99fac18a50613247cadb900ba79bf6f7d9a073b61e4ab303d3635
```
Finally, set your file server address in the `config.ko_url` ist (there can be multiple addresses), so that when the plugin starts, the ko file that is compatible with the [LKM](../../driver) and kernel version will be automatically downloaded.

## License
Driver Plugin are distributed under the Apache-2.0 license.

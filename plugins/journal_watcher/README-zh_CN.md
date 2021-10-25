[English](README.md) | 简体中文
## 关于Journal Watcher插件
Journal Wacher是一个用来监视systemd日志的插件。当前插件会解析并产生ssh相关的事件，这些事件可以用来监视不正常的登陆行为，例如ssh暴力破解或者krb5的不正常登陆等。

## 平台兼容性
与[Elkeid Agent](../README-zh_CN.md#平台兼容性)相同，请确保机器日志服务是由`systemd-journald`托管。


## 需要的编译环境
* Rust 1.48.0

快速安装 [rust](https://www.rust-lang.org/tools/install) 环境：
```
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

## 编译
执行以下命令:
```
make build
```
或者：
```
cargo build --release
```
你将会在`target/release/`下面找到`journal_watcher`二进制文件。

如果你想获得完全静态链接的二进制文件(更易于分发)，执行以下命令：
```
make build-musl
```
或者：
```
cargo build --release --target x86_64-unknown-linux-musl
```
你将会在`target/x86_64-unknown-linux-musl/release/`下面找到`journal_watcher`二进制文件。

详情请查阅：
https://doc.rust-lang.org/edition-guide/rust-2018/platform-and-target-support/musl-support-for-fully-static-binaries.html

## License
journal_watcher plugin is distributed under the Apache-2.0 license.

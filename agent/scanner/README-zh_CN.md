[English](README.md) | 简体中文
## 关于 Yara Scanner 插件
Yara Scanner 使用 [yara 规则](https://yara.readthedocs.io/)对系统进程和敏感目录进行周期扫描，并使用fanotify监控敏感目录文件变动，以发现可疑静态文件（UPX/挖矿二进制/挖矿脚本/可疑脚本文件/...）。

## 平台兼容性
与[Elkeid Agent](../README-zh_CN.md#平台兼容性)相同。


## 配置
在[config.rs](./src/config.rs)中,有下面一些常量，可根据实际情况进行配置（出于性能考虑，除规则外，建议保持默认）。

### 插件配置
```
const SOCKET_PATH:&str = ../../plugin.sock";
const NAME:&str = "scanner";
const VERSION:&str = "0.0.0.0";
```
这些常量可以根据需要进行修改，但是要注意：他们需要与[Agent参数](../README-zh_CN.md#参数和选项)以及[Agent的配置文件](../README-zh_CN.md#配置文件)保持一致。

### 扫描配置
* `SCAN_DIR_CONFIG` 定义扫描目录，以及递归深度
* `SCAN_DIR_FILTER` 定义过滤目录，按照前缀匹配过滤扫描白名单

### 性能限制配置
* `LOAD_MMAP_MAX_SIZE` 定义扫描的文件的最大文件大小，跳过大文件
* `WAIT_INTERVAL_DAILY` 定义周期扫描每轮的间隔时间
* `WAIT_INTERVAL_DIR_SCAN` 定义周期扫描目录的间隔时间
* `WAIT_INTERVAL_PROC_SCAN` 定义周期扫描proc进程的间隔时间


### [Yara 扫描规则](https://yara.readthedocs.io/en/stable/writingrules.html)
配置`RULES_SET`定义Yara扫描规则
目前提供参考的规则:
* UPX 带壳elf
* 存在挖矿通信协议的elf/脚本
* 可疑的脚本文件


更多Yara规则可[参考](https://github.com/InQuest/awesome-yara)
* https://github.com/godaddy/yara-rules
* https://github.com/Yara-Rules/rules
* https://github.com/fireeye/red_team_tool_countermeasures
* https://github.com/x64dbg/yarasigs
...


## 需要的编译环境

* Requirements
```bash
llvm
musl-gcc
libclang >= 3.9 (requried by rust-bindgen)
gcc >= 6.3 (suggested gcc 6.3.0 which is the default version in debian 9)
```
Optional - [musl tool-chain](https://www.musl-libc.org/how.html)

* Build-essential
```bash
# debian & ubuntu
apt-get install build-essential clang llvm musl-tools llvm-dev
# centos & rhel
yum groupinstall "Development Tools" && yum install clang llvm
```


* Rust 1.56 +

快速安装 [rust](https://www.rust-lang.org/tools/install) 环境：
```
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# add build target x86_64-unknown-linux-gnu
rustup target add x86_64-unknown-linux-gnu

# add build target x86_64-unknown-linux-musl
rustup target add x86_64-unknown-linux-musl

```

## 编译
方式1:执行以下命令:
```
chmod +x build.sh && ./build.sh
```
或者：
```
RUSTFLAGS='-C target-feature=+crt-static' cargo build --release --target x86_64-unknown-linux-gnu
```
你将会在`target/x86_64-unknown-linux-gnu/release/`下面找到`scanner`二进制文件。静态链接的二进制文件(更易于分发)。



方式2:执行以下命令:
```
cargo build --release --target x86_64-unknown-linux-musl
```
你将会在`target/x86_64-unknown-linux-musl/release/`下面找到`scanner`二进制文件。静态链接的二进制文件(更易于分发)。


## 检查
如果检查结果为动态链接的可执行文件，则非预期，请检查编译链
```
ldd ./target/x86_64-unknown-linux-gnu/release/scanner
#output
   not a dynamic executable
```


## 预编译产物

sha256 = e216470f52601b5268b248e4bb60e2f6b0e8b0a86bd18a799057461526c81a4b

```bash
"https://lf3-elkeid.bytetos.com/obj/elkeid-download/plugin/scanner/scanner-0.0.0.2.pkg",
"https://lf6-elkeid.bytetos.com/obj/elkeid-download/plugin/scanner/scanner-0.0.0.2.pkg",
"https://lf9-elkeid.bytetos.com/obj/elkeid-download/plugin/scanner/scanner-0.0.0.2.pkg",
"https://lf26-elkeid.bytetos.com/obj/elkeid-download/plugin/scanner/scanner-0.0.0.2.pkg"
```


## 已知问题
* Creation time / birth_time is not available for some filesystems
```bash
error: "creation time is not available for the filesystem
```
* Centos7 default compile tool-chains didn't work,  high version of tool-chains needed.


## License
Yara Scanner plugin is distributed under the Apache-2.0 license.

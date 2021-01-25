[English](README.md) | 简体中文
## 关于Journal Watcher插件
Journal Wacher是一个用来监视systemd日志的插件。当前插件会解析并产生ssh相关的事件，这些事件可以用来监视不正常的登陆行为，例如ssh暴力破解或者krb5的不正常登陆等。

## 平台兼容性
与[AgentSmith-HIDS Agent](../README-zh_CN.md#平台兼容性)相同。

但是请注意：这个插件是基于libsystemd进行开发的，请确保在你的环境中能找到`libsystemd.so`。

不提供基于musl-libc静态链接的原因：

libsystemd中用到了大量glibc特有的函数，这导致移植到musl-libc十分困难，如果你有好的想法请随时联系我们。


## 需要的编译环境
* Rust 1.48.0

快速安装 [rust](https://www.rust-lang.org/tools/install) 环境：
```
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

## 编译
执行以下命令：
```
make build
```
或者：
```
cargo build --release
```
你将会在`target/release/`下面找到`journal_watcher`二进制文件。

## 配置
在[main.rs](./src/main.rs)中,有下面几个常量：
```
const AGENT_SOCK_PATH:&str = "/etc/hids/plugin.sock";
const PLUGIN_NAME:&str = "journal_watcher";
const PLUGIN_VERSION:&str = "1.0.0.0";
```
这些常量可以根据需要进行修改，但是要注意：他们需要与[Agent参数](../README-zh_CN.md#参数和选项)以及[Agent的配置文件](../README-zh_CN.md#配置文件)保持一致。

## License
Journal Watcher Plugin are distributed under the LGPL-2.1 license.

[English](README.md) | 简体中文
## 关于Driver插件
Driver Plugin用于管理内核模块(安装/卸载/升级)。它可以接收并解析来自内核模块的数据，并将其进一步丰富，然后将数据转发给Agent。


## 平台兼容性
与[ByteDance-HIDS Agent](../README-zh_CN.md#平台兼容性)相同。

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
你将会在`target/release/`下面找到`driver`二进制文件。

如果你想获得完全静态链接的二进制文件(更易于分发)，执行以下命令：
```
make build-musl
```
或者：
```
cargo build --release --target x86_64-unknown-linux-musl
```
你将会在`target/x86_64-unknown-linux-musl/release/`下面找到`driver`二进制文件。

详情请查阅：
https://doc.rust-lang.org/edition-guide/rust-2018/platform-and-target-support/musl-support-for-fully-static-binaries.html

## 模版生成
根据[Driver中的数据定义](../../driver)，我们使用代码生成实现了解析器，模版数据的结构被定义在[template.toml](template.toml)。

`metadata`字段定义了[LKM](../../driver)的版本与这个模版的维护者；

`config`由如下几个配置项组成：`ko_url`定义了ko的分发下载地址(如果需要的话)；`pipe_path`字段定义了[LKM](../../driver)的pipe文件路径；`name`字段定义了所要管理的ko文件的名字；`socket_path`定义了与Agent通信的Socket地址。请注意：`socket_path`必须与[Agent中的相应参数](../README-zh_CN.md#参数和选项)保持一致。


`structures` 字段描述了不同的数据类型，请根据需要进行修改。关于`toml`文件的详细信息，请参阅：https://github.com/toml-lang/toml

## 分发 ko
你可以将不同内核版本的ko文件放在文件服务器上以方便分发。请按照如下要求对ko文件进行命名：

文件名应该由三部分组成： `NAME-VERSION-KERNEL_VERSION.ko`。

`NAME`应该与`template.toml`中的`config.name`字段保持一致。

`VERSION`应该与`config.version`字段保持一致(也就是[LKM](../../driver)的版本)。

`KERNEL_VERSION`应该与`uname -r`保持一致。

除此之外，对于每个ko文件都应该与一个命名为`NAME-VERSION-KERNEL_VERSION.sha256`的文本文件一起上传，这个文件中包含着`NAME-VERSION-KERNEL_VERSION.ko`文件的`sha256`字符串(经过hex编码)。例如：
```
cat hids_driver-1.0.0.0-4.14-amd64.sha256
3ca9eb8143e99fac18a50613247cadb900ba79bf6f7d9a073b61e4ab303d3635
```
最后，将你的文件服务器地址填入到`config.ko_url`列表中(可以有多个)。这样当插件启动时，与当前插件和内核版本保持一致的ko文件将会被自动下载。

## License
Driver Plugin are distributed under the Apache-2.0 license.

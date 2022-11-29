[English](README.md) | 简体中文
## 关于Journal Watcher插件
Journal Watcher 通过读取 sshd 的日志，并进行解析，生成sshd登陆、gssapi事件。
## 运行时要求
支持主流的Linux发行版，包括CentOS、RHEL、Debian、Ubuntu、RockyLinux、OpenSUSE等。支持x86-64与aarch64架构。
## 快速开始
通过 [elkeidup](../../elkeidup) 的完整部署，此插件默认开启。
## 手动编译
### 环境要求
* [Rust](https://www.rust-lang.org) >= 1.48.0
* [Rust x86_64-unknown-linux-musl aarch64-unknown-linux-musl 编译链](https://doc.bccnsoft.com/docs/rust-1.36.0-docs-html/edition-guide/rust-2018/platform-and-target-support/musl-support-for-fully-static-binaries.html)
* [musl-gcc](https://command-not-found.com/musl-gcc)
### 编译
在根目录，执行：
```
BUILD_VERSION=1.7.0.23 bash build.sh
```
在编译过程中，脚本会读取 `BUILD_VERSION` 环境变量设置版本信息，可根据实际需要进行修改。

编译成功后，在根目录的 `output` 目录下，应该可以看到2个plg文件，它们分别对应不同的系统架构。
### 版本升级
1. 如果没有创建过客户端类型的组件，请在 [Elkeid Console - 组件管理]() 界面新建对应组件。
2. 在 [Elkeid Console - 组件管理]() 界面，找到“journal_watcher”条目，点击右侧“发布版本”，填写版本信息并上传对应平台与架构的文件，点击确认。
3. 在 [Elkeid Console - 组件策略]() 界面，(如有)删除旧的“journal_watcher”版本策略，点击“新建策略”，选中刚刚发布的版本，点击确认。后续新安装的Agent的插件均会自升级到最新版本。
4. 在 [Elkeid Console - 任务管理]() 界面，点击“新建任务”，选择全部主机，点击下一步，选择“同步配置”任务类型，点击确认。随后，在此页面找到刚刚创建的任务，点击运行，即可对存量旧版本插件进行升级。
## License
journal_watcher plugin is distributed under the Apache-2.0 license.
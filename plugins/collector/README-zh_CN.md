[![License](https://img.shields.io/badge/License-Apache%20v2-blue.svg)](https://github.com/bytedance/Elkeid/blob/main/agent/LICENSE)
[![Project Status: Active – The project has reached a stable, usable state and is being actively developed.](https://www.repostatus.org/badges/latest/active.svg)](https://www.repostatus.org/#active)

[English](README.md) | 简体中文
## 关于collector插件
collector周期性采集主机上的各类资产信息，并进行关联分析，目前支持以下资产类型：
- 进程：支持对exe md5的哈希计算，后续可关联威胁情报分析，另外与容器信息进行关联，支撑后续数据溯源功能。(跨容器)
- 端口：支持tcp、udp监听端口的信息提取，以及与进程、容器信息的关联上报。另外基于sock状态及其关系，分析对外暴露服务，向上支撑主机暴露面分析功能。(跨容器)
- 账户：除了基本的账户字段外，基于弱口令字典进行端上hash碰撞检测弱口令，向上提供了Console的弱口令基线检测功能。另外，会关联分析sudoers配置，一同上报。
- 软件：支持系统软件包、pypi包、jar包，向上支撑漏洞扫描功能。(部分跨容器)
- 容器：支持docker、cri/containerd等多种运行时下的容器信息采集。
- 应用：支持数据库、消息队列、容器组件、Web服务、DevOps工具等类型的应用采集、目前支持30+中常见应用的版本、配置文件的匹配与提取。(跨容器)
- 硬件：支持网卡、磁盘等硬件信息的采集。
- 系统完整性校验：通过将软件包文件哈希与Host实际文件哈希进行对比，判断文件是否有被更改。
- 内核模块：采集基本字段，以及内存地址、依赖关系等额外字段。
- 系统服务、定时任务：兼容不同发行版下的服务及cron位置的定义，并对核心字段进行解析。
## 运行时要求
支持主流的Linux发行版，包括CentOS、RHEL、Debian、Ubuntu、RockyLinux、OpenSUSE等。支持x86-64与aarch64架构。
## 快速开始
通过 [elkeidup](../../elkeidup/README-zh_CN.md) 的完整部署，此插件默认开启。
## 手动编译
### 环境要求
* [Go](https://go.dev/) >= 1.18
### 编译
在Agent根目录，执行：
```
BUILD_VERSION=1.7.0.140 bash build.sh
```
在编译过程中，脚本会读取 `BUILD_VERSION` 环境变量设置版本信息，可根据实际需要进行修改。

编译成功后，在根目录的 `output` 目录下，应该可以看到2个deb与2个rpm文件，它们分别对应不同的系统架构。
## 版本升级
1. 如果没有创建过客户端类型的组件，请在 [Elkeid Console-组件管理](../../server/docs/console_tutorial/Elkeid_Console_manual.md#组件管理) 界面新建对应组件。
2. 在 [Elkeid Console - 组件管理](../../server/docs/console_tutorial/Elkeid_Console_manual.md#组件管理) 界面，找到“collector”条目，点击右侧“发布版本”，填写版本信息并上传对应平台与架构的文件，点击确认。
3. 在 [Elkeid Console - 组件策略](../../server/docs/console_tutorial/Elkeid_Console_manual.md#组件策略) 界面，(如有)删除旧的“collector”版本策略，点击“新建策略”，选中刚刚发布的版本，点击确认。后续新安装的Agent的插件均会自升级到最新版本。
4. 在 [Elkeid Console - 任务管理](../../server/docs/console_tutorial/Elkeid_Console_manual.md#任务管理) 界面，点击“新建任务”，选择全部主机，点击下一步，选择“同步配置”任务类型，点击确认。随后，在此页面找到刚刚创建的任务，点击运行，即可对存量旧版本插件进行升级。
## License
collector is distributed under the Apache-2.0 license.

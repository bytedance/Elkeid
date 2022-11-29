[![License](https://img.shields.io/badge/License-Apache%20v2-blue.svg)](https://github.com/bytedance/Elkeid/blob/main/agent/LICENSE)
[![Project Status: Active – The project has reached a stable, usable state and is being actively developed.](https://www.repostatus.org/badges/latest/active.svg)](https://www.repostatus.org/#active)

[English](README.md) | 简体中文
## 关于 Elkeid Agent
Agent提供端上组件的基本能力支撑，包括数据通信、资源监控、组件版本控制、文件传输、机器基础信息采集等。

Agent本身不提供安全能力，作为一个插件底座以系统服务的方式运行。各类功能插件的策略存放于服务器端的配置，Agent接收到相应的控制指令及配置后对自身及插件进行开启、关闭、升级等操作。

Agent与Server之间采用bi-stream gRPC进行通信，基于自签名证书开启双向TLS验证，保障信道安全。其中，Agent -> Server 方向信息流动称为数据流，Server -> Agent 方向信息流动一般为控制流，使用protobuf的不同message类型。Agent本身支持客户端侧服务发现，也支持跨Region级别的通信配置，实现一个Agent包在多个网络隔离的环境下进行安装，基于底层一个TCP连接，在上层实现了Transfer与FileOp两种数据传输服务，支撑了插件本身的数据上报与Host中的文件交互。

Plugins作为安全能力插件，与Agent的进程关系一般为“父——子”进程。以两个pipe作为跨进程通信方式，[plugins](../plugins/lib) lib提供了Go与Rust的两个插件库，负责插件端信息的编码与发送。值得一提的是，插件发送数据后，会被编码为Protobuf二进制数据，Agent接收到后无需二次解编码，再其外层拼接好Header特征数据，直接传输给Server，一般情况下Server也无需解码，直接传输至后续数据流中，使用时进行解码，一定程度上降低了数据传输中多次编解码造成的额外性能开销。

Agent采用Go实现，在Linux下，通过systemd作为守护方式，受cgroup限制控制资源使用，支持aarch64与x86-64架构，最终编译、打包为deb与rpm包分发，格式均符合systemd及Debian、RHEL规范，可以直接提供至对应的软件仓库中进行后续版本维护。在后续版本中，将会发布用于Windows平台下的Agent。
## 运行时要求
Agent及Plugin提供的大部分功能需要以root权限运行在宿主机(Host)层面，在权限受限的容器中，部分功能可能会存在异常。
## 快速开始
通过 [elkeidup](../elkeidup/README-zh_CN.md) 的完整部署，可以直接得到用于Debian/RHEL系列发行版的安装包，并按照 [Elkeid Console - 安装配置]() 界面的命令进行安装部署。
## 手动编译
### 环境要求
* [Go](https://go.dev/) >= 1.18
* [nFPM](https://nfpm.goreleaser.com/)
* 成功部署的 [Server](../server/README-zh_CN.md) (包含所有组件)
### 确认相关配置
* 需要确保 `transport/connection` 目录下的 `ca.crt`、`client.key`、`client.crt` 三个文件与Agent Center `conf` 目录下的同名文件保持一致。
* 需要确保 `transport/connection/product.go` 文件中的参数都配置妥当：
    * 如果是手动部署的Server：
        * `serviceDiscoveryHost["default"]` 需被赋值为 [ServiceDiscovery](../server/service_discovery) 服务或代理服务的内网监听地址与端口，例如：`serviceDiscoveryHost["default"] = "192.168.0.1:8088"`
        * `privateHost["default"]` 需被赋值为 [AgentCenter](../server/agent_center) 服务或代理服务的内网监听地址与端口，例如：`privateHost["default"] = "192.168.0.1:6751"`
        * 如有Server的公网接入点，`publicHost["default"]` 需被赋值为 [AgentCenter](../server/agent_center) 服务或代理服务的外网监听地址与端口，例如：`publicHost["default"]="203.0.113.1:6751"`
    * 如果是通过 [elkeidup](../elkeidup/README-zh_CN.md) 部署的Server，可以根据部署Server机器的 `~/.elkeidup/elkeidup_config.yaml` 文件获得对应配置：
        * 在配置文件中找到 Nginx 服务的IP，具体的配置项为 `nginx.sshhost[0].host`
        * 在配置文件中找到 [ServiceDiscovery](../server/service_discovery) 服务的IP，具体的配置项为 `sd.sshhost[0].host`
        * `serviceDiscoveryHost["default"]` 需被赋值为 [ServiceDiscovery](../server/service_discovery) 服务的IP，并将端口号设置为8088，例如：`serviceDiscoveryHost["default"] = "192.168.0.1:8088"`
        * `privateHost["default"]` 需被赋值为 Nginx 服务的IP，并将端口号设置为8090，例如：`privateHost["default"] = "192.168.0.1:8090"`
### 编译
在Agent根目录，执行：
```
BUILD_VERSION=1.7.0.26 bash build.sh
```
在编译过程中，脚本会读取 `BUILD_VERSION` 环境变量设置版本信息，可根据实际需要进行修改。

编译成功后，在根目录的 `output` 目录下，应该可以看到2个deb与2个rpm文件，它们分别对应不同的系统架构。
## 版本升级
1. 如果没有创建过客户端类型的组件，请在 [Elkeid Console-组件管理]() 界面新建对应组件。
2. 在 [Elkeid Console - 组件管理]() 界面，找到“elkeid-agent”条目，点击右侧“发布版本”，填写版本信息并上传对应平台与架构的文件，点击确认。
3. 在 [Elkeid Console - 组件策略]() 界面，(如有)删除旧的“elkeid-agent”版本策略，点击“新建策略”，选中刚刚发布的版本，点击确认。后续新安装的Agent均会自升级到最新版本。
4. 在 [Elkeid Console - 任务管理]() 界面，点击“新建任务”，选择全部主机，点击下一步，选择“同步配置”任务类型，点击确认。随后，在此页面找到刚刚创建的任务，点击运行，即可对存量旧版本Agent进行升级。
## License
Elkeid Agent are distributed under the Apache-2.0 license.

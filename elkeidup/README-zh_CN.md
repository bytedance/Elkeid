# ElkeidUP

[English](README.md) | 简体中文

Elkeid 自动化部署工具

## Component List
[资源配置手册](./configuration.md)

## Instructions

* 部署所用的后端服务器需要仅供Elkeid使用
* 部署所用的后端服务器需要保证内网互通，也仅支持内网部署
* 部署所用的后端服务器部署时需要有 root 用户权限
* 部署所用的后端服务器只能使用：Centos7 及以上；Ubuntu16 及以上；Debian9 及以上
* 执行elkeidup的服务器需要能以root用户免密码ssh到所有的后端服务器上
* 部署过程不可以手动打断
* 仅可以使用局域网IP，不要使用 127.0.0.1 或者 hostname 或者公网IP
* 安装后不要删除 `~/.elkeidup` 目录
* 不要修改任何组件的密码，包括Elkeid Console(Manager)初始默认用户

### 收集信息提示

为了能更好的共建Elkeid开源社区，我们希望可以在您的试用或使用中收集以下必要信息，以便我们了解您的基础运行状况。我们需要参考相关信息制定后续规划，以及给出合理的资源占用评估。
我们会尝试收集且仅收集以下信息，所有收集信息的逻辑和代码均位于已开源的manager中，预编译manager二进制与开源代码一致，您可以重新编译：
1. 缺失预编译ko的内核版本，服务器架构(仅为arm64或amd64二选一，不涉及任何其他cpu机器信息)，仅在driver。
2. agent center上agent的连接数，每30min收集一次。
3. agent center上agent的qps，包含send和receive，每30min收集一次，取30min的平均值。
4. hub input qps，每30min收集一次，取30min的平均值。
5. redis qps，每30min收集一次，取30min的平均值。
6. redis 内存占用，每30min收集一次，实时数值。
7. kafka 生产和消费的qps，每30min收集一次，取30min的平均值。
8. mongodb qps，每30min收集一次，取30min的平均值。

> 如果您不同意收集请求，仅自动下载缺失的预编译ko一项功能无法使用，不影响其他功能。

### Elkeid 完整部署
[Elkeid 完整部署](./deploy.md)

### Elkeid HUB 单独部署
[Elkeid HUB 单独部署](./deploy_hub.md)

## Raw Data Usage Tutorial
- [Elkeid 数据说明](../server/docs/ElkeidData.xlsx)
- [Raw Data Usage Tutorial](raw_data_usage_tutorial/raw_data_usage_tutorial-zh_CN.md)


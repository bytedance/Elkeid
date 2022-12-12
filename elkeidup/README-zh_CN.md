# ElkeidUP

[English](README.md) | 简体中文

Elkeid 自动化部署工具

## Component List
[资源配置手册](./configuration-zh_CN.md)

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

> 注意：由于v1.9.1版本与v1.7之间差异较大，不支持从v1.7直接平滑升级到v1.9.1，可参考[重装指定组件](./deploy-zh_CN.md#5、重装指定组件)。v1.9.1往后的版本都会支持平滑升级。

### 自动下载缺失预编译ko服务开启提示

**服务背景**：
Elkeid Driver是在内核态工作的，由于内核要求加载的内核模块与内核版本强绑定，我们又无法占用客户机的资源在安装agent时在客户机上编译ko。因此，我们在release包中提供了预编译的ko，避免每次都需要手动编译ko，目前共计包含3435个预编译ko。但依旧存在两个问题无法解决，一是无法实时更新，上游发行版更新内核后，我们无法也没有人力同步更新预编译的ko到release中，二是覆盖范围有限，可能会遇见我们未曾使用过的发行版所使用的内核。为此，我们提供了自动下载缺失预编译ko的功能，此功能主要是通知到我们相关同学，该ko有客户在试用，尽快从上游更新或覆盖该发行版。
若您选择同意开启此服务，我们需要同时收集一些基础运行信息，以便我们根据不同需求的用户定制优先级排期，并给出合理的资源占用评估。填写的email信息仅用于区分来源身份，真实email或昵称均可。具体信息如下：
1. 缺失预编译ko的内核版本，服务器架构(仅为arm64或amd64二选一，不涉及任何其他cpu机器信息)。
2. agent center上agent的连接数，每30min收集一次。
3. agent center上agent的qps，包含send和receive，每30min收集一次，取30min的平均值。
4. hub input qps，每30min收集一次，取30min的平均值。
5. redis qps，每30min收集一次，取30min的平均值。
6. redis 内存占用，每30min收集一次，实时数值。
7. kafka 生产和消费的qps，每30min收集一次，取30min的平均值。
8. mongodb qps，每30min收集一次，取30min的平均值。

若您不同意开启此服务，您依旧可以使用release包中提供的预编译ko，其他功能不受影响。具体操作为在release界面下载ko_1.7.0.9.tar.xz，然后替换`package/to_upload/agent/component/driver/ko.tar.xz`，deploy期间会将ko解压到`/elkeid/nginx/ElkeidAgent/agent/component/driver/ko`目录中。相关收集信息和下载ko的代码均在已开源的manager代码中，是否开启相关功能取决于manager运行时conf目录下的elkeidup_config.yaml文件。若您在部署期间开启了此服务，但是需要在之后的流程中关闭，您可以将`elkeidup_config.yaml`文件中的`report.enable_report`设置为false，之后重启manager即可。

> 附：相关功能位于manager代码中的以下位置:
>   - 开关位于internal/monitor/report.go的InitReport()函数中，清空此函数内容，即可关闭功能入口。
>   - 收集信息项位于internal/monitor/report.go的heartbeatDefaultQuery结构中。
>   - 自动下载ko功能位于biz/handler/v6/ko.go的SendAgentDriverKoMissedMsg函数中。

### Elkeid 完整部署(推荐)
[Elkeid 完整部署](./deploy-zh_CN.md)

### Elkeid HUB 单独部署
[Elkeid HUB 单独部署](./deploy_hub-zh_CN.md)

## Raw Data Usage Tutorial
- [Elkeid 数据说明](../server/docs/ElkeidData.xlsx)
- [Raw Data Usage Tutorial](raw_data_usage_tutorial/raw_data_usage_tutorial-zh_CN.md)


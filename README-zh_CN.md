# Elkeid - Bytedance Cloud Workload Protection Platform

[English](README.md) | 简体中文



**Elkeid** 是一款可以满足 **主机，容器与容器集群，Serverless** 等多种工作负载安全需求的开源解决方案，源于字节跳动内部最佳实践。

随着企业的业务发展，多云、云原生、多种工作负载共存的情况愈发凸显，我们希望可以有一套方案可以满足不同工作负载下的安全需求，因此 **Elkeid** 诞生了。


## Introduction

Elkeid 具备以下主要能力：

* **Elkeid** 不仅具备传统的 **HIDS(Host Intrusion Detection System)** 的对于主机层入侵检测和恶意文件识别的能力，且对容器内的恶意行为也可以很好的识别，部署在宿主机即可以满足宿主机与其上容器内的反入侵安全需求，并且 **Elkeid** 底层强大的内核态数据采集能力可以满足大部分安全运营人员对于主机层数据的渴望。

* 对于运行的业务 **Elkeid** 具备 **RASP** 能力可以注入到业务进程内进行反入侵保护，不仅运维人员不需要再安装一个 Agent，业务也无需重启。

* 对于 **K8s** 本身 **Elkeid** 支持接入**K8s Audit Log** 对 **K8s** 系统进行入侵检测和风险识别。

* **Elkeid** 的规则引擎 **Elkeid HUB** 也可以很好的和外部多系统进行联动对接。

**Ekeid** 将这些能力都很好的融合在一个平台内，满足不同工作负载的复杂安全需求的同时，还能实现多组件能力关联，更难得的是每个组件均经过字节跳动海量数据和多年的实战检验。



## Elkeid Community Edition Description

需要注意的是 **Elkeid** **开源版本** 和完整版本存在差异，目前已开源的能力主要包括：

* 全部端上能力，即端上数据/资产/部分采集能力，内核态数据采集能力，RASP 探针部分等，并与字节跳动内部版本一致；
* 全部接入层能力，即 Agent Center，服务发现等，并与字节跳动内部版本一致；
* 提供社区版规则引擎即 Elkeid HUB，并配套少量策略作为示例使用；
* 提供社区版 Elkeid Console 与部分配套能力。

因此需要具备完整的反入侵与风险感知能力，还需要自行基于 Elkeid HUB 进行策略构建和对 Elkeid 采集的数据进行二次加工等工作。



## Elkeid Architecture

<img src="server/docs/server_new.png"/>

##  Elkeid Host Ability
* **[Elkeid Agent](agent/README-zh_CN.md)** 用户态 Agent，负责管理各个端上能力组件并与 **Elkeid Agent Center** 通信
* **[Elkeid Driver](driver/README-zh_CN.md)** 负责 Linux Kernel 层采集数据，兼容容器，并能够检测常见 Rootkit
* **[Elkeid RASP](rasp)** 支持 CPython、Golang、JVM、NodeJS、PHP 的运行时数据采集探针，支持动态注入到运行时
* **Elkeid Agent Plugin List**
  * [Driver Plugin](plugins/driver): 负责与 **Elkeid Driver** 通信，处理其传递的数据等
  * [Collector Plugin](plugins/collector): 负责端上的资产/关键信息采集工作，如用户，定时任务，包信息等
  * [Journal Watcher](plugins/journal_watcher): 负责监测systemd日志的插件，目前支持ssh相关日志采集与上报
  * [Scanner Plugin](plugins/scanner): 负责在端上进行静态检测恶意文件的插件，支持 Yara
  * [RASP Plugin](rasp/plugin): 分析系统进程运行时，上报运行时信息，处理下发的 Attach 指令，收集各个探针上报的数据
  * [Baseline Plugin](plugins/baseline): 负责在端上进行基线风险识别的插件
* [**Elkeid 数据说明**](server/docs/ElkeidData.xlsx)
* [**Elkeid 数据接入**](elkeidup/raw_data_usage_tutorial/raw_data_usage_tutorial-zh_CN.md)


## Elkeid Backend Ability
* **[Elkeid AgentCenter](server/agent_center)** 负责与 Agent 进行通信并管理 Agent 如升级，配置修改，任务下发等
* **[Elkeid ServiceDiscovery](server/service_discovery)** 后台中的各组件都会向该组件定时注册、同步服务信息，从而保证各组件相互可见，便于直接通信
* **[Elkeid Manager](server/manager)** 负责对整个后台进行管理，并提供相关的查询、管理接口
* **[Elkeid Console](server/web_console)** Elkeid 前端部分
* **[Elkeid HUB](https://github.com/bytedance/Elkeid-HUB)**  策略引擎



## Elkeid Function List

| 功能                 | Elkeid Community Edition | Elkeid Enterprise Edition |
|--------------------|--------------------------|---------------------------|
| Linux 数据采集能力       | :white_check_mark:       | :white_check_mark:        |
| RASP 探针能力          | :white_check_mark:       | :white_check_mark:        |
| K8s Audit Log 采集能力 | :white_check_mark:       | :white_check_mark:        |
| Agent 控制面          | :white_check_mark:       | :white_check_mark:        |
| 主机状态与详情            | :white_check_mark:       | :white_check_mark:        |
| 勒索诱饵               | :ng_man:                 | :white_check_mark:        |
| 资产采集               | :white_check_mark:       | :white_check_mark:        |
| 高级资产采集             | :ng_man:                 | :white_check_mark:        |
| 容器集群资产采集           | :white_check_mark:       | :white_check_mark:        |
| 暴露面与脆弱性分析          | :ng_man:                 | :white_check_mark:        |
| 主机/容器 基础入侵检测       | `少量样例`                   | :white_check_mark:        |
| 主机/容器 行为序列入侵检测     | :ng_man:                 | :white_check_mark:        |
| RASP 基础入侵检测        | `少量样例`                   | :white_check_mark:        |
| RASP 行为序列入侵检测      | :ng_man:                 | :white_check_mark:        |
| K8S 基础入侵检测         | `少量样例`                   | :white_check_mark:        |
| K8S 行为序列入侵检测       | :ng_man:                 | :white_check_mark:        |
| K8S 威胁分析           | :ng_man:                 | :white_check_mark:        |
| 告警溯源(行为溯源)         | :ng_man:                 | :white_check_mark:        |
| 告警溯源(驻留溯源)         | :ng_man:                 | :white_check_mark:        |
| 告警白名单              | :white_check_mark:       | :white_check_mark:        |
| 多告警聚合能力            | :ng_man:                 | :white_check_mark:        |
| 威胁处置(进程)           | :ng_man:                 | :white_check_mark:        |
| 威胁处置(网络)           | :ng_man:                 | :white_check_mark:        |
| 威胁处置(文件)           | :ng_man:                 | :white_check_mark:        |
| 文件隔离箱              | :ng_man:                 | :white_check_mark:        |
| 漏洞检测               | `少量情报`                   | :white_check_mark:        |
| 漏洞情报热更新            | :ng_man:                 | :white_check_mark:        |
| 基线检查               | `少量基线`                   | :white_check_mark:        |
| RASP 热补丁           | :ng_man:                 | :white_check_mark:        |
| 病毒扫描               | :white_check_mark:       | :white_check_mark:        |
| 用户行为日志分析           | :ng_man:                 | :white_check_mark:        |
| 插件管理               | :white_check_mark:       | :white_check_mark:        |
| 系统监控               | :white_check_mark:       | :white_check_mark:        |
| 系统管理               | :white_check_mark:       | :white_check_mark:        |
| Windows 支持         | :ng_man:                 | :white_check_mark:        |
| 蜜罐                 | :ng_man:                 | :oncoming_automobile:     |
| 主动防御               | :ng_man:                 | :oncoming_automobile:     |
| 云查杀                | :ng_man:                 | :oncoming_automobile:     |
| 防篡改                | :ng_man:                 | :oncoming_automobile:     |



## Front-end Display (Community Edition)
**安全概览**
<img src="png/console0.png" style="float:left;"/>

**容器集群安全告警**

<img src="png/console1.png" style="float:left;"/>

**容器集群工作负载信息**

<img src="png/console2.png" style="float:left;"/>

****

**主机概览**

<img src="png/console3.png" style="float:left;"/>

**资产指纹**

<img src="png/console4.png" style="float:left;"/>

**安全告警**

<img src="png/console5.png" style="float:left;"/>

**漏洞信息**

<img src="png/console6.png" style="float:left;"/>

**基线检查**

<img src="png/console7.png" style="float:left;"/>

**病毒扫描**

<img src="png/console8.png" style="float:left;"/>

**后端监控**

<img src="png/console9.png" style="float:left;"/>

**后端服务监控**

<img src="png/console10.png" style="float:left;"/>



## Console User Guide
* **[ELkeid Console User Guide](server/docs/console_tutorial/Elkeid_Console_manual.md)**

## Quick Start
* **[通过Elkeidup部署](elkeidup/README-zh_CN.md)**

## Contact us && Cooperation

<img src="png/Lark.png" width="40%" style="float:left;"/>

*Lark Group*



## About Elkeid Enterprise Edition

Elkeid 企业版本支持单独策略售卖，也支持完全完整能力售卖。

如果对Elkeid企业版感兴趣请联系: elkeid@bytedance.com


## Elkeid Docs
For more details and latest updates, see [Elkeid docs](https://elkeid.bytedance.com/Chinese/).


## License
* Elkeid Driver: GPLv2
* Elkeid RASP: Apache-2.0
* Elkeid Agent: Apache-2.0
* Elkeid Server: Apache-2.0
* Elkeid Console: [Elkeid License](server/web_console/LICENSE)
* Elkeid HUB: [Elkeid License](https://github.com/bytedance/Elkeid-HUB/blob/main/LICENSE)



## 404StarLink 2.0 - Galaxy
<img src="https://github.com/knownsec/404StarLink-Project/raw/master/logo.png" width="30%" style="float:left;"/>

同时，Elkeid 也是 404Team [星链计划2.0](https://github.com/knownsec/404StarLink2.0-Galaxy)中的一环，如果对星链计划感兴趣的小伙伴可以点击下方链接了解。
[https://github.com/knownsec/404StarLink2.0-Galaxy](https://github.com/knownsec/404StarLink2.0-Galaxy)

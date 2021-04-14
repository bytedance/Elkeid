# Elkeid(AgentSmith-HIDS)

[English](README.md) | 简体中文

Elkeid是一个云原生的基于主机的入侵检测解决方案。

Elkeid 包含两大部分：
* **Elkeid Agent**与**Elkeid Driver**作为数据采集层，它在Linux系统的内核和用户空间上均可使用，从而提供了具有更好性能的且更丰富的数据。 
* **Elkeid Server**可以提供百万级Agent的接入能力，采集Agent数据，支持控制与策略下发。包含实时、离线计算模块，对采集上来的数据进行分析和检测。又有自带的服务发现和管理系统，方便对整个后台管理和操作。

## 系统架构

<img src="server/docs/server.png"/>

端上Elkeid Agent和Elkeid Driver已开源。这两个组件已经在生产环境中部署和测试了数月。由于当前开源模块缺少规则引擎和检测功能，Elkeid Agent && Driver 无法单独提供所有的HIDS能力。但是目前开源的部分作为"Host-Information-Collect-Agent"，可以轻松地与其他的HIDS/NIDS/XDR解决方案进行集成。 Elkeid Agent和Elkeid Driver 有以下几个优点：

* **性能更优**，主要通过内核态驱动来获取信息，无需诸如遍历`/proc`这样的行为进行数据补全。
* **难以绕过**，由于我们的信息获取是来自于内核态驱动，因此面对很多刻意隐藏自己的行为如rootkit难以绕过我们的监控。并且对于rootkit本身，驱动提供了一部分检测能力。
* **为联动而生**，我们不仅可以作为安全工具实现侵检测/溯源等功能，也可以实现如梳理内部资产等能力，我们通过内核模块对进程/用户/文件/网络连接进行梳理，如果有CMDB的信息，那么联动后你将会得到一张从网络到主机/容器/业务信息的调用/依赖关系图，还可以和NIDS/威胁情报联动等等。
* **用户态+内核态**，Elkeid同时拥有内核态和用户态的模块，可以形成互补。

后台开源了AgentCenter，ServiceDiscovery，Manager，提供了基础的后台框架。后台具有如下特点：
* **百万级Agent的后台架构解决方案**
* **分布式，去中心化，集群高可用**
* **部署简单，依赖少，便于维护**

欢迎任何建议与合作

* #### [Elkeid Driver](https://github.com/bytedance/Elkeid/tree/main/driver)
* #### [Elkeid Agent](https://github.com/bytedance/Elkeid/tree/main/agent)
* #### [Elkeid Server](https://github.com/bytedance/Elkeid/tree/main/server)

## To be Continued
* Elkeid Server还在持续迭代中，更多功能即将推出。

## Contact us && Cooperation

<img src="./Lark.png"/>

Lark Group

## License
* Elkeid Driver: GPLv2
* Elkeid Agent: Apache-2.0

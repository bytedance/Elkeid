# AgentSmith-HIDS

[English](README.md) | 简体中文

AgentSmith-HIDS严格意义上并不是一个“Host-based Intrusion Detection System”，因为目前开源的部分来讲它缺乏了规则引擎和相关检测的能力，但是它可以作为一个高性能“主机信息收集工具”来构建属于你自己的HIDS。
由于AgentSmit-HIDS的特点(**从内核态获取尽可能全的数据**)，对比用户态的HIDS拥有巨大的优势：

* **性能更优**，通过内核态驱动来获取信息，无需诸如遍历/proc这样的行为进行数据补全。
* **难以绕过**，由于我们的信息获取是来自于内核态驱动，因此面对很多刻意隐藏自己的行为如rootkit难以绕过我们的监控。
* **为联动而生**，我们不仅可以作为安全工具，也可以作为监控，或者梳理内部资产。我们通过内核模块对进程/用户/文件/网络连接进行梳理，如果有CMDB的信息，那么联动后你将会得到一张从网络到主机/容器/业务信息的调用/依赖关系图；如果你们还有DB Audit Tool，那么联动后你可以得到DB User/库表字段/应用/网络/主机容器的关系；等等，还可以和NIDS/威胁情报联动，达到溯源的目的。
* **用户态+内核态**，AgentSmith-HIDS同时拥有内核态和用户态的模块，可以形成互补。

## 系统架构

<img src="./AgentSmith-HIDS.png" width="50%" height="50%"/>

目前我们只开源了AgentSmith-HIDS Agent && Driver：

#### [AgentSmith-Driver](https://github.com/bytedance/AgentSmith-HIDS/tree/main/driver)

#### [AgentSmith-Agent](https://github.com/bytedance/AgentSmith-HIDS/tree/main/agent)

## TODO
* OpenSource AgentSmith-Server
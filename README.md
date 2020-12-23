# AgentSmith-HIDS

English | [简体中文](README-zh_CN.md)

Technically, AgentSmith-HIDS is not a Host-based Intrusion Detection System (HIDS) due to lack of rule engine and detection function. However, it can be used as a high performance 'Host Information Collect Agent' as part of your own HIDS solution.
The comprehensiveness of information which can be collected by this agent was one of the most important metrics during developing this project, hence it was built to function in the kernel stack and achieve huge advantage comparing to those function in user stack, such as:

* **Better performance**, Information needed are collected in kernel stack to avoid additional supplement actions such as traversal of '/proc'; and to enhance the performance of data transportation.
* **Hard to be bypassed**, Information collection was powered by specifically designed kernel drive, makes it almost impossible to bypass the detection for malicious software like rootkit, which can deliberately hide themselves.
* **Easy to be integrated**，The AgentSmith-HIDS was built to integrate with other applications and can be used not only as security tool but also a good monitoring tool, or even a good detector of your assets. The agent is capable of collecting the users, files, processes and internet connections for you, so let's imagine when you integrate it with CMDB, you could get a comprehensive map consists of your network, host, container and business (even dependencies). What if you also have a Database audit tool at hand? The map can be extended to contain the relationship between your DB, DB User, tables, fields, applications, network, host and containers etc. Thinking of the possibility of integration with network intrusion detection system and/or threat intelligence etc., higher traceability could also be achieved. It just never gets old.
* **Kernel Space + User Space**，AgentSmith-HIDS also provide user space module, to further extend the functionality when working with kernel space module.

## System Architecture

<img src="./AgentSmith-HIDS.png" width="50%" height="50%"/>

Currently we only opensource AgentSmith-HIDS Agent && Driver

#### [AgentSmith-Driver](https://github.com/bytedance/AgentSmith-HIDS/tree/main/driver)

#### [AgentSmith-Agent](https://github.com/bytedance/AgentSmith-HIDS/tree/main/agent)

## TODO
* OpenSource AgentSmith-Server
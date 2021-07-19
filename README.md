# Elkeid

*(Originated from AgentSmith-HIDS, but now it’s not just HIDS)*

English | [简体中文](README-zh_CN.md)

Elkeid is a support cloud-native and base linux host intrusion detection solution.

## Elkeid Architecture

<img src="server/docs/server.png"/>

##  Elkeid Host Ability
<img src="./Ability_1.png"/>

* **[Elkeid Agent](https://github.com/bytedance/Elkeid/tree/main/agent)** Linux userspace agent，responsible for managing various plugin,communication with **Elkeid Server**.
* **[Elkeid Driver](https://github.com/bytedance/Elkeid/tree/main/driver)** Driver can collect data on Linux Kernel, support container environment, communication with Elkeid Driver Plugin.
* **[Elkeid RASP](https://github.com/bytedance/Elkeid/tree/main/rasp)** Support CPython、Golang、JVM、NodeJS runtime data probe, supports dynamic injection into the runtime.
* **Elkeid Agent Plugin List**
    * [Driver Plugin](https://github.com/bytedance/Elkeid/tree/main/agent/driver): Responsible for managing **Elkeid Driver**, and process the driver data.
    * [Collector Plugin](https://github.com/bytedance/Elkeid/tree/main/agent/collector): Responsible for the collection of assets/log information on the Linux System, such as user list, crontab, package information, etc.
    * [Journal Watcher](https://github.com/bytedance/Elkeid/tree/main/agent/journal_watcher): Responsible for monitoring systemd logs, currently supports ssh related log collection and reporting.
    * [Scanner Plugin](https://github.com/bytedance/Elkeid/tree/main/agent/scanner): Responsible for static detection of malicious files on the host, currently supports yara.
    * RASP Plugin: Responsible for managing RASP components and processing data collected from RASP, not open source yet.


The above components can provide these data:

<img src="./data.png"/>



## [Elkeid Backend Abilty](https://github.com/bytedance/Elkeid/tree/main/server)
* **[Elkeid AgentCenter](https://github.com/bytedance/Elkeid/tree/main/server/agent_center)** Responsible for communicating with the Agent, collecting Agent data and simply processing it and then summing it into the MQ, is also responsible for the management of the Agent, including Agent upgrade, configuration modification, task distribution, etc.
* **[Elkeid ServiceDiscovery](https://github.com/bytedance/Elkeid/tree/main/server/service_discovery)** Each component in the background needs to register and synchronize service information with the component regularly, so as to ensure that the instances in each service module are visible to each other and facilitate direct communication.
* **[Elkeid Manager](https://github.com/bytedance/Elkeid/tree/main/server/manager)** Responsible for the management of the entire backend, and provide related query and management API.


## Elkeid Advantage
The current open source module lacks a rule engine and detection rule, and cannot provide intrusion detection capabilities. However, the current open source part can be easily integrated with other HIDS/NIDS/XDR solutions, or you can perform data processing on the collected data to meet your own needs. Elkeid has the following main advantages:

* **Excellent Performance**: With the help of Elkeid Driver and many custom developments, the end-to-end capability is excellent
* **Born For Intrusion Detection**: Data collection is based on high-intensity confrontation, and targeted data collection is available for many advanced confrontation scenarios such as Kernel Rootkit, privilege escalation, and fileless attacks.
* **Support Cloud Native**: Cloud native environment is supported from end-to-end capabilities to back-end deployment.
* **One-million-level Production Environment Verification**: The whole has been internally verified at a million-level, and the stability and performance have been tested from end to server. Elkeid is not just a PoC, it is production-level; the open source version is the internal Release Version.
* **Secondary Development Friendly**: Elkeid facilitates secondary development and increased demand for customization.

## Quick Start
* **[Quick Start](server/docs/quick-start-zh_CN.md)**
* **[Deploy Question and Answer](server/docs/qa-zh_CN.md)**

## Contact us && Cooperation

<img src="./Lark.png" width="40%" style="float:left;"/>

*Lark Group*

## License
* Elkeid Driver: GPLv2
* Elkeid RASP: Apache-2.0
* Elkeid Agent: Apache-2.0
* Elkeid Server: Apache-2.0

## 404StarLink 2.0 - Galaxy
<img src="https://github.com/knownsec/404StarLink-Project/raw/master/logo.png" width="30%" style="float:left;"/>

Elkeid has joined 404Team [404StarLink 2.0 - Galaxy](https://github.com/knownsec/404StarLink2.0-Galaxy)

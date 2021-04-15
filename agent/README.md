[![License](https://img.shields.io/badge/License-Apache%20v2-blue.svg)](https://github.com/bytedance/Elkeid/blob/main/agent/LICENSE)
[![Project Status: Active – The project has reached a stable, usable state and is being actively developed.](https://www.repostatus.org/badges/latest/active.svg)](https://www.repostatus.org/#active)

English | [简体中文](README-zh_CN.md)
## About Elkeid Agent
Elkeid Agent is a User Space program designed to supplement multiple functionalities through build-in or third party plugins. The main program controls plugins' behavior via configurations and forwards data, collected by various Agent plugins, to the configured remote backend. 

Elkeid Agent is written in Golang, but plugins are designed to support other languages ​​([rust is currently supported](support/rust), and the next will be Golang).

A plugin is a program with a specific function that can be independently updated and configured. The plugin's resource usage will be monitored once it gets registered on the agent. The plugin's log will also be passed to the Agent and logged together.

You may check out two examples of plugin implementation in [driver](driver/) and [journal_watcher](journal_watcher/) directories. The former one parses and enriches the data transmitted by the Elkeid Driver from the kernel. The latter one is used for log monitoring.

We decoupled basic functionalities through this Agent-Plugins struct. Functional modules such as process monitoring and file auditioning could be implemented for specific needs, while basic modules, like communication and control/resource monitoring could stay the same across various Linux distributions.

The current version of Elkeid Agent is recommended only for local testing. Without Elkeid Server, it does not support remote control and configurations. 

## Supported Platforms
In theory, all Linux distribution systems are compatible, but only Debian (including Ubuntu) and RHEL (including CentOS) have been fully tested. For the Agent itself, `amd64` and `arm64` are supported.

We recommend running the Elkeid Agent with **root privileges** in a **physical machine** or a **virtual machine** instead of a container for better compatibility with the current plugins.

## Compilation Environment Requirements
* Golang 1.16(Required)

## Work with Elkeid Server
Before compiling, please confirm that the security credentials and certificates that the Agent relies on are consistent with those of the Server. If they are inconsistent, please replace them manually. For details, please see [Replace Agent-AgentCenter communication certificate](../server/docs/install.md#replace-agent-agentcenter-communication-certificate)

The Agent supports one or more of the following methods to connect to the Server:
* ServiceDiscovery
* LoadBalance/Passthrough
If multiple methods are enabled at the same time, the priority when connecting is: sd> load balance/passthrough (internal network)> load balance/passthrough (external network). Moreover, each connection method can be configured with multiple destination addresses. This function is very useful when in a complex network environment. The specific configuration is located in the [`product.go`](transport/connection/product.go) and can be modified as needed. The following is an example:
```
  sd["sd-0"] = "sd-0.pri"
  sd["sd-1"] = "sd-1.pri"
  priLB["pri-0"] = "lb-0.pri"
  priLB["pri-1"] = "lb-1.pri"
  pubLB["pub-0"] = "lb-0.pub"
  pubLB["pub-1"] = "lb-1.pub"
```
When establishing a connection, it will first try to obtain the address of the Server from `sd-0.pri` or `sd-1.pri` and establish a connection; if both fail, try to directly establish a connection with `lb-0.pri` or `lb-1.pri`; If the connection still fails, it will directly establish a connection with `lb-0.pub` or `lb-1.pub`.

## Work with Elkeid Driver
Elkeid Driver runs as a plugin of Elkeid Agent and is enabled under the control of Manager API. For details, please refer to the corresponding chapter: [API interface documentation](../server/README.md#api-interface-documentation).

## Required environment of compilation
Golang 1.16 (required)

## Quick start
Because the entire `Plugin-Agent-Server` system has a certain threshold to get started, we will further explain the relevant content here so that everyone can quickly start this project.
> Definition/Objective of Quick Start: All security functions on the host are enabled, the Agent and Server are connected successfully, and the data can be seen successfully in Kafka.
### Preconditions and dependencies
Waiting for translating...
## License
Elkeid Agent are distributed under the Apache-2.0 license.

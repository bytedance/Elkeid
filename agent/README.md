[![License](https://img.shields.io/badge/License-Apache%20v2-blue.svg)](https://github.com/bytedance/Elkeid/blob/main/agent/LICENSE)
[![Project Status: Active – The project has reached a stable, usable state and is being actively developed.](https://www.repostatus.org/badges/latest/active.svg)](https://www.repostatus.org/#active)

English | [简体中文](README-zh_CN.md)
## About Elkeid Agent
Agent provides basic capability support for components on the host, including data communication, resource monitoring, component version control, file transfer, and host basic information collection.

Agent itself does not provide security capabilities, and operates as a system service as a plugin base. The policies of various functional plugins are stored in the server-side configuration, and after the Agent receives the corresponding control instructions and configuration, it will open, close, and upgrade itself and the plugins.

Bi-stream gRPC is used for communication between Agent and Server, and mutual TLS verification is enabled based on self-signed certificates to ensure transport security. Among them, the flow of information in the direction of Agent -> Server is called data flow, and the flow of information in the direction of Server -> Agent is generally control flow, using different message types of protobuf. The Agent itself supports client-side service discovery, and also supports cross-Region level communication configuration. It realizes that an Agent package can be installed in multiple network isolation environments. Based on a TCP connection at the bottom layer, two data transmissions, Transfer and FileOp, are realized in the upper layer. The service supports the data reporting of the plugin itself and the interaction with the files in the Host.

Plugins, as security capability plugins, generally have a "parent-child" process relationship with the Agent. Using two pipes as the cross-process communication method, the [plugins](../plugins/lib) lib provides two plugin libraries for Go and Rust, which are responsible for encoding and sending plugin-side information. It is worth mentioning that after the plugin sends data, it will be encoded as Protobuf binary data. After the Agent receives it, there is no need to decode it twice, and then splices the Header feature data in the outer layer and transmits it directly to the server. Generally, the server does not need to Decoding is directly transmitted to the subsequent data stream, and decoding is performed when used, which reduces the additional performance overhead caused by multiple encoding and decoding in data transmission to a certain extent.

The Agent is implemented in Go. Under Linux, systemd is used as a guardian to control resource usage by cgroup restrictions. It supports aarch64 and x86-64 architectures. It is finally compiled and packaged as deb and rpm packages for distribution. The formats are in line with systemd, Debian, and RHEL specifications. , which can be directly provided to the corresponding software repository for subsequent version maintenance. In subsequent versions, Agent for Windows platform will be released.
## Runtime Requirements
Most of the functions provided by Agent and Plugin need to run at the host level with root privileges. In containers with limited privileges, some functions may be abnormal.
## Quick Start
Through the complete deployment of [elkeidup](../elkeidup/README.md), you can directly obtain the installation package for Debian/RHEL series distributions, and deploy according to the commands of the [Elkeid Console - Installation Configuration]() page.
## Compile from source
### Dependency Requirements
* [Go](https://go.dev/) >= 1.18
* [nFPM](https://nfpm.goreleaser.com/)
* Successfully deployed [Server](../server/README.md) (includes all components)
### Confirm related configuration
* Make sure that the three files `ca.crt`, `client.key`, and `client.crt` in the `transport/connection` directory are the same as the files with the same name in the Agent Center's `conf` directory.
* Make sure the parameters in the `transport/connection/product.go` file are properly configured:
    * If it is a manually deployed Server:
        * `serviceDiscoveryHost["default"]` needs to be assigned to the intranet listening address and port of the [ServiceDiscovery](../server/service_discovery) service or its proxy, for example: `serviceDiscoveryHost["default"] = "192.168.0.1: 8088"`
        * `privateHost["default"]` needs to be assigned to the intranet listening address and port of the [AgentCenter](../server/agent_center) service or its proxy, for example: `privateHost["default"] = "192.168.0.1: 6751"`
        * If there is a public network access point of the Server, `publicHost["default"]` needs to be assigned to the external network listening address and port of the [AgentCenter](../server/agent_center) service or its proxy, for example: `publicHost[ "default"]="203.0.113.1:6751"`
    * If the Server is deployed through [elkeidup](../elkeidup), the corresponding configuration can be found according to the `~/.elkeidup/elkeidup_config.yaml` file of the deployed Server host:
        * Find the IP of the Nginx service in the configuration file, the specific configuration item is `nginx.sshhost[0].host`
        * Find the IP of the [ServiceDiscovery](../server/service_discovery) service in the configuration file, the specific configuration item is `sd.sshhost[0].host`
        * `serviceDiscoveryHost["default"]` needs to be assigned the IP of the [ServiceDiscovery](../server/service_discovery) service and set the port number to 8088, for example: `serviceDiscoveryHost["default"] = "192.168.0.1 :8088"`
        * `privateHost["default"]` needs to be assigned the IP of the Nginx service, and set the port number to 8090, for example: `privateHost["default"] = "192.168.0.1:8090"`
### Compile
Chage to the root directory of agent source code, execute:
````
BUILD_VERSION=1.7.0.24 bash build.sh
````
During the compilation process, the script will read the `BUILD_VERSION` environment variable to set the version information, which can be modified according to actual needs.

After the compilation is successful, in the `output` directory of the root directory, you should see 2 deb and 2 rpm files, which correspond to different systems and architectures.
## Version Upgrade
1. If no client component has been created, please create a new component in the [Elkeid Console-Component Management]() page.
2. On the [Elkeid Console - Component Management]() page, find the "elkeid-agent" entry, click "Release Version" on the right, fill in the version information and upload the files corresponding to the platform and architecture, and click OK.
3. On the [Elkeid Console - Component Policy]() page, delete the old "elkeid-agent" version policy (if any), click "New Policy", select the version just released, and click OK. Subsequent newly installed Agents will be self-upgraded to the latest version.
4. On the [Elkeid Console - Task Management]() page, click "New Task", select all hosts, click Next, select the "Sync Configuration" task type, and click OK. Then, find the task you just created on this page, and click Run to upgrade the old version of the Agent.
## License
Elkeid Agent is distributed under the Apache-2.0 license.

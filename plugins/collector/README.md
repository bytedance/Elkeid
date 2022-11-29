[![License](https://img.shields.io/badge/License-Apache%20v2-blue.svg)](https://github.com/bytedance/Elkeid/blob/main/agent/LICENSE)
[![Project Status: Active – The project has reached a stable, usable state and is being actively developed.](https://www.repostatus.org/badges/latest/active.svg)](https://www.repostatus.org/#active)

English | [简体中文](README-zh_CN.md)
## About collector Plugin
The collector periodically collects various asset information on the host and performs correlation analysis. Currently, the following asset types are supported:
* Process: supports the hash calculation of exe md5, which can be associated with threat intelligence analysis, and also associated with container information to support subsequent data traceability. (avaliable in container)
* Port: Support information extraction of tcp and udp listening ports, as well as associated reporting with process and container information. In addition, based on the sock status and its relationship, it analyzes externally exposed services and supports the analysis function of host exposed surfaces. (avaliable in container)
* Account: In addition to the basic account fields, weak passwords are detected on the terminal based on the weak password dictionary based on the hash collision, and the weak password baseline detection function of the Console is provided upwards. In addition, the sudoers configuration will be correlated and reported together.
* Software: Support system software packages, pypi packages, jar packages, and upwardly support the vulnerability scanning function. (partially avaliable in container)
* Container: Support container information collection under multiple runtimes such as docker and cri/containerd.
* Application: Support database, message queue, container component, Web service, DevOps tools and other types of application collection, currently supports the matching and extraction of 30+ common application versions, configuration files. (avaliable in container)
* Hardware: Supports the collection of hardware information such as network cards and disks.
* System integrity verification: By comparing the hash of the software package file with the actual file hash of the Host, it is judged whether the file has been changed.
* Kernel module: Collect basic fields, as well as additional fields such as memory addresses and dependencies.
* System services, scheduled tasks: Compatible with the definition of services and cron locations under different distributions, and parse the core fields.
## Runtime requirements
Supports mainstream Linux distributions, including CentOS, RHEL, Debian, Ubuntu, RockyLinux, OpenSUSE, etc. Supports x86-64 and aarch64 architectures.
## Quick start
Through the complete deployment of [elkeidup](../../elkeidup/README.md), this plugin is enabled by default.
## Compiling from source
### Dependency requirements
* [Go](https://go.dev/) >= 1.18
### Compile
In the root directory, execute:
```
BUILD_VERSION=1.7.0.140 bash build.sh
```
During the compilation process, the script will read the `BUILD_VERSION` environment variable to set the version information, which can be modified according to actual needs.

After the compilation is successful, you should see two plg files in the `output` directory of the root directory, which correspond to different system architectures.
## 版本升级
1. If no client component has been created, please create a new component in the [Elkeid Console-Component Management]() page.
2. On the [Elkeid Console - Component Management]() page, find the "collector" entry, click "Release Version" on the right, fill in the version information and upload the files corresponding to the platform and architecture, and click OK.
3. On the [Elkeid Console - Component Policy]() page, delete the old "collector" version policy (if any), click "New Policy", select the version just released, and click OK. Subsequent newly installed Agents will be self-upgraded to the latest version.
4. On the [Elkeid Console - Task Management]() page, click "New Task", select all hosts, click Next, select the "Sync Configuration" task type, and click OK. Then, find the task you just created on this page, and click Run to upgrade the old version of the Agent.
## License
collector is distributed under the Apache-2.0 license.

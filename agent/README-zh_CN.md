[![License](https://img.shields.io/badge/License-Apache%20v2-blue.svg)](https://github.com/DianrongSecurity/AgentSmith-HIDS/blob/master/LICENSE)
[![Project Status: Active – The project has reached a stable, usable state and is being actively developed.](https://www.repostatus.org/badges/latest/active.svg)](https://www.repostatus.org/#active)

[English](README.md) | 简体中文
## 关于 AgentSmith-HIDS Agent
AgentSmith-HIDS Agent 是一个用户态的程序，主要是用来转发其他功能插件发送来的数据以及通过配置来控制其他插件。

AgentSmith-HIDS Agent基于Golang构建，但其他功能插件可以用不同的语言去完成([目前已经支持Rust](support/rust)，下一个受到支持的语言是Golang)。

插件是一个具有特定功能并且可以独立配置与更新的程序。当插件向Agent注册之后，插件的资源使用情况会被受到监视，并且插件本身产生的的日志也会被转发给Agent。

在[driver](driver/) 与 [journal_watcher](journal_watcher/)下你可以看到两个示例插件。前者用来解析并丰富AgentSmith-HIDS Driver从内核发来的数据，后者用来监控系统日志。

通过Agent-Plugin的这种模式，我们可以将基础模块(例如通信与控制和资源监控等)与功能模块(例如进程监控和文件监控以及漏洞分析等)解耦，进而实现动态增减相关模块。

## 平台兼容性
理论上，所有Linux下的发行版都是兼容的，但是只有Debian(包括Ubuntu)与RHEL(包括CentOS)经过了充分测试。当前，我们只在x86_64平台上进行了测试。

另外，为了更好的与插件兼容，建议将Agent运行在物理机或者虚拟机中，而不是容器中。

为了功能的完整性，你可能需要以root权限运行AgentSmith-HIDS Agent。

## 需要的编译环境
* Golang 1.15(推荐)
## 快速开始
```
git clone --recursive https://github.com/bytedance/AgentSmith-HIDS
cd AgentSmith-HIDS/agent
go build
```
在当前目录下，你将会看见`agent`二进制文件。
## 参数和选项
如果你想查看当前Agent支持的参数，请执行：
```
./agent --help
```
你将会看到：
```
Usage:
  agent [OPTIONS]
Application Options:
  -v, --version                  Print agent version
      --plugin=                  Plugin socket path (default: plugin.sock)
      --log=                     Log file path (default: log/agent_smith.log)
      --config=                  Config file path(.yaml) (default: config.yaml)
      --data=[file|stdout|kafka] Set data output (default: stdout)
      --file_path=               If data option is file ,this option is used to set the file path (default: data.log)
      --addr=                    If data option is kafka ,this option is used to set kafka addr
      --topic=                   If data option is kafka ,this option is used to set kafka topic name

Help Options:
  -h, --help                     Show this help message

```
配置文件是用来控制当前运行的插件实例的。如果你只是想简单快速的开始运行Agent本身，不想开启功能插件，那么你可以直接执行`./agent`，你将会在当前终端的stdout上看到数据输出：

```
[{"data_type":"1001","level":"error","msg":"no such file or directory","source":"config/config.go:114","timestamp":"${current_timestamp}"}]
[{"cpu":"0.00000","data_type":"1000","distro":"${your_distro}","io":"8192","kernel_version":"${your_kernel_version}","memory":"${current_agent_memory_usage}","plugins":"[]","slab":"${current_sys_slab_usage}","timestamp":"${current_timestamp}"}]
```
第一行的错误数据是因为配置文件没有被找到，在这里我们可以暂时忽略。
第二行是当前Agent的心跳数据，里面的字段描述了当前Agent和当前已加载
插件的相关信息。
## 数据输出
当前版本的AgentSmith-HIDS Agent更多是用于本地的测试，它不支持远程控制与配置，但是支持将数据发送到远端(通过sarama/kafka)。

注意：请不要用于生产环境。
### Stdout(默认)
将所有数据输出到stdout。

注意：这个方式不会持久化保存任何数据，当数据发送速度过快时可能会导致当前终端运行缓慢。
### File
将所有数据保存到特定的文件中，默认是当前Agent工作目录下的`data.log`文件。
### Kafka
Agent将会产生一个同步生产者去发送数据到Kafka，在此之前请配置`addr`和`topic` 参数。
### 其他方法
你可以通过实现[transport](transport/transport.go)下的`Transport interface`来完成自定义的方法。

实现后请修改`main`函数，将自定义的方法设置为默认的。在未来，我们会支持gRPC数据传输。
## 日志
你可以通过配置`log`参数来配置Agent日志的存放位置(默认是Agent工作目录下的`log/agent_smith.log`)。

更加具体的日志配置，请修改`main`函数中的相应日志选项。所有等级大于等于Error的日志都将会被转发到[数据输出](#数据输出)中。
## 配置文件
当前，处于测试目的，我们提供了一个配置文件去控制Agent中插件的添加与删除。这将会带来较大的安全风险，所以请不要在生产环境中使用。

当Agent开始运行时，`config`参数中所配置的文件(默认是Agent工作目录下的`config.yaml`)将会被监视(通过inotify)。每当文件的修改事件被触发，配置文件都会被重新解析并与当前加载的Agent插件列表进行对比，进而实现对已加载插件的动态修改。请注意，不要使用类似vim/gedit等工具进行修改，因为它们[不会触发inotify的修改事件](https://stackoverflow.com/questions/13312794/inotify-dont-treat-vim-editting-as-a-modification-event)。

一个正确的配置文件如下所示：
```
plugins:
  -
    name: exmple1
    version: 0.0.0.1
    path: /opt/plugins/exmple1
    sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
  -
    name: exmple2
    version: 0.0.1.0
    path: /opt/plugins/exmple2
    sha256: 01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b
```
其中，`name` 与 `version`需要与[插件](support/README-zh_CN.md#注册)配置中的保持一致。`path`用于查找插件的二进制文件，`sha256`用于验证启动的文件。

所有与插件相关的事件都可以在[日志文件](#日志)中看到。

## 与AgentSmith-HIDS Driver兼容运行的示例
### 前提条件
* [Linux Kernrl Module](../driver) (一个ko文件)
* [Driver Plugin](driver) (一个二进制文件)
* [Agent](#快速开始) (一个二进制文件)
### 选择工作目录
在接下来的步骤中，我将会以`/etc/hids`作为Agent的工作目录：
```
mkdir -p /etc/hids
```
### 安装
创建插件的工作目录并将相关文件复制到对应的目录中：
```
cp agent /etc/hids/agent
mkdir -p /etc/hids/plugin/driver/
cp driver /etc/hids/plugin/driver/driver
cp hids_driver.ko /etc/hids/plugin/driver/hids_driver-latest.ko
```
### 创建配置文件
首先先计算插件二进制文件的`sha256`：
```
shasum -a 256 /etc/hids/plugin/driver/driver
5b76d3da59d45be3dd5d2326c1f2a87bd454ed4028201750b5b3eebb29cc6eac  /etc/hids/plugin/driver/driver
```
然后，修改`/etc/hids/config.yaml`的内容：
```
echo "plugins: [{name: hids_driver,version: 1.5.0.0,path: ./plugin/driver/driver,sha256: 5b76d3da59d45be3dd5d2326c1f2a87bd454ed4028201750b5b3eebb29cc6eac}]" > /etc/hids/config.yaml
```
### 运行Agent
执行下面的命令
```
cd /etc/hids/ && ./agent
```
在当前屏幕上你将会看到来自内核的相关数据。

如果你想关闭这个插件，请修改配置文件移除相关内容：
```
echo "plugins : []" > /etc/hids/config.yaml
```
如果你想再次开启这个插件，请[恢复配置文件](#配置文件)。

## License
AgentSmith-HIDS Agent are distributed under the Apache-2.0 license.
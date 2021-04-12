[![License](https://img.shields.io/badge/License-Apache%20v2-blue.svg)](https://github.com/bytedance/Elkeid/blob/main/agent/LICENSE)
[![Project Status: Active – The project has reached a stable, usable state and is being actively developed.](https://www.repostatus.org/badges/latest/active.svg)](https://www.repostatus.org/#active)

[English](README.md) | 简体中文
## 关于 Elkeid Agent
Elkeid Agent 是一个用户态的程序，主要是用来转发其他功能插件发送来的数据以及通过远端下发的配置来控制其他插件。

Elkeid Agent基于Golang构建，但其他功能插件可以用不同的语言去完成([目前已经支持Rust](support/rust)，下一个受到支持的语言是Golang)。

插件是一个具有特定功能并且可以独立配置与更新的程序。当插件向Agent注册之后，插件的资源使用情况会被受到监视，并且插件本身产生的的日志也会被转发给Agent。

在[driver](driver/) 与 [journal_watcher](journal_watcher/)下你可以看到两个示例插件。前者用来解析并丰富Elkeid Driver从内核发来的数据，后者用来接受系统日志并产生与ssh相关的事件。

通过Agent-Plugin的这种模式，我们可以将基础模块(例如通信与控制和资源监控等)与功能模块(例如进程监控和文件监控以及漏洞分析等)解耦，进而实现动态增减相关模块。

## 平台兼容性
理论上，所有Linux下的发行版都是兼容的，但是只有Debian(包括Ubuntu)与RHEL(包括CentOS)经过了充分测试，对于Agent本身，支持amd64与arm64。

另外，为了更好的与插件兼容，建议将Agent运行在物理机或者虚拟机，而不是容器中。

为了功能的完整性，你可能需要以root权限运行Elkeid Agent。

## 与Elkeid Server协同工作
在编译前，请确认Agent所依赖的安全凭证以及证书与Server的保持一致，如果不一致请手动进行替换。

Agent支持采用以下一种或多种方式连接到Server：
* sd
* load balance/passthrough

如果同时开启了多种方式，那么在连接时，优先级为：sd > load balance/passthrough (内网) >  load balance/passthrough (外网) 。并且，每种连接方式都可以配置多个目的地址，当处在复杂网络环境下时，这个功能十分有用，具体配置位于[`product.go`](transport/connection/product.go)文件中，可以根据需要进行修改，下面为一个样例：
```
  sd["sd-0"] = "sd-0.pri"
  sd["sd-1"] = "sd-1.pri"
  priLB["pri-0"] = "lb-0.pri"
  priLB["pri-1"] = "lb-1.pri"
  pubLB["pub-0"] = "lb-0.pub"
  pubLB["pub-1"] = "lb-1.pub"
```
当建立连接时，首先会尝试从`sd-0.pri`或`sd-1.pri`获取Server的地址并建立连接；如果都失败，便尝试直接与`lb-0.pri`或`lb-1.pri`建立连接；如果依然连接失败，会直接与`lb-0.pub`或`lb-1.pub`建立连接。
## 与Elkeid Driver协同工作
Elkeid Driver作为Elkeid Agent的一个Plugin运行，由Manager API控制下发，具体请参见对应章节：
> 如何编译 Elkeid Driver
>
> 如何使用 Manager API
## 需要的编译环境
* Golang 1.16(必需)
## 快速开始
```
git clone --recursive https://github.com/bytedance/Elkeid
cd Elkeid/agent
mkdir /etc/hids
go build -o /etc/elkeid/elkeid-agent
/etc/hids/elkeid-agent &
```
## License
Elkeid Agent are distributed under the Apache-2.0 license.
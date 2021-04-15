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
在编译前，请确认Agent所依赖的安全凭证以及证书与Server的保持一致，如果不一致请手动进行替换。详情请查看[更换Agent-AgentCenter通信证书](../server/docs/install-zh_CN.md#更换agent-agentcenter通信证书)

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
Elkeid Driver作为Elkeid Agent的一个Plugin运行，由Manager API控制下发，具体请参见对应章节：[如何使用 Manager API](../server/README-zh_CN.md#api接口文档)。

## 需要的编译环境
* Golang 1.16(必需)
## 快速开始
因为整个`插件-Agent-Server`体系具有一定上手门槛，所以在这里进一步阐述相关内容，以便大家可以快速开始本项目。
> 快速开始的定义/目标：端上安全功能全部开启，Agent与Server连接正常，在后端可以正常看到相关数据。
### 前提条件与依赖
Server部署完成，工作正常。具体请查阅[Server部署文档](../server/server/docs/install-zh_CN.md)
部署完成后，你应该获取了以下资源：
* ServiceDiscovery地址(记为sd_host)及端口(记为sd_port)
* Manager地址(记为ma_host)及端口(记为ma_port)
* AgentCenter地址(记为ac_host)及端口(记为ac_port)
* 安全凭证:ca.crt/client.crt/client.key
### 配置Agent
将上述安全凭证分别替换至[客户端CA证书](transport/connection/ca.crt);[客户端证书](transport/connection/client.crt);[客户端私钥](transport/connection/client.key)。
修改[`product.go`](transport/connection/product.go)文件为以下内容：
```
package connection

import _ "embed"

//go:embed client.key
var ClientKey []byte

//go:embed client.crt
var ClientCert []byte

//go:embed ca.crt
var CaCert []byte

func init() {
	sd["sd"] = "sd_host:sd_port"
  priLB["ac"] = "ac_host:ac_port"  
	setDialOptions(CaCert, ClientKey, ClientCert, "hids_svr.github.com")
}
```
### 编译Agent
```
mkdir output
go build -o output/elkeid-agent
```
### 安装并启动Agent
在获取上述二进制产物后，在终端机器进行安装部署：
> 不同机器间需要分发产物，在这里不做阐述
```
mkdir -p /etc/elkeid
cp output/elkeid-agent /etc/elkeid
```
后台启动即可：
> 在这里没有提供进程守护与自保护，如有需要可以自行通过systemd/cron实现，这里不做要求
```
cd /etc/elkeid && /etc/elkeid/elkeid-agent &
```
### 验证Agent状态
查看Agent日志，如果看到已经启动并不断有心跳数据打印到日志中，则部署成功；如果进程消失/无(空)日志/stderr有panic，则部署失败，如果确认自己部署步骤没问题，请提issue或者群里沟通。
```
ps aux|grep elkeid-agent
cat /etc/elkeid/log/elkeid-agent.log
```
预期输出:
```
2021-04-15T15:32:57.937+0800    INFO    agent/main.go:67        Elkeid Agent:v1.6.0.0
2021-04-15T15:32:57.937+0800    INFO    agent/main.go:68        AgentID:f4c6d306-3d4b-4eb7-abe7-b15757acbb27
2021-04-15T15:32:57.937+0800    INFO    agent/main.go:69        PrivateIPv4:[10.0.0.1]
2021-04-15T15:32:57.937+0800    INFO    agent/main.go:70        PublicIPv4:[]
2021-04-15T15:32:57.937+0800    INFO    agent/main.go:71        PrivateIPv6:[fdbd:dc02:ff:1:1:225:85:27]
2021-04-15T15:32:57.937+0800    INFO    agent/main.go:72        PublicIPv6:[]
2021-04-15T15:32:57.937+0800    INFO    agent/main.go:73        Hostname:test
2021-04-15T15:32:57.938+0800    INFO    report/report.go:119    map[cpu:0.00000 data_type:1000 io:12288 kernel_version:4-amd64 memory:12009472 net_type: platform:debian platform_version:9.13 plugins:[] slab:1271408 timestamp:1618471977]
2021-04-15T15:32:58.118+0800    INFO    transport/client.go:69
2021-04-15T15:33:27.939+0800    INFO    report/report.go:119    map[cpu:0.00101 data_type:1000 io:0 kernel_version:4-amd64 memory:14602240 net_type:sd platform:debian platform_version:9 plugins:[] slab:1273792 timestamp:1618472007]
```
可以看到日志里面打印出了AgentID:f4c6d306-3d4b-4eb7-abe7-b15757acbb27，我们下面将会以这个AgentID为例进行配置。
### 编译插件
在Agent启动完毕且状态正常后，说明Agent-Server已经建立了稳定的通信链路，但Agent本身只具有监控/通信/控制的功能，其他安全功能承载在其他插件上，所以我们需要对插件进行编译并下发。
> 我们提供了预编好的插件，如果采用预编译插件可以直接跳过这步。
* driver插件：参见[driver插件编译](driver/README-zh_CN.md#编译)
* jouran_watcher插件：参见[jouran_watcher插件编译](jouran_watcher/README-zh_CN.md#编译)
编译完成后，你应该可以获得`driver`与`jouran_watcher`两个二进制文件。
### 上传插件
计算上述两个二进制文件sha256，并上传至可访问的文件服务器，并获得相应的下载地址：
> 我们已经上传了预编译好的插件，如果采用预编译插件可以直接跳过这步，下面也会以我们预编译好的插件地址为例。
* driver插件(sha256:a9ab7a2eda69b83d830a6061a393f886a7b125ea63e7ae1df4a276105764b37d)
```
https://lf3-elkeid.bytetos.com/obj/elkeid-download/plugin/driver/driver_1.6.0.0_amd64.plg
https://lf6-elkeid.bytetos.com/obj/elkeid-download/plugin/driver/driver_1.6.0.0_amd64.plg
https://lf9-elkeid.bytetos.com/obj/elkeid-download/plugin/driver/driver_1.6.0.0_amd64.plg
https://lf26-elkeid.bytetos.com/obj/elkeid-download/plugin/driver/driver_1.6.0.0_amd64.plg
```
* jouran_watcher插件(sha256:a0c065514debf6f2109aa873ece86ec89b0e6ccedfa05c124b5863a4568ee20c)
```
https://lf3-elkeid.bytetos.com/obj/elkeid-download/plugin/journal_watcher/journal_watcher_1.6.0.0_amd64.plg
https://lf6-elkeid.bytetos.com/obj/elkeid-download/plugin/journal_watcher/journal_watcher_1.6.0.0_amd64.plg
https://lf9-elkeid.bytetos.com/obj/elkeid-download/plugin/journal_watcher/journal_watcher_1.6.0.0_amd64.plg
https://lf26-elkeid.bytetos.com/obj/elkeid-download/plugin/journal_watcher/djournal_watcher_1.6.0.0_amd64.plg
```
### 配置插件
在配置插件前需要鉴权Manager API：
> 详细参见[API接口文档](../server/README-zh_CN.md#api接口文档)
> 如果在部署Manager时修改了`username`和`password`，下面也记得做对应修改
```
curl --location --request POST 'http://m_host:m_port/api/v1/user/login' \
--data-raw '{
    "username": "hids_test",
    "password": "hids_test"
}'
```
回应中带着鉴权的token：
```
{
    "code": 0,
    "msg": "success",
    "data": {
        "token": "BUVUDcxsaf%^&%4643667"
    }
}
```
将token加到配置插件的请求中，并根据插件名、插件版本、插件sha256、插件下载地址编写请求body：
```
curl --location --request GET 'http://m_host:m_port/api/v1/agent/createTask/config' -H "token:BUVUDcxsaf%^&%4643667" --data-raw '{
    "id_list": [
        "f4c6d306-3d4b-4eb7-abe7-b15757acbb27"
    ],
    "data": {
        "config": [
            {
                "name": "driver",
                "download_url": [
                    "https://lf3-elkeid.bytetos.com/obj/elkeid-download/plugin/driver/driver_1.6.0.0_amd64.plg","https://lf6-elkeid.bytetos.com/obj/elkeid-download/plugin/driver/driver_1.6.0.0_amd64.plg","https://lf9-elkeid.bytetos.com/obj/elkeid-download/plugin/driver/driver_1.6.0.0_amd64.plg","https://lf26-elkeid.bytetos.com/obj/elkeid-download/plugin/driver/driver_1.6.0.0_amd64.plg"
                ],
                "version": "1.6.0.0",
                "sha256": "a9ab7a2eda69b83d830a6061a393f886a7b125ea63e7ae1df4a276105764b37d",
                "detail": ""
            },
            {
                "name": "journal_watcher",
                "download_url": [
                    "https://lf3-elkeid.bytetos.com/obj/elkeid-download/plugin/journal_watcher/journal_watcher_1.6.0.0_amd64.plg","https://lf6-elkeid.bytetos.com/obj/elkeid-download/plugin/journal_watcher/journal_watcher_1.6.0.0_amd64.plg","https://lf9-elkeid.bytetos.com/obj/elkeid-download/plugin/journal_watcher/journal_watcher_1.6.0.0_amd64.plg","https://lf26-elkeid.bytetos.com/obj/elkeid-download/plugin/journal_watcher/journal_watcher_1.6.0.0_amd64.plg"
                ],
                "version": "1.6.0.0",
                "sha256": "a0c065514debf6f2109aa873ece86ec89b0e6ccedfa05c124b5863a4568ee20c",
                "detail": ""
            }
        ]
    }
}'
```
在回应中，我们可以看到如下内容：
```
{"code":0,"msg":"success","data":{"count":1,"task_id":"1618474279380056335bbGGcn"}}
```
其中count代表有1台机器将要被配置，task_id：1618474279380056335bbGGcn是要执行的任务id。
### 下发配置
通过上述得到的task_id，我们构造以下请求：
```
curl --location --request GET 'http://m_host:m_port/api/v1/agent/controlTask' -H "token:BUVUDcxsaf%^&%4643667" --data-raw '{
    "task_id": "1618474279380056335bbGGcn",
    "action": "run",
    "rolling_percent": 1,
    "concurrence": 100
}'
```
可以看到如下回应，说明配置已经下发：
```
{"code":0,"msg":"success","data":{"id_count":1,"jobID":"id-Agent_Config-1618474660501972408","taskID":"1618474279380056335bbGGcn"}}
```
### 验证配置
在Agent的日志中，我们可以看到如下记录：
```
2021-04-15T16:17:40.537+0800    INFO    transport/client.go:69  Config:<Name:"driver" Version:"1.6.0.0" SHA256:"a9ab7a2eda69b83d830a6061a393f886a7b125ea63e7ae1df4a276105764b37d" DownloadURL:"https://lf3-elkeid.bytetos.com/obj/elkeid-download/plugin/driver/driver_1.6.0.0_amd64.plg" DownloadURL:"https://lf6-elkeid.bytetos.com/obj/elkeid-download/plugin/driver/driver_1.6.0.0_amd64.plg" DownloadURL:"https://lf9-elkeid.bytetos.com/obj/elkeid-download/plugin/driver/driver_1.6.0.0_amd64.plg" DownloadURL:"https://lf26-elkeid.bytetos.com/obj/elkeid-download/plugin/driver/driver_1.6.0.0_amd64.plg" > Config:<Name:"journal_watcher" Version:"1.6.0.0" SHA256:"a0c065514debf6f2109aa873ece86ec89b0e6ccedfa05c124b5863a4568ee20c" DownloadURL:"https://lf3-elkeid.bytetos.com/obj/elkeid-download/plugin/journal_watcher/journal_watcher_1.6.0.0_amd64.plg" DownloadURL:"https://lf6-elkeid.bytetos.com/obj/elkeid-download/plugin/journal_watcher/journal_watcher_1.6.0.0_amd64.plg" DownloadURL:"https://lf9-elkeid.bytetos.com/obj/elkeid-download/plugin/journal_watcher/journal_watcher_1.6.0.0_amd64.plg" DownloadURL:"https://lf26-elkeid.bytetos.com/obj/elkeid-download/plugin/journal_watcher/journal_watcher_1.6.0.0_amd64.plg" > 
```
这说明接收到了插件下发的指令，进而我们可以看到插件加载相关日志：
```
2021-04-15T16:17:42.803+0800    INFO    plugin/plugin.go:162    Plugin work directory: /etc/elkeid/plugin/driver/
2021-04-15T16:17:42.807+0800    INFO    plugin/server.go:126    Received a registration:{Pid:1746809 Name:driver Version:1.6.0.0}
2021-04-15T16:17:42.807+0800    INFO    plugin/server.go:141    Plugin has been successfully connected:&{name:driver version:1.6.0.0 checksum:a9ab7a2eda69b83d830a6061a393f886a7b125ea63e7ae1df4a276105764b37d cmd:0xc000388000 conn:0xc000314088 runtimePID:1746809 pgid:1746809 IO:253952 CPU:0 reader:0xc00007e200 exited:{Value:{v:false} _:[]} Counter:{_:[] v:0}}
2021-04-15T16:17:43.649+0800    INFO    plugin/plugin.go:162    Plugin work directory: /etc/elkeid/plugin/journal_watcher/
2021-04-15T16:17:43.650+0800    INFO    plugin/server.go:126    Received a registration:{Pid:1746883 Name:journal_watcher Version:1.6.0.0}
2021-04-15T16:17:43.650+0800    INFO    plugin/server.go:141    Plugin has been successfully connected:&{name:journal_watcher version:1.6.0.0 checksum:a0c065514debf6f2109aa873ece86ec89b0e6ccedfa05c124b5863a4568ee20c cmd:0xc000162580 conn:0xc000010040 runtimePID:1746883 pgid:1746883 IO:0 CPU:0 reader:0xc000324180 exited:{Value:{v:false} _:[]} Counter:{_:[] v:0}}
2021-04-15T16:17:57.939+0800    INFO    report/report.go:119    map[cpu:0.02274 data_type:1000 io:24526848 kernel_version:4-amd64 memory:18325504 net_type:sd platform:debian platform_version:9.13 plugins:[{"rss":9654272,"io":4399104,"cpu":0,"name":"driver","version":"1.6.0.0","pid":1746809,"qps":188.66666666666666},{"rss":8192,"io":0,"cpu":0,"name":"journal_watcher","version":"1.6.0.0","pid":1746883,"qps":0.03333333333333333}] slab:2868720 timestamp:1618474677]
2021-04-15T16:18:27.939+0800    INFO    report/report.go:119    map[cpu:0.03518 data_type:1000 io:0 kernel_version:4-amd64 memory:17645568 net_type:sd platform:debian platform_version:9.13 plugins:[{"rss":13709312,"io":479232,"cpu":0.015414258189652063,"name":"driver","version":"1.6.0.0","pid":1746809,"qps":428.73333333333335},{"rss":8192,"io":0,"cpu":0,"name":"journal_watcher","version":"1.6.0.0","pid":1746883,"qps":0}] slab:2875588 timestamp:1618474707]
```
### 验证插件数据
现在，可以从kafka里面消费数据了，里面包含所有插件和Agent上报的数据。

## License
Elkeid Agent are distributed under the Apache-2.0 license.
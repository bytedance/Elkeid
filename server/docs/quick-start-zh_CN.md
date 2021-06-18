## 依赖环境准备

### 1. 依赖组件准备
Elkeid后端依赖如下组件，进行所有操作之前请先准备好，可以与其他系统复用。

|组件|推荐配置|是否必须|备注|
| :- | :- | :- | :- |
|MongoDB|每1000台Agent 10GB|是|如果Agent>1w，建议集群部署|
|Kafka|每1000台Agent 25Partation|是|如果Agent>1w，建议集群部署|
|Redis|每1000台Agent 1GB内存|是|如果Agent>1w，建议集群部署|

### 2. Elkeid Server集群部署机器准备
Elkeid后端包括三个部分，ServiceDiscovery、Manager、AgentCenter三部分，可单机部署也可集群部署。推荐配置如下：

|组件|推荐配置|是否必须|备注|
| :- | :- | :- | :- |
|ServiceDiscovery|每1000台Agent 4C8G|是|如果Agent>1w，建议集群部署|
|Manager|每1000台Agent 4C8G|是|如果Agent>1w，建议集群部署|
|AgentCenter|每1000台Agent 8C8G|是|如果Agent>1w，建议集群部署|
|

> **安装之前，请确保Server集群机器之间可互通！**  
> **Server机器与Mongodb/Kafka/Redis集群之间可互通，否则无法正常工作！**

### 3. 编译依赖环境
- Golang 1.16(必需)

> **编译Agent与Server二进制需要依赖Golang 1.16**  
> **Golang的安装请参照官方文档：<https://golang.org/doc/install>**

## 代码下载
Agent和Server的代码在 https://github.com/bytedance/Elkeid/ 中，可通过git/或者在页面直接下载。
### 通过GIt下载

```
git clone https://github.com/bytedance/Elkeid.git
```
### 也可以通过前端页面直接下载
访问 https://github.com/bytedance/Elkeid 直接下载

## Server编译和部署
### 1. 更换Agent-AgentCenter通信证书
生产环境部署，强烈建议执行此部署，替换Agent-AgentCenter通信证书。若测试环境，可忽略这个步骤。  

在Elkeid/server/build目录执行如下脚本。
```
cd Elkeid/server/build
./cert_gen.sh elkeid.com hids-svr elkeid@elkeid.com
```
执行完成后将会看到类似如下的输出
```
Generating RSA private key, 2048 bit long modulus
......................................................................................+++++
.................................+++++
e is 65537 (0x010001)
Generating RSA private key, 2048 bit long modulus
...........................+++++
............................+++++
e is 65537 (0x010001)
Signature ok
subject=C = GB, L = China, O = hids-svr, CN = elkeid@elkeid.com
Getting CA Private Key
Generating RSA private key, 2048 bit long modulus
..........+++++
...............+++++
e is 65537 (0x010001)
Signature ok
subject=C = GB, L = China, O = hids-svr, CN = elkeid@elkeid.com
Getting CA Private Key
generate cert ok!
update agent_center cert ok!
update agent cert ok!
success!
```
> ./cert_gen.sh [域名] hids-svr [邮箱]  
> 命令中的邮箱 elkeid@elkeid.com 可以替换成任意其他的。   
> 域名 elkeid.com 不建议修改，如果修改了，需要同步修改Elkeid/agent/transport/connection/product.go 中配置的域名。
### 2. 替换后端AK、SK鉴权秘钥
后端各个组件之间使用appKey+secretKey来做内部接口鉴权。其中appKey为16位的由数字和小写字母组成的随机字符串，secretKey为32位的由数字和小写字母组成的随机字符串。  
我们需要生成两对AK:SK组合，agent_center/manager各自需要一对，另外还需要生成一个manager_key，用于初始化token。  并将这些密钥替换到server对应的配置文件中。  
   
请在Elkeid/server/build目录执行如下脚本，它将自动化为我们生成和替换AKSK。
```
cd Elkeid/server/build
bash ./update_aksk.sh
```
执行完成后，将会看到如下输出：
```
generate key ok!
update agent_center/conf/svr.yml ok!
update service_discovery/conf/conf.yaml ok!
update manager/conf/svr.yml ok!
success!
```
如果看到其他报错，请确认当前是否在`Elkeid/server/build`目录下。
### 3. 编译 Elkeid Server二进制
> 前置条件：Golang (版本1.16)  
> Golang的安装请参照官方文档：https://golang.org/doc/install  
```
cd Elkeid/server/build
./build.sh
```
执行成功后会输出如下：
```
service_discovery/
service_discovery/conf/
service_discovery/conf/conf.yaml
service_discovery/sd
agent_center/
agent_center/conf/
agent_center/conf/server.crt
agent_center/conf/ca.key
agent_center/conf/svr.yml
agent_center/conf/client.crt
agent_center/conf/client.key
agent_center/conf/ca.crt
agent_center/conf/server.key
agent_center/agent_center
manager/
manager/manager
manager/conf/
manager/conf/svr.yml
manager/conf/index.json
manager/init
```
并且生成三个压缩包，将他们拷贝到对应的机器目录上进行部署。
```
service_discovery-xxx.tar.gz
agent_center-xxx.tar.gz
Manager-xxx.tar.gz
```
如果脚本运行过程中有 `i/o timeout` 的报错，则是网络不通导致，请配置go proxy。
> Go proxy配置请参考：https://github.com/goproxy/goproxy.cn/blob/master/README.zh-CN.md
### 4. 部署 ServiceDiscovery(服务发现)
4.1 将第三步生成的 service_discovery-xxx.tar.gz 拷贝到SD集群各服务器上，并解压。
```
tar xvfz service_discovery-xxx.tar.gz
```
4.2 修改sd的配置conf/conf.yaml，将下面的127.0.0.1修改为部署机器的本机IP：
```
Server:
  Ip: "127.0.0.1"
  Port: 8088

Cluster:
  Mode: "config"
  Members: ["127.0.0.1:8088"]
```
4.3 启动服务
```
./sd
```
如果看到如下输出，并且无任何error报错，则服务已经启动成功：
```
[GIN-debug] [WARNING] Creating an Engine instance with the Logger and Recovery middleware already attached.

[GIN-debug] [WARNING] Running in "debug" mode. Switch to "release" mode in production.
 - using env:	export GIN_MODE=release
 - using code:	gin.SetMode(gin.ReleaseMode)

[GIN-debug] POST   /registry/register        --> github.com/bytedance/Elkeid/server/service_discovery/server/handler.Register (4 handlers)
[GIN-debug] POST   /registry/evict           --> github.com/bytedance/Elkeid/server/service_discovery/server/handler.Evict (4 handlers)
[GIN-debug] POST   /registry/sync            --> github.com/bytedance/Elkeid/server/service_discovery/server/handler.Sync (4 handlers)
[GIN-debug] GET    /endpoint/ping            --> github.com/bytedance/Elkeid/server/service_discovery/server/handler.Ping (3 handlers)
[GIN-debug] GET    /endpoint/stat            --> github.com/bytedance/Elkeid/server/service_discovery/server/handler.EndpointStat (3 handlers)
[GIN-debug] GET    /registry/summary         --> github.com/bytedance/Elkeid/server/service_discovery/server/handler.RegistrySummary (3 handlers)
[GIN-debug] GET    /registry/detail          --> github.com/bytedance/Elkeid/server/service_discovery/server/handler.RegistryDetail (3 handlers)
[GIN-debug] GET    /registry/list            --> github.com/bytedance/Elkeid/server/service_discovery/server/handler.RegistryList (3 handlers)
[GIN-debug] Listening and serving HTTP on xx.xx.xx.xx:8088
```
4.4 步骤3中服务若正常运行，则可放到后台运行：
```
nohup ./sd>/dev/null 2>&1 &
```
> 默认情况下ServiceDiscovery会在8088端口开放HTTP服务，用于对外API访问和内部通信。请保持此端口与所有Agent机器通信畅通。  
>  同时也需要保持此端口与所有Manager/AgentCenter机器之间通信畅通。  
### 5. 部署 Manager
1. 将第三步生成的 Manager-xxx.tar.gz 拷贝到Manager集群各服务器上，并解压。
```
tar xvfz manager-xxx.tar.gz
```
2. 修改Manager的配置conf/svr.yml： 
  - 修改redis配置：  
    redis.passwd为redis密码（为空可不设置）。  
    如果使用的是redis集群，请将集群地址列表配置到redis.addrs中，如果是单实例redis，则将地址配置到redis.addr中。**redis.addr和redis.addrs只需要配置一个即可**
  - 将sd.addrs修改为服务发现集群的地址列表。（即步骤4中部署的ServiceDiscovery的ip:port）
  - 将 mongo.uri 修改为mongodb集群的uri地址，格式为 mongodb://{{user_name}}:{{passwd}}@{{ip}}:{{port}}/{{dbname}}?authSource={{dbname}} 。并且将mongo.dbname修改为对应的db名
```
# addr和addrs只需配置一个，redis集群则配置addrs，单机redis则配置addr
redis:
  addr: 127.0.0.1:6379
  addrs: ["127.0.0.1:6379"]
  passwd:
  
sd:
  addrs: ["127.0.0.1:8088"]

mongo:
  uri: mongodb://hids:I7ILUz7WhOJUWygy@127.0.0.1:27000/hids_server?authSource=hids_server
  dbname: hids_server
```
3. 服务初始化。 
  - 新增用户，请保存好新增的用户名和密码，在后续Manager API接口/api/v1/user/login中需要用到。
```
./init -c conf/svr.yml -t addUser -u hids_test -p hids_test
```
执行成功后会看到如下输出，若有其他报错，则是Mongodb配置不对，请确认本机器与mongodb集群是否通畅。
```
InsertedID: ObjectID("60cc447e809e3afbd63ee256") {hids_test 689e877c0fcf65fd361fec8eae645f1d514d451a VlBzgbaiCMRAjWwh 0}
```
  - 新增索引，Mongodb未加索引会影响系统性能，所以请确保系统必要的字段都加上索引。
```
#index新增Mongodb索引
./init -c conf/svr.yml -t addIndex -f conf/index.json
```
4. 启动服务
./manager -c conf/svr.yml

如果看到如下输出，并且无任何error报错，则服务已经启动成功。
```
[job] api job init
{"level":"info","ts":1623999644.6970289,"msg":"JOB_MANAGE","info":"job manage init"}
{"level":"debug","ts":1623999644.6972933,"msg":"cronJobManager","info":"cron jobs: [{Server_AgentStat 90 512 120} {Server_AgentList 30 512 20}]"}
>>>>new registry: discovery.ServerRegistry{Name:"hids_manage", Ip:"10.227.2.103", Port:6701, Weight:0, SDHost:"127.0.0.1:8088", stopChan:(chan struct {})(0xc0001ac5a0)}
>>>>register response: {"msg":"ok"}
[START_SERVER] Listening and serving on :6701
```
5. 服务校验
  - 校验服务发现是否注册成功：
   执行 `curl http://{{sd_ip:sd_port}}/registry/detail?name=hids_manage`
   如果为异常返回，请检查步骤2中配置文件conf/svr.yml里面的sd.addrs是否配置正确。如果还未能解决，请参考 **QA 2服务发现异常排查** 来解决。
```
//正常返回，返回了manager注册的地址
{"data":[{"name":"hids_manage","ip":"xxxx","port":6701,"status":0,"create_at":1623400287,"update_at":1623402507,"weight":0,"extra":{}}],"msg":"ok"}

//异常返回
{"data":[],"msg":"ok"}
```
6. 如果步骤4和步骤5中都无异常，则可放到后台运行：
```
nohup ./manager -c conf/svr.yml>/dev/null 2>&1 &
```
> 默认情况下Manager会在6701端口开放HTTP服务，用于对外API访问和内部通信。  
> 另外请确保Redis集群和Mongodb集群与Manager集群机器之间的通信畅通。  

### 6. 部署 AgentCenter
1. 将第三步生成的 agent_center-xxx.tar.gz 拷贝到AgentCenter集群各服务器上，并解压。
```
tar xvfz agent_center-xxx.tar.gz
```
2. 修改agent_center的配置conf/svr.yml 主要是改3个地方：
  - 将 sd.addrs修改为服务发现集群的地址列表。（即步骤4中部署的ServiceDiscovery的ip:port）
  - 将manage.addrs修改为Manager集群的地址列表。（即步骤5中部署的Manager的ip:port）
  - 将kafka.addrs修改为kafka集群的地址列表。并且将kafka.topic修改为kafka集群的写入topic
```
sd:
  addrs:
    - 127.0.0.1:8088
    
manage:
  addrs:
    - 127.0.0.1:6701

kafka:
  addrs:
    - 127.0.0.1:9092
  topic: hids_svr
```
3. 启动服务
```
./agent_center -c conf/svr.yml
```
如果看到如下输出，并且无任何error报错，则服务已经启动成功：
```
{"level":"info","ts":1623999988.1748643,"msg":"InitComponents","info":"KAFKA Producer: [127.0.0.1:9092] - hids_svr"}
{"level":"info","ts":1623999988.174998,"msg":"Sarama","info":["Initializing new client"]}
{"level":"info","ts":1623999988.1751726,"msg":"Sarama","info":"client/metadata fetching metadata for all topics from broker 127.0.0.1:9092\n"}
{"level":"info","ts":1623999988.1760483,"msg":"Sarama","info":"Connected to broker at 127.0.0.1:9092 (unregistered)\n"}
{"level":"info","ts":1623999988.1820292,"msg":"Sarama","info":"client/brokers registered new broker #1 at 127.0.0.1:9092"}
{"level":"info","ts":1623999988.182112,"msg":"Sarama","info":["Successfully initialized new client"]}
[MAIN] START_SERVER
[GIN-debug] [WARNING] Creating an Engine instance with the Logger and Recovery middleware already attached.

[GIN-debug] [WARNING] Running in "debug" mode. Switch to "release" mode in production.
 - using env:	export GIN_MODE=release
 - using code:	gin.SetMode(gin.ReleaseMode)

{"level":"info","ts":1623999988.1901152,"msg":"NewRegistry","info":">>>>new registry: {hids_svr_grpc 10.227.2.103 %!s(int=6751) %!s(int=0) map[] [127.0.0.1:8088] %!s(chan struct {}=0xc0004b0000)}"}
[GIN-debug] GET    /conn/stat                --> github.com/bytedance/Elkeid/server/agent_center/httptrans/http_handler.ConnStat (3 handlers)
[GIN-debug] GET    /conn/list                --> github.com/bytedance/Elkeid/server/agent_center/httptrans/http_handler.ConnList (3 handlers)
[GIN-debug] GET    /conn/count               --> github.com/bytedance/Elkeid/server/agent_center/httptrans/http_handler.ConnCount (3 handlers)
[GIN-debug] POST   /conn/reset               --> github.com/bytedance/Elkeid/server/agent_center/httptrans/http_handler.ConnReset (3 handlers)
[GIN-debug] POST   /command/                 --> github.com/bytedance/Elkeid/server/agent_center/httptrans/http_handler.PostCommand (3 handlers)
[GIN-debug] Listening and serving HTTPS on :6752
{"level":"info","ts":1623999988.1933253,"msg":"RunServer","info":"####TCP_LISTEN_OK: [::]:6751"}
####TCP_LISTEN_OK: [::]:6751
[NewRegistry] >>>>new registry {"name":"hids_svr_grpc","ip":"10.227.2.103","port":6751,"weight":0,"extra":null} resp: {"msg":"ok"}
{"level":"info","ts":1623999988.1938977,"msg":"NewRegistry","info":">>>>new registry {\"name\":\"hids_svr_grpc\",\"ip\":\"10.227.2.103\",\"port\":6751,\"weight\":0,\"extra\":null} resp: {\"msg\":\"ok\"}"}
{"level":"info","ts":1623999988.1940048,"msg":"NewRegistry","info":">>>>new registry: {hids_svr_http 10.227.2.103 %!s(int=6752) %!s(int=0) map[] [127.0.0.1:8088] %!s(chan struct {}=0xc00003a0c0)}"}
[NewRegistry] >>>>new registry {"name":"hids_svr_http","ip":"10.227.2.103","port":6752,"weight":0,"extra":null} resp: {"msg":"ok"}
{"level":"info","ts":1623999988.1950216,"msg":"NewRegistry","info":">>>>new registry {\"name\":\"hids_svr_http\",\"ip\":\"10.227.2.103\",\"port\":6752,\"weight\":0,\"extra\":null} resp: {\"msg\":\"ok\"}"}
```
HTTPS服务监听了6752端口，TCP服务监听了6751端口，并且注册到服务发现已经成功。  
4. 服务校验
  - 校验服务发现是否注册成功：
   执行 `curl http://{{sd_ip:sd_port}}/registry/detail?name=hids_svr_grpc`
   如果为异常返回，请检查步骤2中配置文件conf/svr.yml里面的sd.addrs是否配置正确。如果还未能解决，请参考 **QA 2服务发现异常排查** 来解决。
```
//正常返回，返回了manager注册的地址
{"data":[{"name":"hids_svr_grpc","ip":"xxxx","port":6751,"status":0,"create_at":1623403853,"update_at":1623403853,"weight":0,"extra":null}],"msg":"ok"}

//异常返回
{"data":[],"msg":"ok"}
```
5. 步骤3中服务若正常运行，则可放到后台运行：
```
nohup ./agent_center -c conf/svr.yml>/dev/null 2>&1 &
```
> AgentCenter会在6751端口开放RPC服务，请保持此端口与所有Agent机器通信畅通。   
> AgentCenter会在6752端口开放HTTP服务，请保持此端口与所有Manager机器通信畅通。 AgentCenter会在6753端口开放pprof服务，用于debug。
>
> 另外请确保Kafka集群和AgentCenter集群机器之间的通信畅通。
### 8. 端口策略
要想整套系统能正常运行，默认情况下，需要至少开通如下访问策略：
|sip|sport|dip|dport|备注|
| :- | :- | :- | :- | :- |
|所有Agent/Manager/AgentCenter|*|ServiceDiscovery|8088|
所有Agent/Manager/AgentCenter/其他需要访问managerAPI的机器|*|Manager|6701|http服务|
|Agent机器|*|AgentCenter|6751|agent上报数据|
|所有Manager机器|*|AgentCenter|6752|http服务|
|Manager/AgentCenter/ServiceDiscovery|*|kafka集群/redis集群/mongodb集群|对应集群端口|
|

## Agent编译和部署
Server部署完后，可以得到以下资源：
- ServiceDiscovery地址(记为sd_host)及端口(记为sd_port)
- Manager地址(记为ma_host)及端口(记为ma_port)
- AgentCenter地址(记为ac_host)及端口(记为ac_port)
### 1. 配置Agent
将 Elkeid/agent/transport/connection/product.go 替换成如下内容：
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
        //这里"elkeid.com"需要与生成证书时使用的域名一致，如果生成时不是默认配置需要在这里一起修改
        setDialOptions(CaCert, ClientKey, ClientCert, "elkeid.com")
}
```
### 2. 编译Agent
```
cd Elkeid/agent
mkdir output
go build -o output/elkeid-agent
```
### 3. 安装并启动Agent
在获取上述二进制产物后，在终端机器进行安装部署：
不同机器间需要分发产物，在这里不做阐述
```
mkdir -p /etc/elkeid
cp output/elkeid-agent /etc/elkeid
```
后台启动即可：
在这里没有提供进程守护与自保护，如有需要可以自行通过systemd/cron实现，这里不做要求
```
cd /etc/elkeid && /etc/elkeid/elkeid-agent &
```
### 4. 验证Agent状态
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
可以看到日志里面打印出了`AgentID:f4c6d306-3d4b-4eb7-abe7-b15757acbb27`，我们下面将会以这个AgentID为例进行配置。

### 5. 编译插件
在Agent启动完毕且状态正常后，说明Agent-Server已经建立了稳定的通信链路，但Agent本身只具有监控/通信/控制的功能，其他安全功能承载在其他插件上，所以我们需要对插件进行编译并下发。
> 我们提供了预编好的插件，如果采用预编译插件可以直接**跳过这步**。
* driver插件：参见[driver插件编译](../../agent/driver/README-zh_CN.md#编译)
* journal_watcher插件：参见[journal_watcher插件编译](../../agent/journal_watcher/README-zh_CN.md#编译)
* collector插件：参见[collector插件编译](../../agent/collector/README-zh_CN.md#编译)
编译完成后，你应该可以获得driver journal_watcher collector三个二进制文件。
### 6. 上传插件
计算上述两个三进制文件sha256，并上传至可访问的文件服务器，并获得相应的下载地址：
我们已经上传了预编译好的插件，如果采用预编译插件可以直接跳过这步，下面也会以我们预编译好的插件地址为例。
- driver插件(sha256:a9ab7a2eda69b83d830a6061a393f886a7b125ea63e7ae1df4a276105764b37d)
```
https://lf3-elkeid.bytetos.com/obj/elkeid-download/plugin/driver/driver_1.6.0.0_amd64.plg
https://lf6-elkeid.bytetos.com/obj/elkeid-download/plugin/driver/driver_1.6.0.0_amd64.plg
https://lf9-elkeid.bytetos.com/obj/elkeid-download/plugin/driver/driver_1.6.0.0_amd64.plg
https://lf26-elkeid.bytetos.com/obj/elkeid-download/plugin/driver/driver_1.6.0.0_amd64.plg
```
- journal_watcher插件(sha256:a0c065514debf6f2109aa873ece86ec89b0e6ccedfa05c124b5863a4568ee20c)
```
https://lf3-elkeid.bytetos.com/obj/elkeid-download/plugin/journal_watcher/journal_watcher_1.6.0.0_amd64.plg
https://lf6-elkeid.bytetos.com/obj/elkeid-download/plugin/journal_watcher/journal_watcher_1.6.0.0_amd64.plg
https://lf9-elkeid.bytetos.com/obj/elkeid-download/plugin/journal_watcher/journal_watcher_1.6.0.0_amd64.plg
https://lf26-elkeid.bytetos.com/obj/elkeid-download/plugin/journal_watcher/journal_watcher_1.6.0.0_amd64.plg
```
- collector插件(sha256:f6e0b34de998844cbfc95ae0e47d39225c2449833657a6a6289d9722d8e2fdc8)
```
https://lf3-elkeid.bytetos.com/obj/elkeid-download/plugin/collector/collector_1.6.0.0_amd64.plg
https://lf6-elkeid.bytetos.com/obj/elkeid-download/plugin/collector/collector_1.6.0.0_amd64.plg
https://lf9-elkeid.bytetos.com/obj/elkeid-download/plugin/collector/collector_1.6.0.0_amd64.plg
https://lf26-elkeid.bytetos.com/obj/elkeid-download/plugin/collector/collector_1.6.0.0_amd64.plg
```
### 7. 配置插件
在配置插件前需要鉴权Manager API：
> 详细参见[API接口文档](./README-zh_CN.md#api接口文档)
>
> 如果在部署Manager时修改了`username`和`password`，下面也记得做对应修改
>
```
curl --location --request POST 'http://m_host:m_port/api/v1/user/login' \
--data-raw '{
    "username": "hids_test",
    "password": "hids_test"
}'
```
回应中带着鉴权的token（后面的其他接口请求都需要header带上这个token）：
```
{
    "code": 0,
    "msg": "success",
    "data": {
        "token": "BUVUDcxsaf%^&%4643667"
    }
}
```
将token加到配置插件的请求头中，并根据需要下发的AgentID、插件名、插件版本、插件sha256、插件下载地址编写请求body：
```
curl --location --request POST 'http://m_host:m_port/api/v1/agent/createTask/config' -H "token:BUVUDcxsaf%^&%4643667" --data-raw '{
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
            },
	    {
                "name": "collector",
                "download_url": [
                    "https://lf3-elkeid.bytetos.com/obj/elkeid-download/plugin/collector/collector_1.6.0.0_amd64.plg","https://lf6-elkeid.bytetos.com/obj/elkeid-download/plugin/collector/collector_1.6.0.0_amd64.plg","https://lf9-elkeid.bytetos.com/obj/elkeid-download/plugin/collector/collector_1.6.0.0_amd64.plg","https://lf26-elkeid.bytetos.com/obj/elkeid-download/plugin/collector/collector_1.6.0.0_amd64.plg"
                ],
                "version": "1.6.0.0",
                "sha256": "f6e0b34de998844cbfc95ae0e47d39225c2449833657a6a6289d9722d8e2fdc8",
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
### 8. 下发配置
通过上述得到的task_id，我们构造以下请求：
```
curl --location --request POST 'http://m_host:m_port/api/v1/agent/controlTask' -H "token:BUVUDcxsaf%^&%4643667" --data-raw '{
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
### 9. 验证配置
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
### 10. 验证插件数据
现在，可以从kafka里面消费数据了，里面包含所有插件和Agent上报的数据。

## Manager API使用指南
这里只介绍部分接口的用法，更多接口的用法请参考[API接口](https://documenter.getpostman.com/view/9865152/TzCTZ5Do#intro)。

建议使用[Postman](https://www.postman.com/)来操作，会更便于使用和管理，安装Postman后点击以上链接，通过打开后的右上角的"Run in Postman"来导入到本地。另外实际使用过程中，请将地址修改为对应的manager的地址。
### 1. 登录
所有api接口使用前都需要先登录，获取token，再将token添加到请求header中。
```
curl --location --request POST 'http://127.0.0.1:6701/api/v1/user/login' \
--data-raw '{
    "username": "hids_test",
    "password": "hids_test"
}'

#response
{"code":0,"msg":"success","data":{"token":"xxxxx"}}
```
### 2. 查询Agent状态
#### 2.1 获取所有agent状态
```
curl --location --request GET 'http://127.0.0.1:6701/api/v1/agent/getStatus' -H 'token:xxxxxxxxx'
```
#### 2.2 获取指定agent状态
```
curl --location --request GET 'http://127.0.0.1:6701/api/v1/agent/getStatus/33623333-3365-4905-b417-331e183330' -H 'token:xxxxxxxxx'
```
#### 2.3 根据filter查询Agent状态
```
#查询所有last_heartbeat_time>1617172110的agent
curl --location -H 'token:xxxxxxxxx' --request POST 'http://127.0.0.1:6701/api/v1/agent/getStatus/filter' \
--data-raw '{
    "filter": [
        {
            "key": "last_heartbeat_time",
            "rules": [
                {
                    "operator": "$gt",
                    "value": 1617172110
                }
            ],
            "condition": "$and"
        }
    ],
    "condition": "$and"
}'
```
### 3. Agent任务
####  3.1 查询任务状态
```  
#查询task 1617876668390045859aiCMRA的执行状态
curl --location -H 'token:xxxxxxxxx' --request GET 'http://127.0.0.1:6701/api/v1/agent/getTask/1617876668390045859aiCMRA?result=true&detail=false' \
--data-raw '{
    "task_id": "task-1617097443663532000-Bzgb",
    "action": "run",
    "rolling_percent": 0.5,
    "concurrence": 1
}'
```
### 4. 设置Agent默认配置
####  4.1 设置Agent默认配置
agent默认配置用来控制新接入agent开启哪部分的插件。默认设置为空(为空意味着新接入的agent不会自动开启任何插件)。
```  
curl --location --request POST 'http://127.0.0.1:6701/api/v1/agent/updateDefaultConfig' -H "token:BUVUDcxsaf%^&%4643667" \
--data-raw '{
    "type": "agent_config",
    "version": 0,
    "config": []
}'
```
## QA
### 1. Mangager API 使用过程中遇到报错 CLUSTERDOWN Hash slot not served
如果是单节点的redis集群，运行可能会遇到报错 CLUSTERDOWN Hash slot not served，需要执行如下命令修复： redis-cli --cluster fix 127.0.0.1:6379
### 2. 服务发现异常排查 
1. 首先请确认manager/agentcenter配置文件中服务发现的地址写的是正确的地址。
2. 如果地址配置没错，则是aksk配置的问题：
类似返回 `{"code":-1,"data":"User not exist","msg":"auth failed"}` 类似的错误，一般情况下是因为没将manager/agentcenter的aksk写到服务发现配置文件中导致的。  
请按照如下方法排查：
    - 查看manager/conf/svr.yml的配置文件:  
确保`manager/conf/svr.yml`文件里面的sd.credentials.ak和sd.credentials.sk已经配置到service_discovery的配置文件Auth.Keys里面。  
    - 查看agent_center/conf/svr.yml的配置文件  
确保上面`agent_center/conf/svr.yml`文件里面的sd.auth.ak和sd.auth.sk已经配置到service_discovery的配置文件Auth.Keys里面。

### 3. 首次使用manager接口时，发现有异常
首次使用manager api时，如果发现有controlTask接口下发任务失败、无响应；getStatus接口查询不到agent数据等情况。请按照如下步骤排查：
1. 如果是单节点的redis集群，请先执行如下命令修复集群状态：redis-cli --cluster fix 127.0.0.1:6379
2. manager接口的数据是定时采集，所以接口数据会有30秒-90秒的时间延迟，如果上述操作都执行完成后，manager接口仍然有异常，可稍稍2分钟再尝试。
### 4. Manager API接口响应慢，db耗性能等
请参照 上面 Server编译和部署-->部署Manager -->3 服务初始化--> 新增索引 步骤来给mongodb增加必要的索引。

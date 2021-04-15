[English](install.md) | 简体中文
## 服务器资源需求参照表
| 集群 | 机器配置 | 数量 |
| ----- | ----- | ----- |
| MongoDB |  | 如Agent数>1w，建议集群部署 |
| KAFKA |  | 如Agent数>1w，建议集群部署 |
| Redis |  | 如Agent数>1w，建议集群部署 |
| ServiceDiscovery集群 | 4C8G | 1-5台（Agent数<1w可单机部署） |
| Manager集群 | 4C8G | 1-5台（Agent数<1w可单机部署） |
| AgentCenter集群 | 8C8G | Agent数/1600 |

## 更换Agent-AgentCenter通信证书
生产环境部署，强烈建议执行此部署，替换Agent-AgentCenter通信证书。若测试环境，可忽略这个步骤。
1. 随机生成证书。并替换AgentCenter证书。
```
git clone https://github.com/bytedance/Elkeid.git
cd Elkeid/server/build && ./cert_gen.sh elkeid.com hids-svr elkeid@elkeid.com
cp cert/* ../agent_center/conf/ 
```
2. 替换Agent证书。
```
cp cert/ca.crt cert/client.crt cert/client.key ../../agent/transport/connection
```

## 编译elkeid Server二进制
```
cd server/build && ./build.sh
```
编译后生成三个压缩包，将他们拷贝到对应的机器目录上进行部署
```
service_discovery-xxx.tar.gz
agent_center-xxx.tar.gz
Manager-xxx.tar.gz
```

## 部署依赖组件
> 非生产环境下，Mongodb、KAFKA、Redis都可以使用docker部署，具体可参考docker官方文档
### 部署 MongoDB
官网下载页面 https://www.mongodb.com/try/download/community
> 推荐以集群部署，具体参照官方文档 https://docs.mongodb.com/manual/administration/install-community/

以Debian9为例，这里演示单机部署
```
wget https://fastdl.mongodb.org/linux/mongodb-linux-x86_64-debian92-4.4.4.tgz
tar xvf mongodb-linux-x86_64-debian92-4.4.4.tgz
```

新增配置文件mongodb.conf
```
# mongodb.conf
storage:
  #存储路径，需要根据实际情况修改
  dbPath: /data/mongodb/data/
  journal:
    enabled: true
  wiredTiger:
    engineConfig:
    #通常配置为机器内存的一半
        cacheSizeGB: 2

net:
   bindIp: 0.0.0.0
   port: 27000

processManagement:
   fork: true

systemLog:
   destination: file
   #log路径，需要根据实际情况修改
   path: /data/mongodb/log/mongodb.log
   logAppend: true

security:
  authorization: enabled
```

启动服务
```
./bin/mongod --config ./mongodb.conf
```

新增管理员和普通用户，并设置密码(设置的账号密码需要与manager/conf/svr.yml文件的mongo.url配置中保持一致)
```
./bin/mongo 127.0.0.1:27000

#新建管理员
use admin
db.createUser(
  {
    user: "admin",
    pwd: "q50stucaziKZw6DG",
    roles: [ { role: "userAdminAnyDatabase", db: "admin" }, "readWriteAnyDatabase" ]
  }
)

#新建普通用户
db.auth('admin', 'q50stucaziKZw6DG')
use hids_server
db.createUser({
    user:"hids",
    pwd:"I7ILUz7WhOJUWygy",
    roles:[{
        role:"readWrite",
        db:"hids_server"
    }]
})

use hids_server
db.auth('hids', 'I7ILUz7WhOJUWygy')
```

### 部署 KAFKA
#### Java安装
先安装JAVA：https://www.oracle.com/java/technologies/javase/javase-jdk8-downloads.html
确认JAVA已经安装成功
```
java -version
```
#### Kafka安装
官网下载页面  http://kafka.apache.org/downloads
```
wget https://apache.claz.org/kafka/2.7.0/kafka_2.13-2.7.0.tgz
tar -zxvf  kafka_2.13-2.7.0.tgz
cd kafka_2.13-2.7.0
```
启动服务
```
#1.启动zookeeper
bin/zookeeper-server-start.sh -daemon config/zookeeper.properties

#2.修改kafka配置 config/server.properties，新增下面的配置：
#broker能接收消息的最大字节数(10M)
message.max.bytes=10485760
#broker可复制的消息的最大字节数(10M)
replica.fetch.max.bytes=10485760
#消费者端的可读取的最大消息(10M) 
fetch.message.max.bytes=10485760


#3.启动kafka
bin/kafka-server-start.sh -daemon config/server.properties
```
创建Topic
```
bin/kafka-topics.sh --create --zookeeper 127.0.0.1:2181 --replication-factor 1 --partitions 200 --topic hids_svr

#列出Topic是否创建成功
bin/kafka-topics.sh --list --zookeeper 127.0.0.1:2181
```
#### 确认Kafka集群是否正常
发送消息
```
bin/kafka-console-producer.sh --broker-list 127.0.0.1:9092 --topic hids_svr
> {"info":"test"}
```
接收消息
```
bin/kafka-console-consumer.sh --bootstrap-server 127.0.0.1:9092 --topic hids_svr --from-beginning
```
### 部署 Redis
官网下载页面 https://redis.io/download
```
wget https://download.redis.io/releases/redis-6.2.1.tar.gz
tar -zvxf redis-6.2.1.tar.gz
cd redis-6.2.1
make
sudo make install

#启动服务
redis-server ./redis.conf
```
其中redis.conf配置关键修改如下几个地方
```
#bind 修改为本机ip或者0.0.0.0
bind 0.0.0.0 ::1

# 关闭包含模式，允许非本机访问redis
protected-mode no

#开启集群模式
cluster-enabled yes
```
> 如果是单节点的redis集群，运行可能会遇到报错 CLUSTERDOWN Hash slot not served，需要执行如下命令修复：
redis-cli --cluster fix 127.0.0.1:6379

## 部署Elkeid Server
### 部署 ServiceDiscovery
1. 将第一步生成的 service_discovery-xxx.tar.gz 拷贝到SD集群各服务器上，并解压。
```
tar xvfz service_discovery-xxx.tar.gz
```
2. 修改sd的配置conf/conf.yaml
主要是改3个地方：
```
Server.Ip: 本服务监听IP，主要修改为本机IP
Server.Port: 本服务监听端口(默认为8089)

Cluster.Mode: 配置为"config"即可
Cluster.Members: 集群其他机器的地址 

Auth.Enable: 注册接口是否开启鉴权
Auth.Keys: 鉴权秘钥列表，客户端（AC/Manager）需要拿到这个的秘钥，才能访问对应的接口。（可以为AC和Manager分别生成随机的AKSK，写入到配置中）
```
3. 启动服务
```
./sd
#如果服务无异常，也可放后台运行  
#nohup ./sd>/dev/null 2>&1 &
```

### 部署 Manager
1. 将第一步生成的 Manager-xxx.tar.gz 拷贝到Manager集群各服务器上，并解压。
```
tar xvfz manager-xxx.tar.gz
```
2. 修改Manager的配置conf/svr.yml。
主要是改3个地方：
```
redis.addrs 是redis集群的地址列表。
mongo.uri 是mongodb集群的uri地址。
sd.addrs 是服务发现集群的地址列表。
```
3. 服务初始化。
请保存好新增的用户名和密码，在后续Manager API接口/api/v1/user/login中需要用到。
Mongodb未加索引会影响系统性能，所以请确保系统必要的字段都加上索引。
```
#新增用户
./init -c conf/svr.yml -t addUser -u test1 -p 22222

#index新增Mongodb索引
./init -c conf/svr.yml -t addIndex -f conf/index.json
```
4. 启动服务
```
./Manager -c conf/svr.yml
#如果服务无异常，也可放后台运行  
#nohup ./Manager -c conf/svr.yml>/dev/null 2>&1 &
```
> Manager会在6701端口开放HTTP服务，用于对外API访问和内部通信。

> 另外请确保Redis集群和Mongodb集群与Manager集群机器之间的通信畅通。

### 部署AgentCenter
1. 将第一步生成的 agent_center-xxx.tar.gz 拷贝到AgentCenter集群各服务器上，并解压。
```
tar xvfz agent_center-xxx.tar.gz
```
2. 修改agent_center的配置conf/svr.yml
主要是改3个地方：
```
manage.addrs 是Manager集群的地址列表。
sd.addrs 是服务发现集群的地址列表。
kafka.addrs 是kafka集群的地址列表。
```
3. 启动服务
```
./agent_center -c conf/svr.yml
#如果服务无异常，也可放后台运行  
#nohup ./agent_center -c conf/svr.yml>/dev/null 2>&1 &
```
> AgentCenter会在6751端口开放RPC服务，请保持此端口与所有Agent机器通信畅通。
AgentCenter会在6752端口开放HTTP服务，请保持此端口与所有Manager机器通信畅通。
AgentCenter会在6753端口开放pprof服务，用于debug。

> 另外请确保Kafka集群和AgentCenter集群机器之间的通信畅通。
## 开始使用
安装完成后，可跑测试脚本简单验证连通性
```
cd server/agent_center/test && go run grpc_client.go
```

将ServerDiscovery的地址配置到[Agent](../../agent/README-zh_CN.md)中，编译并部署Agent，即可通过[Manager API](../README-zh_CN.md)查看Agent在线情况。

可以从KAFKA中消费Agent数据进行后续处理。
```
bin/kafka-console-consumer.sh --bootstrap-server 127.0.0.1:9092 --topic hids_svr --from-beginning
```

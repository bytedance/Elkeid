[English](install-compose.md) | 简体中文

> 非生产环境下，Mongodb、KAFKA、Redis都可以使用docker部署，具体可参考docker官方文档或者参考[docker快速体验文档](docker-install-zh_CN.md)
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
> 先安装JAVA，可参考：https://www.oracle.com/java/technologies/javase/javase-jdk8-downloads.html

以Debian9为例，这里演示单机部署
```
sudo apt-get update
sudo apt-get install default-jre
sudo apt-get install default-jdk
```
确认JAVA已经安装成功
```
java -version
```
#### Kafka安装
官网下载页面  http://kafka.apache.org/downloads
```
wget https://archive.apache.org/dist/kafka/2.7.0/kafka_2.13-2.7.0.tgz
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
```
> 如果是单节点的redis集群，运行可能会遇到报错 CLUSTERDOWN Hash slot not served，需要执行如下命令修复：
redis-cli --cluster fix 127.0.0.1:6379

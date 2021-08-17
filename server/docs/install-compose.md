English | [简体中文](install-compose-zh_CN.md)

## Deployment components
> In a non-production environment, Mongodb, KAFKA, and Redis can all be deployed using docker. For details, please refer to the official documentation of docker or [docker test deployment document](docker-install.md).
### Deploy MongoDB
Official website download page https://www.mongodb.com/try/download/community
> It is recommended to deploy in clusters, refer to official documents for details https://docs.mongodb.com/manual/administration/install-community/

Take Debian9 as an example, here is a demonstration of stand-alone deployment
```
wget https://fastdl.mongodb.org/linux/mongodb-linux-x86_64-debian92-4.4.4.tgz
tar xvf mongodb-linux-x86_64-debian92-4.4.4.tgz
```

Add a new configuration file mongodb.conf
```
# mongodb.conf
storage:
  #Storage path, need to be modified according to your machine
  dbPath: /data/mongodb/data/
  journal:
    enabled: true
  wiredTiger:
    engineConfig:
    #Usually configured as half of the machine's memory
        cacheSizeGB: 2

net:
   bindIp: 0.0.0.0
   port: 27000

processManagement:
   fork: true

systemLog:
   destination: file
   #log path, need to be modified according to your machine
   path: /data/mongodb/log/mongodb.log
   logAppend: true

security:
  authorization: enabled
```

Start service
```
./bin/mongod --config ./mongodb.conf
```

Add administrators and normal users.(the account and password must be consistent with the mongo.url in the manager/conf/svr.yml file)
```
./bin/mongo 127.0.0.1:27000

#Add administrator
use admin
db.createUser(
  {
    user: "admin",
    pwd: "q50stucaziKZw6DG",
    roles: [ { role: "userAdminAnyDatabase", db: "admin" }, "readWriteAnyDatabase" ]
  }
)

#Add normal users
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

### Deploy KAFKA
#### Java installation
> Install JAVA first, you can refer: https://www.oracle.com/java/technologies/javase/javase-jdk8-downloads.html

Here take Debian9 as an example to install
```
sudo apt-get update
sudo apt-get install default-jre
sudo apt-get install default-jdk
```
确认JAVA已经安装成功
Confirm that JAVA has been installed successfully
```
java -version
```
#### Kafka installation
Official website download page http://kafka.apache.org/downloads
```
wget https://apache.claz.org/kafka/2.7.0/kafka_2.13-2.7.0.tgz
tar -zxvf kafka_2.13-2.7.0.tgz
cd kafka_2.13-2.7.0
```
Start service
```
#1. Start zookeeper
bin/zookeeper-server-start.sh -daemon config/zookeeper.properties

#2. Modify kafka configuration config/server.properties, add the following configuration:
message.max.bytes=10485760
replica.fetch.max.bytes=10485760
fetch.message.max.bytes=10485760


#3. Start Kafka
bin/kafka-server-start.sh -daemon config/server.properties
```
Create Topic
```
bin/kafka-topics.sh --create --zookeeper 127.0.0.1:2181 --replication-factor 1 --partitions 200 --topic hids_svr

#Check whether the Topic was created successfully
bin/kafka-topics.sh --list --zookeeper 127.0.0.1:2181
```
#### Confirm whether the Kafka cluster is working
Send a message
```
bin/kafka-console-producer.sh --broker-list 127.0.0.1:9092 --topic hids_svr
> {"info":"test"}
```
Receive message
```
bin/kafka-console-consumer.sh --bootstrap-server 127.0.0.1:9092 --topic hids_svr --from-beginning
```
### Deploy Redis
Official website download page https://redis.io/download
```
wget https://download.redis.io/releases/redis-6.2.1.tar.gz
tar -zvxf redis-6.2.1.tar.gz
cd redis-6.2.1
make
sudo make install

#Start service
redis-server ./redis.conf
```
Modify the redis.conf configuration file, especially the following parts
```
#bind modify the local ip or 0.0.0.0
bind 0.0.0.0 ::1

# Turn off the include mode, allowing non-local access to redis
protected-mode no
```
> If it is a single-node redis cluster, you may encounter an error CLUSTERDOWN Hash slot not served during operation, and you need to execute the following commands to fix:
redis-cli --cluster fix 127.0.0.1:6379

English | [简体中文](install-zh_CN.md)
## Resource requirements
| Cluster | Machine Configuration | Quantity |
| ----- | ----- | ----- |
| MongoDB | | If the number of Agents> 1w, cluster deployment is recommended |
| KAFKA | | If the number of Agents> 1w, cluster deployment is recommended |
| Redis | | If the number of Agents> 1w, cluster deployment is recommended |
| ServiceDiscovery cluster | 4C8G | 1-5 (If agent number <1w, can be deployed standalone) |
| Manager cluster | 4C8G | 1-5 (If agent number <1w, can be deployed standalone) |
| AgentCenter cluster | 8C8G | Number of Agents/1500 |

## Replace Agent-AgentCenter communication certificate
If it is deployed in a production environment, it is strongly recommended replacing the Agent-AgentCenter communication certificate. If it is a test environment, you can ignore this step.
1. Generate a certificate randomly and replace the AgentCenter certificate.
``` 
git clone https://github.com/bytedance/Elkeid.git
cd Elkeid/server/build && ./cert_gen.sh elkeid.com hids-svr elkeid@elkeid.com
cp cert/* ../agent_center/conf/ 
```
2. Replace Agent certificate.
```
cp cert/ca.crt cert/client.crt cert/client.key ../../agent/transport/connection
```

## Deployment process
### Compile the binary
```
cd server/build && ./build.sh
```
Generate three compressed packages after compilation, copy them to the corresponding machine for deployment
```
service_discovery-xxx.tar.gz
agent_center-xxx.tar.gz
manager-xxx.tar.gz
```

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

Add administrators and normal users
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
Install JAVA first: https://www.oracle.com/java/technologies/javase/javase-jdk8-downloads.html
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

#Turn on cluster mode
cluster-enabled yes
```
> If it is a single-node redis cluster, you may encounter an error CLUSTERDOWN Hash slot not served during operation, and you need to execute the following commands to fix:
redis-cli --cluster fix 127.0.0.1:6379

### Deploy ServiceDiscovery
1. Copy the service_discovery-xxx.tar.gz generated in the first step to each server of the SD cluster and decompress it.
```
tar xvfz service_discovery-xxx.tar.gz
```
2. Modify the sd configuration file conf/conf.yaml
Mainly to change 3 places:
```
Server.Ip: This service IP, which is mainly modified to the local IP
Server.Port: The listening port of this service (the default is 8089)

Cluster.Mode: Configure to "config"
Cluster.Members: the addresses of other machines in the cluster

Auth.Enable: Whether to enable authentication in the registration interface
Auth.Keys: List of authentication keys. The client (AgentCenter/Manager) needs to get this key to access the sd. (You can generate random AKSKs for AgentCenter and Manager respectively and write them into the configuration)
```
3. Start the service
```
./sd
#If the service is normal, it can also run in the background
#nohup ./sd>/dev/null 2>&1 &
```

### Deployment Manager
1. Copy the manager-xxx.tar.gz generated in the first step to each server of the Manager cluster, and unzip it.
```
tar xvfz manager-xxx.tar.gz
```
2. Modify Manager configuration conf/svr.yml
Mainly to change 3 places:
```
redis.addrs: the address list of the redis cluster.
mongo.uri: the uri address of the mongodb cluster.
sd.addrs: the address list of the service discovery cluster.
```
3. Service initialization
```
#Create new users
./init -c conf/svr.yml -t addUser -u test1 -p 22222

#Add Mongodb index
./init -c conf/svr.yml -t addIndex -f conf/index.json
```
4. Start the service
```
./manager -c conf/svr.yml
#If the service is normal, it can also run in the background
#nohup ./manager -c conf/svr.yml>/dev/null 2>&1 &
```
> Manager will open HTTP service on port 6701 for API access and internal communication.

> In addition, please ensure that the communication between the Redis cluster and Mongodb cluster and the Manager cluster is reachable.

### Deploy AgentCenter
1. Copy the agent_center-xxx.tar.gz generated in the first step to each server in the AgentCenter cluster and decompress it.
```
tar xvfz agent_center-xxx.tar.gz
```
2. Modify the configuration conf/svr.yml of agent_center
Mainly to change 3 places:
```
manage.addrs: the address list of the Manager cluster.
sd.addrs: the address list of the service discovery cluster.
kafka.addrs: the address list of the kafka cluster.
```
3. Start the service
```
./agent_center -c conf/svr.yml
#If the service is normal, it can also run in the background
#nohup ./agent_center -c conf/svr.yml>/dev/null 2>&1 &
```
> AgentCenter will open RPC service on port 6751. Please keep this port reachable to all Agent machines.
AgentCenter will open HTTP service on port 6752, please keep this port reachable with all Manager machines.
AgentCenter will open the pprof service on port 6753 for debugging.

> In addition, please ensure that the communication between the Kafka cluster and the AgentCenter cluster machines is reachable.
## Start using
Deploy the Agent, you can check the Agent's online status through the API, and consume KAFKA data.

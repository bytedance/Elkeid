English | [简体中文](docker-install-zh_CN.md)
##  Description
The Docker version is only for quick testing, please do not use it in a production environment!
This version only includes Server, Agent please run on the corresponding machine.

##  Requirements
docker-ce >= 18  
docker-compose >= 1.20  
Golang >=1.16(recommended)
> Please refer to the official documentation for Golang installation：https://golang.org/doc/install  
> Please refer to the official documentation for Docker installation：https://docs.docker.com/engine/install/  
> Please refer to the official documentation for Docker-Compose installation: https://docs.docker.com/compose/install/

##  Installation
Step1. Download source code
```
git clone https://github.com/bytedance/Elkeid.git
```
Step2. Start dependent components:Kafka/Mongodb/Redis
```
cd Elkeid/server/build
docker-compose up
#If the service is normal, it can be run in the background
# docker-compose up -d
```
Later, `docker ps` will see 4 docker services elkeid_kafka, elkeid_mongodb, elkeid_redis, elkeid_zookeeper

Fix the redis state (for simplicity, the redis cluster has only one instance, and the cluster state needs to be manually fixed)
```
docker exec -it elkeid_redis sh

#run in the docker container
redis-cli --cluster fix 127.0.0.1:6379
#When the screen shows :Fix these slots by covering with a random node? (type'yes' to accept), then enter yes
```
> If you are prompted to get the docker image failed, please check the network and try again, or attach http/https proxy to docker pull

Step3. Compile and copy the compressed package to the corresponding directory
```
cd Elkeid/server/build && ./build.sh 

# 3 compressed packages will be generated
#service_discovery-*.tar.gz
#manager-*.tar.gz
#gent_center-*.tar.gz
```
Step4. Start ServiceDiscovery
```
tar xvf service_discovery-*.tar.gz
cd service_discovery && ./sd
#If the service is normal, it can be run in the background  
nohup ./sd>/dev/null 2>&1 &
```
Step5. Start Manager
```
tar xvf manager-*.tar.gz
cd manager 

#New users
./init -c conf/svr.yml -t addUser -u hids_test -p hids_test

#Add Mongodb index
./init -c conf/svr.yml -t addIndex -f conf/index.json

./manager
#If the service is normal, it can be run in the background
nohup ./manager>/dev/null 2>&1 &
```
Step6. Start AgentCenter
```
tar xvf agent_center-*.tar.gz
cd agent_center  && ./agent_center
#If the service is normal, it can be run in the background
nohup ./agent_center>/dev/null 2>&1 &
```
## Start using
You can run a test script to simply verify connectivity
```
cd server/agent_center/test && go run grpc_client.go
```

Configure the address of ServerDiscovery to [Agent](../../agent/README.md), then compile and deploy it, you can check the Agent's online status through the [Manager API](../README-zh_CN.md) or consume KAFKA data.

Agent data can be consumed from KAFKA:
```
cd server/agent_center/test && go run kafka_comsumer.go
```

English | [简体中文](docker-install-zh_CN.md)
##  Description
The Docker version is only for quick testing, please do not use it in a production environment!
This version only includes Server, Agent please run on the corresponding machine.

##  Requirements
docker-ce >= 18  
docker-compose >= 1.20  
Golang >=1.15(建议)
> Golang安装请参照官方文档：https://golang.org/doc/install  
> Docker安装请参考官方文档：https://docs.docker.com/engine/install/  
> Docker-Compose安装请参考官方文档: https://docs.docker.com/compose/install/

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
> If you are prompted to get the docker image failed, please check the network and try again, or attach http/https proxy to docker pull

Step3. Compile and copy the compressed package to the corresponding directory
```
cd Elkeid/server/build && ./build.sh 

# 将生成3个压缩包
#service_discovery-*.tar.gz
#manager-*.tar.gz
#gent_center-*.tar.gz
```
Step4. Start ServiceDiscovery
```
tar xvf service_discovery-*.tar.gz
cd service_discovery && ./sd
#If the service is normal, it can be run in the background  
#nohup ./sd>/dev/null 2>&1 &
```
Step5. Start Manager
```
tar xvf manager-*.tar.gz
cd manager 

#New users
./init -c conf/svr.yml -t addUser -u test_hids -p test_hids

#Add Mongodb index
./init -c conf/svr.yml -t addIndex -f conf/index.json

./manager
#If the service is normal, it can be run in the background
#nohup ./manager>/dev/null 2>&1 &
```
Step6. Start AgentCenter
```
tar xvf agent_center-*.tar.gz
cd agent_center  && ./agent_center
#If the service is normal, it can be run in the background
#nohup ./agent_center>/dev/null 2>&1 &
```

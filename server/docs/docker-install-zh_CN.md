[English](docker-install.md) | 简体中文
##  说明
Docker版只为快速体验使用，请不要在生产环境下使用!
该版本中只包括了Server, Agent请在相应的机器中运行。

##  依赖
docker-ce >= 18
docker-compose >= 1.20
Golang (建议使用版本>=1.15)
> Golang安装请参照官方文档：https://golang.org/doc/install
> Docker安装请参考官方文档：https://docs.docker.com/engine/install/
> Docker-Compose安装请参考官方文档：https://docs.docker.com/compose/install/

##  使用步骤
Step1. 下载源码
```
git clone https://github.com/bytedance/Elkeid.git
```
Step2. 启动依赖组件Kafka/Mongodb/Redis
```
Elkeid/server/build &&  docker-compose up -d
```
> 如果提示获取 docker image 失败，请检查网络并重试，或者给 docker pull 挂上 http/https 代理

Step3. 编译
```
cd Elkeid/server/build && ./build.sh 
tar xvf service_discovery-*.tar.gz
tar xvf manager-*.tar.gz
tar xvf agent_center-discovery-*.tar.gz
```
Step4. 启动ServiceDiscovery
```
cd service_discovery && ./sd
#如果服务无异常，也可放后台运行  
#nohup ./sd>/dev/null 2>&1 &
```
Step5. 启动Manager
```
cd ../manager 
./manager -c conf/svr.yml
#如果服务无异常，也可放后台运行  
#nohup ./manager -c conf/svr.yml>/dev/null 2>&1 &
```
Step6. 启动AgentCenter
```
cd ../agent_center 
./agent_center -c conf/svr.yml
#如果服务无异常，也可放后台运行  
#nohup ./agent_center -c conf/svr.yml>/dev/null 2>&1 &
```

##  依赖准备
###  1、准备Kubernetes集群
请准备用于运行Elkeid后台系统的Kubernetes集群，推荐使用1.18版本以上的k8s。可以复用已有的k8s集群。

> Kubernetes集群集群部署，请参照官方文档：https://kubernetes.io/zh/docs/home/, https://www.kubernetes.org.cn/docs  

###  2、编译Elkeid后台镜像
> 我们提供了预编好的Elkeid镜像，可以跳过这一步直接使用我们编译好的镜像:    
> [mg.1.0.0.tar](https://lf3-elkeid.bytetos.com/obj/elkeid-download/imags/mg.1.0.0.tar) [sd.1.0.0.tar](https://lf3-elkeid.bytetos.com/obj/elkeid-download/imags/sd.1.0.0.tar) [ac.1.0.0.tar](https://lf3-elkeid.bytetos.com/obj/elkeid-download/imags/ac.1.0.0.tar)   

需要准备好一台机器来编译Elkeid后台镜像，并且请确保编译机器上已经安装好docker
> Docker安装请参考官方文档：https://docs.docker.com/engine/install/  

然后执行  
```
git clone https://github.com/bytedance/Elkeid.git
cd Elkeid/server/build
./build_images.sh
```
执行完成后 `Elkeid/server/build` 目录下会生成下面三个文件：
```
mg.1.0.0.tar
sd.1.0.0.tar
ac.1.0.0.tar
```

###  3、将Elkeid后台镜像导入镜像仓库
如果有私有镜像仓库，可以直接将镜像导入私有仓库直接使用。  

这里提供一个直接导入的方法。
将三个镜像拷贝到k8s集群的每个节点，并执行一遍如下命令将镜像直接导入本地仓库。
如果是docker环境，请执行：
```
docker load <  mg.1.0.0.tar
docker load <  sd-1.0.0.tar
docker load <  ac-1.0.0.tar
```

如果是containerd环境，请执行
```
ctr -n k8s.io i import mg.1.0.0.tar
ctr -n k8s.io i import sd-1.0.0.tar
ctr -n k8s.io i import ac-1.0.0.tar
```
> 需要在集群的每个节点都导入一遍这三个镜像   
> 
> crictl安装配置请参考官方文档：https://kubernetes.io/zh/docs/tasks/debug-application-cluster/crictl/

###  4、生成所需的k8s配置
执行如下命令，生成新的通信证书和k8s配置文件。
```
cd Elkeid/server/build/kube/
./build_config.sh
```
> 注意该命令会在 Elkeid/server/build/cert 目录生成新的证书。所以必须重新编译Agent，不能复用已有的Agent，否则会因为证书不一致而无法正常运行。
> 如果不需要替换证书，可执行 ./build_config.sh -t simple

##  Server部署
* 下面所有步骤均需要在k8s集群的master上操作
###  1、同步所需配置到k8s的master上
将`Elkeid/server/build/kube`下的全部yaml文件都拷贝到k8s的master上，然后切换到文件所在目录，后续操作均此目录下操作。  
包括下面五个yaml文件:
```
kube_elkeid_svc.yaml  
kube_mongodb_svc.yaml  
kube_zookeeper_svc.yaml
kube_kafka_svc.yaml   
kube_redis_svc.yaml
```
###  2、创建k8s的命名空间
所有服务默认都运行在elkeid命名空间下，请执行下面命令创建所需的命名空间:
```
kubectl create namespace elkeid
```
###  3、运行依赖组件
> 运行依赖的镜像存在在docker的官方仓库中(地址)，运行前请确保运行的k8s能连通docker的官方仓库。镜像取决时间取决于你的机器网络情况。  
>  
> 这里提供的方法只为了测试或体验Elkeid，并且没有配置永久存储和集群外部访问，不适用于生产环境使用，请使用前注意。

执行下面命令，安装zookeeper、mongodb、redis、kafka。
```
kubectl apply -f kube_zookeeper_svc.yaml
kubectl apply -f kube_redis_svc.yaml
kubectl apply -f kube_mongodb_svc.yaml
kubectl apply -f kube_kafka_svc.yaml
```

等待若干秒(取决于镜像拉取的速度)，按照下面步骤逐一检查各个服务：
- 执行`kubectl -n elkeid get svc`，检查是否存在`zookeeper-service/mongodb-service/redis-service/kafka-service`这四个service
- 执行`kubectl -n elkeid get pod`，检查分别以`zookeeper-/redis-/mongodb-/kafka-`开头的POD是否STATUS都为Running

上述检查如果都没问题，说明各个服务启动成功。

###  3、运行ServerDiscovery&Manager&AgentCenter
执行命令
```
kubectl apply -f kube_elkeid_svc.yaml
```

等待若干秒(取决于镜像拉取的速度)，按照下面步骤逐一检查各个服务：
- 执行`kubectl -n elkeid get svc`，检查是否存在elkeid-sd/elkeid-mg/elkeid-ac这三个service
- 执行`kubectl -n elkeid get pod`，检查分别以sd-/mg-/ac-开头的POD是否STATUS都为Running
- 执行命令`curl http://localhost:30088/registry/summary`，检查输出是否为`{"data":{"hids_manage":1,"hids_svr_grpc":1,"hids_svr_http":1},"msg":"ok"}`

上述检查如果都没问题，说明各个服务启动成功。

接着执行如下命令，新增用户。
```
// 请将{{mg-POD-name}}替换成你mg服务对应的pod name(以mg-开头)
// {{passwd}}和{{user_name}}需要自定义。
// example: kubectl exec -it mg-69b74cb94-jswbt -n elkeid -- ./init  -t addUser -p hids_test -u hids_test
kubectl exec -it {{mg-POD-name}} -n elkeid -- ./init  -t addUser -p {{passwd}} -u {{user_name}}
```

##  Agent部署
Server部署完后，可以得到以下资源：
- Manager地址(记为mg_host:mg_port): {{k8s任意节点IP}}:30088
- AgentCenter地址(记为ac_host:ac_port): {{k8s任意节点IP}}:30088

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
        priLB["ac"] = "ac_host:ac_port"  
        //这里"elkeid.com"需要与生成证书时使用的域名一致，如果生成时不是默认配置需要在这里一起修改
        setDialOptions(CaCert, ClientKey, ClientCert, "elkeid.com")
}
```
接着参照文档[Agent编译和部署](./quick-start-zh_CN.md#2-编译agent) 后续步骤进行编译和部署Agent即可。

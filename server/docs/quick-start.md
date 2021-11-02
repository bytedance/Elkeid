English | [简体中文](quick-start-zh_CN.md)

## Dependent environment preparation

### 1. Dependent component preparation
The Elkeid backend relies on the following components, please prepare before performing other operations. These components can be reused with other systems.

|Components|Recommended configuration|Is it necessary|Remarks|
| :- | :- | :- | :- |
|MongoDB|10GB per 1000 Agents|Yes|If Agent>1w, cluster deployment is recommended|
|Kafka|25Partation per 1000 Agents|Yes|If Agent>1w, cluster deployment is recommended|
|Redis|1GB memory per 1000 Agents|Yes|If Agent>1w, cluster deployment is recommended|

For installation tutorial, please refer to [Dependent Environment Installation Guide](install-compose.md)

### 2. Elkeid Server cluster deployment machine preparation
Elkeid backend includes three parts, ServiceDiscovery, Manager, and AgentCenter, which can be deployed on a single machine or in a cluster. The recommended configuration is as follows:

|Components|Recommended configuration|Is it necessary|Remarks|
| :- | :- | :- | :- |
|ServiceDiscovery|4C8G per 1000 Agents|Yes|If Agent>1w, cluster deployment is recommended|
|Manager|4C8G per 1000 Agents|Yes|If Agent>1w, cluster deployment is recommended|
|AgentCenter|8C8G per 1000 Agents|Yes|If Agent>1w, cluster deployment is recommended|

> **Before installation, please ensure that the Server cluster machines can communicate with each other! **
> **Server machine can communicate with Mongodb/Kafka/Redis cluster, otherwise it will not work normally! **

### 3. Compile dependent environment
-Golang 1.16 (required)

> **Compiling Agent and Server binaries requires Golang 1.16**
> **For the installation of Golang, please refer to the official document: <https://golang.org/doc/install>**

## Code download
The code of Agent and Server is in https://github.com/bytedance/Elkeid/, which can be downloaded through git/ or directly on the page.
### Download via GIt

```
git clone https://github.com/bytedance/Elkeid.git
```
### You can also download directly through the front-end page
Visit https://github.com/bytedance/Elkeid to download directly

## Server compilation and deployment
### 1. Replace Agent-AgentCenter communication certificate
Production environment deployment, it is strongly recommended to perform this deployment and replace the Agent-AgentCenter communication certificate. If you are in a test environment, you can ignore this step.

Execute the following script in the `Elkeid/server/build` directory.
```
cd Elkeid/server/build
./cert_gen.sh elkeid.com hids-svr elkeid@elkeid.com
```
After the execution is complete, you will see output similar to the following
```
Generating RSA private key, 2048 bit long modulus
.................................................. ....................................+++++
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
> ./cert_gen.sh [domain] hids-svr [email]
> The email elkeid@elkeid.com in the command can be replaced with any other.
> Domain elkeid.com is not recommended to be modified. If you modify it, you need to modify the domain configured in `Elkeid/agent/transport/connection/product.go` synchronously.

### 2. Replace the back-end AK and SK authentication keys
AppKey+secretKey is used for internal interface authentication between backend components. The appKey is a 16-bit random string composed of numbers and lowercase letters, and the secretKey is a 32-bit random string composed of numbers and lowercase letters.
We need to generate two pairs of AK:SK combinations, each of which requires a pair of agent_center/manager, and also needs to generate a manager_key to initialize the token. And replace these keys in the configuration file corresponding to the server.
   
Please execute the following script in the Elkeid/server/build directory, it will automatically generate and replace AKSK for us.
```
cd Elkeid/server/build
bash ./update_aksk.sh
```
After the execution is complete, you will see the following output:
```
generate key ok!
update agent_center/conf/svr.yml ok!
update service_discovery/conf/conf.yaml ok!
update manager/conf/svr.yml ok!
success!
```
If you see other errors, please confirm whether it is currently in the `Elkeid/server/build` directory.
### 3. Compile the Elkeid Server binary
> Precondition: Golang (version 1.16)
> Please refer to the official document for Golang installation: https://golang.org/doc/install
```
cd Elkeid/server/build
./build.sh
```
After successful execution, the output will be as follows:
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
And generate three compressed packages, copy them to the corresponding machine directory for deployment.
```
service_discovery-xxx.tar.gz
agent_center-xxx.tar.gz
Manager-xxx.tar.gz
```
If there is an error of `i/o timeout` during the running of the script, it is caused by the network failure. Please configure go proxy.
> For Go proxy configuration, please refer to: https://github.com/goproxy/goproxy.cn/blob/master/README.zh-CN.md

### 4. Deploy Service Discovery
4.1 Copy the service_discovery-xxx.tar.gz generated in the third step to each server in the SD cluster, and unzip it.
```
tar xvfz service_discovery-xxx.tar.gz
```
4.2 Modify the sd configuration conf/conf.yaml, modify the following 0.0.0.0 and 127.0.0.1 to the local IP of the deployment machine:
```
Server:
  Ip: "0.0.0.0"
  Port: 8088

Cluster:
  Mode: "config"
  Members: ["127.0.0.1:8088"]
```
4.3 Install the service and start the service
```
//install service
sudo make install

//Start the service
sudo systemctl daemon-reload
sudo systemctl enable elkeid_sd
sudo systemctl start elkeid_sd
```
Check the `/opt/Elkeid_SD/log/service_discovery.log` file. If you see the following output without any error report, the service has started successfully:
```
{"level":"info","ts":1629172213.686969,"msg":"[START_SERVER]","info":"Listening and serving on :0.0.0.0:8088\n"}
```
4.4 Troubleshooting
-In case of abnormal situations, you can check the log to troubleshoot. The default path of the log is: `/opt/Elkeid_SD/log/service_discovery.log`. And systemd log: `journalctl -u elkeid_sd`.
-Modify configuration or other changes may need to take effect before they can take effect. Restart command: `sudo systemctl restart elkeid_sd`

> By default, ServiceDiscovery will open HTTP service on port 8088 for external API access and internal communication. Please keep this port to communicate with all Agent machines smoothly.
> At the same time, it is necessary to keep the communication between this port and all Manager/AgentCenter machines smooth.

### 5. Deployment Manager
5.1 Copy the Manager-xxx.tar.gz generated in the third step to each server of the Manager cluster and decompress it.
```
tar xvfz manager-xxx.tar.gz
```
5.2 Modify the configuration of Manager conf/svr.yml:
  -Modify redis configuration: redis.passwd is the redis password (empty or not set). redis.addrs is the redis address.
  -Modify sd.addrs to the address list of the service discovery cluster. (That is, the ip:port of ServiceDiscovery deployed in step 4)
  -Modify mongo.uri to the uri address of the mongodb cluster, in the format mongodb://{{user_name}}:{{passwd}}@{{ip}}:{{port}}/{{dbname}}?authSource ={{dbname}}. And modify mongo.dbname to the corresponding db name
```
redis:
  addrs: ["127.0.0.1:6379"]
  passwd:
  
sd:
  addrs: ["127.0.0.1:8088"]

mongo:
  uri: mongodb://hids:I7ILUz7WhOJUWygy@127.0.0.1:27000/hids_server?authSource=hids_server
  dbname: hids_server
```
5.3 Service initialization.
  -To add a new user, please save the new user name and password, which will be used in the subsequent Manager API interface /api/v1/user/login.
```
./init -c conf/svr.yml -t addUser -u hids_test -p hids_test
```
After the execution is successful, you will see the following output. If there are other errors, it means that the Mongodb configuration is incorrect. Please confirm whether the machine and the mongodb cluster are smooth.
```
InsertedID: ObjectID("60cc447e809e3afbd63ee256") {hids_test 689e877c0fcf65fd361fec8eae645f1d514d451a VlBzgbaiCMRAjWwh 0}
```
  -Add indexes. Mongodb not adding indexes will affect the system performance, so please make sure that the necessary fields of the system are indexed.
```
#indexAdd Mongodb index
./init -c conf/svr.yml -t addIndex -f conf/index.json
```
5.4 Install the service and start the service
```
//install service
sudo make install

//Start the service
sudo systemctl daemon-reload
sudo systemctl enable elkeid_manager
sudo systemctl start elkeid_manager
```
Check the `/opt/Elkeid_Manager/log/svr.log` file. If you see the following output without any error report, the service has started successfully:
```
{"level":"info","ts":1629185924.3975492,"msg":"JOB_MANAGE","info":"job manage init"}
{"level":"info","ts":1629185924.398058,"msg":"NewRegistry","info":"new registry: discovery.ServerRegistry{Name:\"hids_manage\", Ip:\"10.227.2.103 \", Port:6701, Weight:0, SDHost:\"127.0.0.1:8088\", stopChan:(chan struct {})(0xc00030e960)}"}
{"level":"info","ts":1629185924.3991835,"msg":"NewRegistry","info":"register response: {\"msg\":\"ok\"}"}
{"level":"info","ts":1629185924.3993368,"msg":"[START_SERVER]","info":"Listening and serving on :6701"}
```
5.5 Troubleshooting
-In case of abnormal situations, you can check the log to troubleshoot. The default path of the log is: `/opt/Elkeid_Manager/log/svr.log`. And systemd log: `journalctl -u elkeid_manager`.
-Modified configuration or other changes may need to take effect before they can take effect. Restart command: `sudo systemctl restart elkeid_manager`

5.6 Service verification
  -Check whether the service is registered successfully:
   Execute `curl http://{{sd_ip:sd_port}}/registry/detail?name=hids_manage`
   If it returns abnormally, please check whether the sd.addrs in the configuration file conf/svr.yml in step 2 is configured correctly. If it is still not resolved, please refer to **[QA](qa-zh_CN.md) 2Service Discovery Exception Troubleshooting** to solve it.
```
//Normal return, returned to the address registered by the manager
{"data":[{"name":"hids_manage","ip":"xxxx","port":6701,"status":0,"create_at":1623400287,"update_at":1623402507,"weight" :0,"extra":{}}],"msg":"ok"}

//Exception return
{"data":[],"msg":"ok"}
```

> By default, Manager will open HTTP service on port 6701 for external API access and internal communication.
> In addition, please ensure that the communication between the Redis cluster and Mongodb cluster and the Manager cluster machine is smooth.

### 6. Deploy AgentCenter
6.1 Copy the agent_center-xxx.tar.gz generated in the third step to each server in the AgentCenter cluster, and unzip it.
```
tar xvfz agent_center-xxx.tar.gz
```
6.2 Modify the configuration conf/svr.yml of agent_center mainly in 3 places:
  -Modify sd.addrs to the address list of the service discovery cluster. (That is, the ip:port of ServiceDiscovery deployed in step 4)
  -Modify manage.addrs to the address list of the Manager cluster. (Ie the ip:port of the Manager deployed in step 5)
  -Modify kafka.addrs to the address list of the kafka cluster. And modify kafka.topic to the write topic of the kafka cluster
```
sd:
  addrs:
    -127.0.0.1:8088
    
manage:
  addrs:
    -127.0.0.1:6701

kafka:
  addrs:
    -127.0.0.1:9092
  topic: hids_svr
```
6.3 Install the service and start the service
```
//install service
sudo make install

//Start the service
sudo systemctl daemon-reload
sudo systemctl enable elkeid_ac
sudo systemctl start elkeid_ac
```
Check the `/opt/Elkeid_AC/log/svr.log` file. If you see the following output and no error is reported, the service has started successfully:
```
{"level":"info","ts":1629186151.7101195,"msg":"InitComponents","info":"KAFKA Producer: [127.0.0.1:9092]-hids_svr"}
{"level":"info","ts":1629186151.731163,"msg":"[MAIN]","info":"START_SERVER"}
{"level":"info","ts":1629186151.731474,"msg":"RunServer","info":"####HTTP_LISTEN_ON:6752"}
{"level":"info","ts":1629186151.734691,"msg":"RunServer","info":"####TCP_LISTEN_OK: [::]:6751"}
{"level":"info","ts":1629186151.7313871,"msg":"NewRegistry","info":">>>>new registry: {hids_svr_grpc 10.227.2.103 %!s(int=6751) %! s(int=0) map[] [127.0.0.1:8088] %!s(chan struct {}=0xc00021c120)}"}
{"level":"info","ts":1629186151.7366326,"msg":"NewRegistry","info":">>>>new registry {\"name\":\"hids_svr_grpc\",\"ip \":\"10.227.2.103\",\"port\":6751,\"weight\":0,\"extra\":null} resp: {\"msg\":\"ok\"} "}
{"level":"info","ts":1629186151.7366986,"msg":"NewRegistry","info":">>>>new registry: {hids_svr_http 10.227.2.103 %!s(int=6752) %! s(int=0) map[] [127.0.0.1:8088] %!s(chan struct {}=0xc00013a0c0)}"}
{"level":"info","ts":1629186151.7382596,"msg":"NewRegistry","info":">>>>new registry {\"name\":\"hids_svr_http\",\"ip \":\"10.227.2.103\",\"port\":6752,\"weight\":0,\"extra\":null} resp: {\"msg\":\"ok\"} "}
```
The HTTP service monitors port 6752, and the TCP service monitors port 6751, and the registration to the service discovery has been successful.
6.4 Troubleshooting
-In case of abnormal situations, you can check the log to troubleshoot. The default path of the log is: `/opt/Elkeid_AC/log/svr.log`. And systemd log: `journalctl -u elkeid_ac`.
-Modify configuration or other changes may need to take effect, restart command: `sudo systemctl restart elkeid_ac`
6.5 Service verification
  -Check whether the service is registered successfully:
   Execute `curl http://{{sd_ip:sd_port}}/registry/detail?name=hids_svr_grpc`
   If it returns abnormally, please check whether the sd.addrs in the configuration file conf/svr.yml in step 2 is configured correctly. If it is still not resolved, please refer to **[QA](qa-zh_CN.md) 2Service Discovery Exception Troubleshooting** to solve it.
```
//Normal return, returned to the address registered by the manager
{"data":[{"name":"hids_svr_grpc","ip":"xxxx","port":6751,"status":0,"create_at":1623403853,"update_at":1623403853,"weight" :0,"extra":null}],"msg":"ok"}

//Exception return
{"data":[],"msg":"ok"}
```

> AgentCenter will open the RPC service on port 6751. Please keep this port to communicate with all Agent machines.
> AgentCenter will open HTTP service on port 6752. Please keep this port to communicate with all Manager machines. AgentCenter will open the pprof service on port 6753 for debugging.
>
> In addition, please ensure that the communication between the Kafka cluster and the AgentCenter cluster machines is smooth.
### 8. Port Policy
In order for the entire system to operate normally, by default, at least the following access policies need to be activated:
|sip|sport|dip|dport|Remarks|
| :- | :- | :- | :- | :- |
|All Agent/Manager/AgentCenter|*|ServiceDiscovery|8088|
All Agent/Manager/AgentCenter/other machines that need to access managerAPI|*|Manager|6701|http service|
|Agent machine|*|AgentCenter|6751|agent report data|
|All Manager machines|*|AgentCenter|6752|http service|
|Manager/AgentCenter/ServiceDiscovery|*|kafka cluster/redis cluster/mongodb cluster|corresponding cluster port|

## Agent compilation and deployment
After the server is deployed, you can get the following resources:
-ServiceDiscovery address (denoted as sd_host) and port (denoted as sd_port)
-Manager address (denoted as ma_host) and port (denoted as ma_port)
-AgentCenter address (denoted as ac_host) and port (denoted as ac_port)
### 1. Configure Agent
Replace Elkeid/agent/transport/connection/product.go with the following:
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
        //Here "elkeid.com" needs to be consistent with the domain used when generating the certificate, if it is not the default configuration when generating it, you need to modify it here together
        setDialOptions(CaCert, ClientKey, ClientCert, "elkeid.com")
}
```
### 2. Compile Agent
```
cd Elkeid/agent
mkdir output
go build -o output/elkeid-agent
```
### 3. Install and start the Agent
After obtaining the above binary product, install and deploy on the terminal machine:
Products need to be distributed among different machines, so I won’t elaborate on it here
```
mkdir -p /etc/elkeid
cp output/elkeid-agent /etc/elkeid
```
Start in the background:
There is no process guarding and self-protection provided here. If necessary, you can implement it by yourself through systemd/cron. There is no requirement here.
```
cd /etc/elkeid && /etc/elkeid/elkeid-agent &
```
### 4. Verify Agent status
Check the Agent log. If you see that it has started and keeps heartbeat data printed to the log, the deployment is successful; if the process disappears/no (empty) log/stderr has panic, the deployment fails. If you confirm that your deployment steps are OK, please Raise issues or communicate in groups.
```
ps aux|grep elkeid-agent
cat /etc/elkeid/log/elkeid-agent.log
```
Expected output:
```
2021-04-15T15:32:57.937+0800 INFO agent/main.go:67 Elkeid Agent:v1.6.0.0
2021-04-15T15:32:57.937+0800 INFO agent/main.go:68 AgentID: f4c6d306-3d4b-4eb7-abe7-b15757acbb27
2021-04-15T15:32:57.937+0800 INFO agent/main.go:69 PrivateIPv4:[10.0.0.1]
2021-04-15T15:32:57.937+0800 INFO agent/main.go:70 PublicIPv4:[]
2021-04-15T15:32:57.937+0800 INFO agent/main.go:71 PrivateIPv6:[fdbd:dc02:ff:1:1:225:85:27]
2021-04-15T15:32:57.937+0800 INFO agent/main.go:72 PublicIPv6:[]
2021-04-15T15:32:57.937+0800 INFO agent/main.go:73 Hostname:test
2021-04-15T15:32:57.938+0800 INFO report/report.go:119 map[cpu:0.00000 data_type:1000 io:12288 kernel_version:4-amd64 memory:12009472 net_type: platform:debian platform_version:9.13 plugins:[] slab:1271408 timestamp:1618471977]
2021-04-15T15:32:58.118+0800 INFO transport/client.go:69
2021-04-15T15:33:27.939+0800 INFO report/report.go:119 map[cpu:0.00101 data_type:1000 io:0 kernel_version:4-amd64 memory:14602240 net_type:sd platform:debian platform_version:9 plugins:[ ] slab:1273792 timestamp:1618472007]
```
You can see that `AgentID:f4c6d306-3d4b-4eb7-abe7-b15757acbb27` is printed in the log. We will use this AgentID as an example for configuration.

### 5. Compile the plugin
After the Agent is started and the state is normal, it means that the Agent-Server has established a stable communication link, but the Agent itself only has the functions of monitoring/communication/control, and other security functions are carried on other plug-ins, so we need to perform the plug-in Compile and distribute.
> We provide pre-compiled plug-ins, if you use pre-compiled plug-ins, you can directly **skip this step**.
* driver plug-in: see [driver plug-in compilation](../../agent/driver/README-zh_CN.md#compile)
* journal_watcher plugin: see [journal_watcher plugin compilation](../../agent/journal_watcher/README-zh_CN.md#compile)
* collector plugin: see [collector plugin compilation](../../agent/collector/README-zh_CN.md#compilation)
After compiling, you should get three binary files of driver journal_watcher collector.
### 6. Upload the plugin
Calculate the sha256 of the above two ternary files, upload them to an accessible file server, and obtain the corresponding download address:
We have uploaded the pre-compiled plug-in. If you use the pre-compiled plug-in, you can skip this step directly. The following will also take our pre-compiled plug-in address as an example.
-driver plug-in (sha256: d817195d0ce10974427ed15ef9fa86345bd666db83f5168963af4bb46bbc08d6)
```
https://lf3-elkeid.bytetos.com/obj/elkeid-download/plugin/driver/driver_1.6.0.0_amd64.plg
https://lf6-elkeid.bytetos.com/obj/elkeid-download/plugin/driver/driver_1.6.0.0_amd64.plg
https://lf9-elkeid.bytetos.com/obj/elkeid-download/plugin/driver/driver_1.6.0.0_amd64.plg
https://lf26-elkeid.bytetos.com/obj/elkeid-download/plugin/driver/driver_1.6.0.0_amd64.plg
```
-journal_watcher plugin (sha256: a0c065514debf6f2109aa873ece86ec89b0e6ccedfa05c124b5863a4568ee20c)
```
https://lf3-elkeid.bytetos.com/obj/elkeid-download/plugin/journal_watcher/journal_watcher_1.6.0.0_amd64.plg
https://lf6-elkeid.bytetos.com/obj/elkeid-download/plugin/journal_watcher/journal_watcher_1.6.0.0_amd64.plg
https://lf9-elkeid.bytetos.com/obj/elkeid-download/plugin/journal_watcher/journal_watcher_1.6.0.0_amd64.plg
https://lf26-elkeid.bytetos.com/obj/elkeid-download/plugin/journal_watcher/journal_watcher_1.6.0.0_amd64.plg
```
-collector plugin (sha256: f6e0b34de998844cbfc95ae0e47d39225c2449833657a6a6289d9722d8e2fdc8)
```
https://lf3-elkeid.bytetos.com/obj/elkeid-download/plugin/collector/collector_1.6.0.0_amd64.plg
https://lf6-elkeid.bytetos.com/obj/elkeid-download/plugin/collector/collector_1.6.0.0_amd64.plg
https://lf9-elkeid.bytetos.com/obj/elkeid-download/plugin/collector/collector_1.6.0.0_amd64.plg
https://lf26-elkeid.bytetos.com/obj/elkeid-download/plugin/collector/collector_1.6.0.0_amd64.plg
```
### 7. Configure the plugin
The Manager API needs to be authenticated before configuring the plug-in:
> For details, please refer to [API interface document](../README-zh_CN.md#api interface document)
>
> If you modify the `username` and `password` when deploying the Manager, remember to make the corresponding changes below
>
```
curl --location --request POST'http://m_host:m_port/api/v1/user/login' \
--data-raw'{
   "username": "hids_test",
   "password": "hids_test"
}'
```
The authentication token is included in the response (all other interface requests that follow require the header to carry this token):
```
{
   "code": 0,
   "msg": "success",
   "data": {
       "token": "BUVUDcxsaf%^&%4643667"
   }
}
```
Add the token to the request header of the configuration plug-in, and write the request body according to the required AgentID, plug-in name, plug-in version, plug-in sha256, and plug-in download address:
```
curl --location --request POST'http://m_host:m_port/api/v1/agent/createTask/config' -H "token:BUVUDcxsaf%^&%4643667" --data-raw'{
   "id_list": [
       "f4c6d306-3d4b-4eb7-abe7-b15757acbb27"
   ],
   "data": {
       "config": [
           {
               "name": "driver",
               "download_url": [
                   "https://lf3-elkeid.bytetos.com/obj/elkeid-download/plugin/driver/driver_1.6.0.0_amd64.plg","https://lf6-elkeid.bytetos.com/obj/elkeid-download /plugin/driver/driver_1.6.0.0_amd64.plg","https://lf9-elkeid.bytetos.com/obj/elkeid-download/plugin/driver/driver_1.6.0.0_amd64.plg","https:/ /lf26-elkeid.bytetos.com/obj/elkeid-download/plugin/driver/driver_1.6.0.0_amd64.plg"
               ],
               "version": "1.6.0.0",
               "sha256": "d817195d0ce10974427ed15ef9fa86345bd666db83f5168963af4bb46bbc08d6",
               "detail": ""
           },
           {
               "name": "journal_watcher",
               "download_url": [
                   "https://lf3-elkeid.bytetos.com/obj/elkeid-download/plugin/journal_watcher/journal_watcher_1.6.0.0_amd64.plg","https://lf6-elkeid.bytetos.com/obj/elkeid-download /plugin/journal_watcher/journal_watcher_1.6.0.0_amd64.plg","https://lf9-elkeid.bytetos.com/obj/elkeid-download/plugin/journal_watcher/journal_watcher_1.6.0.0_amd64.plg","https:/ /lf26-elkeid.bytetos.com/obj/elkeid-download/plugin/journal_watcher/journal_watcher_1.6.0.0_amd64.plg"
               ],
               "version": "1.6.0.0",
               "sha256": "a0c065514debf6f2109aa873ece86ec89b0e6ccedfa05c124b5863a4568ee20c",
               "detail": ""
           },
{
               "name": "collector",
               "download_url": [
                   "https://lf3-elkeid.bytetos.com/obj/elkeid-download/plugin/collector/collector_1.6.0.0_amd64.plg","https://lf6-elkeid.bytetos.com/obj/elkeid-download /plugin/collector/collector_1.6.0.0_amd64.plg","https://lf9-elkeid.bytetos.com/obj/elkeid-download/plugin/collector/collector_1.6.0.0_amd64.plg","https:/ /lf26-elkeid.bytetos.com/obj/elkeid-download/plugin/collector/collector_1.6.0.0_amd64.plg"
               ],
               "version": "1.6.0.0",
               "sha256": "f6e0b34de998844cbfc95ae0e47d39225c2449833657a6a6289d9722d8e2fdc8",
               "detail": ""
           }
       ]
   }
}'
```
In the response, we can see the following:
```
{"code":0,"msg":"success","data":{"count":1,"task_id":"1618474279380056335bbGGcn"}}
```
Among them, count represents 1 machine to be configured, task_id: 1618474279380056335bbGGcn is the id of the task to be executed.
### 8. Send configuration
Through the task_id obtained above, we construct the following request:
```
curl --location --request POST'http://m_host:m_port/api/v1/agent/controlTask' -H "token:BUVUDcxsaf%^&%4643667" --data-raw'{
   "task_id": "1618474279380056335bbGGcn",
   "action": "run",
   "rolling_percent": 1,
   "concurrence": 100
}'
```
You can see the following response, indicating that the configuration has been issued:
```
{"code":0,"msg":"success","data":{"id_count":1,"jobID":"id-Agent_Config-1618474660501972408","taskID":"1618474279380056335bbGGcn"}}
```
### 9. Verify configuration
In the agent log, we can see the following records:
```
2021-04-15T16:17:40.537+0800 INFO transport/client.go:69 Config:<Name:"driver" Version:"1.6.0.0" SHA256:"d817195d0ce10974427ed15ef9fa86345bd666db83f5168963af4bb46bbc08d6" DownloadURL:"https://lf3-elkeid. bytetos.com/obj/elkeid-download/plugin/driver/driver_1.6.0.0_amd64.plg" DownloadURL:"https://lf6-elkeid.bytetos.com/obj/elkeid-download/plugin/driver/driver_1.6.0 .0_amd64.plg" DownloadURL:"https://lf9-elkeid.bytetos.com/obj/elkeid-download/plugin/driver/driver_1.6.0.0_amd64.plg" DownloadURL:"https://lf26-elkeid.bytetos .com/obj/elkeid-download/plugin/driver/driver_1.6.0.0_amd64.plg"> Config:<Name:"journal_watcher" Version:"1.6.0.0" SHA256:"a0c065514debf6f2109aa873ece86ec89b0e6ccedfa05c124b5863:"Downloada4568ee20c" -elkeid.bytetos.com/obj/elkeid-download/plugin/journal_watcher/journal_watcher_1.6.0.0_amd64.plg" DownloadURL:"https://lf6-elkeid.bytetos.com/obj/elkeid-download/plugin/journal_watcher/ journal_watcher_1.6.0.0_amd64.plg" DownloadURL:"https://lf9-elkeid.byte tos.com/obj/elkeid-download/plugin/journal_watcher/journal_watcher_1.6.0.0_amd64.plg" Downloa
dURL:"https://lf26-elkeid.bytetos.com/obj/elkeid-download/plugin/journal_watcher/journal_watcher_1.6.0.0_amd64.plg">
```
This shows that the instructions issued by the plug-in have been received, and then we can see the related logs of the plug-in loading:
```
2021-04-15T16:17:42.803+0800 INFO plugin/plugin.go:162 Plugin work directory: /etc/elkeid/plugin/driver/
2021-04-15T16:17:42.807+0800 INFO plugin/server.go:126 Received a registration:{Pid:1746809 Name:driver Version:1.6.0.0}
2021-04-15T16:17:42.807+0800 INFO plugin/server.go:141 Plugin has been successfully connected:&{name:driver version:1.6.0.0 checksum:a9ab7a2eda69b83d830a6061a393f886a7b125ea63e7ae1df4a276105764b37000809 pg: 0xc0003880003 140809 runtimeid: 0xc0003880003 IO:253952 CPU:0 reader:0xc00007e200 exited:{Value:{v:false} _:[]} Counter:{_:[] v:0}}
2021-04-15T16:17:43.649+0800 INFO plugin/plugin.go:162 Plugin work directory: /etc/elkeid/plugin/journal_watcher/
2021-04-15T16:17:43.650+0800 INFO plugin/server.go:126 Received a registration:{Pid:1746883 Name:journal_watcher Version:1.6.0.0}
2021-04-15T16:17:43.650+0800 INFO plugin/server.go:141 Plugin has been successfully connected:&{name:journal_watcher version:1.6.0.0 checksum:a0c065514debf6f2109aa873ece86ec89b0e6ccedfa05c124b5863a4568ee20c cmd:0xc000883580 runtime: 0xc000883580 IO:0 CPU:0 reader:0xc000324180 exited:{Value:{v:false} _:[]} Counter:{_:[] v:0}}
2021-04-15T16:17:57.939+0800 INFO report/report.go:119 map[cpu:0.02274 data_type:1000 io:24526848 kernel_version:4-amd64 memory:18325504 net_type:sd platform:debian platform_version:9.13 plugins:[ {"rss":9654272,"io":4399104,"cpu":0,"name":"driver","version":"1.6.0.0","pid":1746809,"qps":188.66666666666666}, {"rss":8192,"io":0,"cpu":0,"name":"journal_watcher","version":"1.6.0.0","pid":1746883,"qps":0.03333333333333333}] slab:2868720 timestamp:1618474677]
2021-04-15T16:18:27.939+0800 INFO report/report.go:119 map[cpu:0.03518 data_type:1000 io:0 kernel_version:4-amd64 memory:17645568 net_type:sd platform:debian platform_version:9.13 plugins:[ {"rss":13709312,"io":479232,"cpu":0.015414258189652063,"name":"driver","version":"1.6.0.0","pid":1746809,"qps":428.73333333333335}, {"rss":8192,"io":0,"cpu":0,"name":"journal_watcher","version":"1.6.0.0","pid":1746883,"qps":0}] slab:2875588 timestamp:1618474707]
```
### 10. Validate plug-in data
Now, you can consume data from Kafka, which contains the data reported by all plug-ins and agents.


## Manager API User Guide
Only part of the interface usage is introduced here. For more interface usage, please refer to [API interface](https://documenter.getpostman.com/view/9865152/TzCTZ5Do#intro).

It is recommended to use [Postman](https://www.postman.com/) to operate, it will be more convenient to use and manage. After installing Postman, click the above link and import it to the local by opening the "Run in Postman" in the upper right corner. . In addition, during actual use, please modify the address to the address of the corresponding manager.
### 1. Login
Before using all api interfaces, you need to log in first, get the token, and then add the token to the request header.
```
curl --location --request POST'http://127.0.0.1:6701/api/v1/user/login' \
--data-raw'{
    "username": "hids_test",
    "password": "hids_test"
}'

#response
{"code":0,"msg":"success","data":{"token":"xxxxx"}}
```
### 2. Query Agent status
#### 2.1 Get all agent status
```
curl --location --request GET'http://127.0.0.1:6701/api/v1/agent/getStatus' -H'token:xxxxxxxxx'
```
#### 2.2 Get the status of the specified agent
```
curl --location --request GET'http://127.0.0.1:6701/api/v1/agent/getStatus/33623333-3365-4905-b417-331e183330' -H'token:xxxxxxxxx'
```
#### 2.3 Query Agent status based on filter
```
#Query all agents with last_heartbeat_time>1617172110
curl --location -H'token:xxxxxxxxx' --request POST'http://127.0.0.1:6701/api/v1/agent/getStatus/filter' \
--data-raw'{
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
### 3. Agent task
#### 3.1 Query task status
```
#Query task 1617876668390045859aiCMRA execution status
curl --location -H'token:xxxxxxxxx' --request GET'http://127.0.0.1:6701/api/v1/agent/getTask/1617876668390045859aiCMRA?result=true&detail=false'
```
### 4. Set Agent default configuration
#### 4.1 Set Agent default configuration
The default configuration of the agent is used to control which part of the plug-in is enabled by the newly-accessed agent. The default setting is empty (empty means that the newly connected agent will not automatically open any plug-ins).
```
curl --location --request POST'http://127.0.0.1:6701/api/v1/agent/updateDefaultConfig' -H "token:BUVUDcxsaf%^&%4643667" \
--data-raw'{
    "type": "agent_config",
    "version": 0,
    "config": []
}'
```

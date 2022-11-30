# ElkeidUP

English | [简体中文](README-zh_CN.md)

Automated deployment of Elkeid tools



## Component List
* Redis
* Mongodb
* Kafka
* Zookeeper
* Nginx
* Elkeid Agent Center
* Elkeid Manager
* Elkeid Console
* Elkeid Service Discovery
* Elkeid HUB Community Version


| **Name**          | **Minimal deployment in test environment**        | **non-test environment**                          | **Components use ports**           |
| ----------------- | ------------------------------------------------- | ------------------------------------------------- | ---------------------------------- |
| Redis             | Single                                            | Three, Sentinel Mode                              | 6379<br />26379                    |
| Mongodb           | Single                                            | Three, Replicat Mode                              | 27017                              |
| Kafka/ZK          | Single                                            | Calculated by agent amount                        | 2181<br />9092                     |
| Nginx             | Single                                            | Single                                            | 8080<br />8082<br />8089<br />8090 |
| Service Discovery | Single                                            | Two                                               | 8088                               |
| HUB               | Community edition only supports single deployment | Community edition only supports single deployment | 8091<br />8092                     |
| Manager           | Single                                            | Two                                               | 6701                               |
| Agent Center      | Single                                            | Calculated by agent amount                        | 6751<br />6752<br />6753           |



## Instructions
Server Minimum requirements:
* The backend server used for deployment needs to be used by Elkeid only
* The back-end server used for deployment needs to ensure intranet interoperability
* The backend server used for deployment requires root user privileges when deploying
* The backend server used for deployment can only be used: Centos7 and above; Ubuntu16 and above; Debian9 and above
* The server which execute elkeidup could execute ssh root@x.x.x.x without password to any backend server
* Deployment cannot be manually interrupted
* Only cat use LAN IP, do not use 127.0.0.1 or hostname or public IP
* To access Elkeid Console, only the LAN IP filled in the installation configuration can be used, and other such as public network IP cannot be used


```bash
#download and unzip，replace download url when you execute
wget https://github.com/bytedance/Elkeid/releases/download/v1.7/elkeidup
chmod a+x ./elkeidup
wget https://github.com/bytedance/Elkeid/releases/download/v1.7/package_community.tar.gz
tar -zxf package_community.tar.gz

# get elkeidup help
./elkeidup --help
# generate conf template
./elkeidup init
# edit template，the point is all ip address
vim elkeid_server.yaml
# deploy
./elkeidup deploy --package package_community/ --config ./elkeid_server.yaml
# check status
./elkeidup status
# view password and console url
cat ~/.elkeidup/elkeid_passwd
# build agent
./elkeidup agent build --package package_community/ 
```

**Must-read notes**

* **Don't remove `~/.elkeidup` dir**
* **In addition to kafka other components install field must be true**
* **Don't fix any components used user's password, Include the Console(Elkeid Manager)**

### Agent Install Remark
* Driver module depends on pre-compiled ko, specific support list reference: [ko_list](https://github.com/bytedance/Elkeid/blob/main/driver/ko_list.md)
* The way to check if driver exists: `lsmod | grep hids_driver`
* If the kernel version of the test machine is not in the supported list, please compile the ko file and the sign file by yourself and place them in the corresponding server of nginx: `/elkeid/nginx/ElkeidAgent/agent/plugin/driver/ko`, under the ko/sign file The format should follow: `hids_driver_1.7.0.4_{uname -r}_{arch}.ko/sign` After the placement is completed, the Agent will automatically pull the corresponding ko file for installation

### Raw Data Usage Tutorial
[Raw Data Usage Tutorial](raw_data_usage_tutorial/raw_data_usage_tutorial-zh_CN.md)

### Example(1-30 Agents Test)

Minimum 8C16G 200G server

|         | Component                                                    |
| ------- | ------------------------------------------------------------ |
| Server1 | Redis<br />Mongodb<br />Nginx<br />Kafka<br />HUB<br />Service Discovery<br />Manager<br />Agent Center |



### Example(300-500 Agents Test)

Minimum 8C16G 200G server

| Server List | Component                      |
| ----------- | ------------------------------ |
| Server1     | Redis<br />Mongodb<br />Nginx  |
| Server2     | Kafka                          |
| Server3     | HUB                            |
| Server4     | Service Discovery<br />Manager |
| Server5     | Agent Center                   |



### Example(10000 Agents Non-test)

| Server List | Component                  | Recommended Configuration |
|-------------|----------------------------| ------------------------- |
| Server1/2/3 | Redis<br />Mongodb               | 8C16G 500G                |
| Server4/5/6 | Kafka                      | 8C32G 2T 10-Gigabit NIC   |
| Server7/8   | Manager<br />Service Discovery | 8C16G                     |
| Server9/10  | Agent Center               | 16C32G  10-Gigabit NIC    |
| Server13    | Nginx                      | 8C16G                     |

A single HUB does not support 5000 agents.

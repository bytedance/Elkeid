# ElkeidUP

[English](README.md) | 简体中文

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



| **Name**          | 测试环境部署建议      | 生产环境部署建议      | 端口                               |
| ----------------- | --------------------- | --------------------- | ---------------------------------- |
| Redis             | 单台                  | 三台 哨兵模式         | 6379<br />26379                    |
| Mongodb           | 单台                  | 三台 副本模式         | 27017<br />9216                    |
| Kafka/ZK          | 单台                  | 根据Agent数量计算     | 2181<br />9092                     |
| Nginx             | 单台                  | 单台                  | 8080<br />8082<br />8089<br />8090 |
| Service Discovery | 单台                  | 两台                  | 8088                               |
| HUB               | 社区版HUB仅支持单节点 | 社区版HUB仅支持单节点 | 8091<br />8092                     |
| Manager           | 单台                  | 两台                  | 6701                               |
| Agent Center      | 单台                  | 根据Agent数量计算     | 6751<br />6752<br />6753           |



## Instructions

- 部署所用的后端服务器需要仅供Elkeid使用

- 部署所用的后端服务器需要保证内网互通，也仅支持内网部署

- 部署所用的后端服务器部署时需要有 root 用户权限

- 部署所用的后端服务器只能使用：Centos7 及以上；Ubuntu16 及以上；Debian9 及以上



```bash
wget elkeidup
wget package
unzip package
./elkeidup init
vim elkeid_server.yaml
./elkeidup deploy --package package/ --config ./elkeid_server.yaml
./elkeidup status
cat ~/.elkeidup/elkeid_passwd
./elkeidup agent build --package package/ --config ./elkeid_will.yaml 
```



**必读事项**

* **安装后不要删除 `~/.elkeidup` 目录**
* **除了Kafka其他的组件的 install 字段必须为true**

* **不要修改任何组件的密码，包括Elkeid Console(Manager)初始默认用户**

* **Kafka 默认链接配置如下:**

```json
{"sasl.mechanism":"PLAIN","sasl.password":"elkeid","sasl.username":"admin","security.protocol":"SASL_PLAINTEXT"}
```



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

| Server List | Component                      | Recommended Configuration |
| ----------- | ------------------------------ | ------------------------- |
| Server1     | RedisMongodb                   | 8C16G 500G                |
| Server2     | RedisMongodb                   | 8C16G 500G                |
| Server3     | RedisMongodb                   | 8C16G 500G                |
| Server4/5/6 | Kafka                          | 8C32G 2T 10-Gigabit NIC   |
| Server7/8   | Manager<br />Service Discovery | 8C16G                     |
| Server9/10  | Agent Center                   | 16C32G  10-Gigabit NIC    |
| Server13    | Nginx                          | 8C16G                     |

A single HUB does not support 10,000 agents.


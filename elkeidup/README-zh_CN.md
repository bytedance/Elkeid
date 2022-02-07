# ElkeidUP

[English](README.md) | 简体中文

Elkeid 自动化部署工具

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
| Mongodb           | 单台                  | 三台 副本模式         | 27017                              |
| Kafka/ZK          | 单台                  | 根据Agent数量计算     | 2181<br />9092                     |
| Nginx             | 单台                  | 单台                  | 8080<br />8082<br />8089<br />8090 |
| Service Discovery | 单台                  | 两台                  | 8088                               |
| HUB               | 社区版HUB仅支持单节点 | 社区版HUB仅支持单节点 | 8091<br />8092                     |
| Manager           | 单台                  | 两台                  | 6701                               |
| Agent Center      | 单台                  | 根据Agent数量计算     | 6751<br />6752<br />6753           |



## Instructions

* 部署所用的后端服务器需要仅供Elkeid使用
* 部署所用的后端服务器需要保证内网互通，也仅支持内网部署
* 部署所用的后端服务器部署时需要有 root 用户权限
* 部署所用的后端服务器只能使用：Centos7 及以上；Ubuntu16 及以上；Debian9 及以上
* 执行elkeidup的服务器需要能以root用户免密码ssh到所有的后端服务器上
* 部署过程不可以手动打断
* 仅可以使用局域网IP，不要使用 127.0.0.1 或者 hostname 或者公网IP
* 访问 Elkeid Console 只能使用安装配置中填写的局域网IP，不可使用其他如公网IP

```bash
#下载&解压，请根据release替换download url
wget https://github.com/bytedance/Elkeid/releases/download/v1.7/elkeidup
chmod a+x ./elkeidup
wget https://github.com/bytedance/Elkeid/releases/download/v1.7/package_community.tar.gz
tar -zxf package_community.tar.gz

# get elkeidup help
./elkeidup --help
# 生成配置模版
./elkeidup init
#按需填写配置
vim elkeid_server.yaml
#后端组件自动化部署
./elkeidup deploy --package package_community/ --config ./elkeid_server.yaml
#检查状态
./elkeidup status
#查看组件地址与密码
cat ~/.elkeidup/elkeid_passwd
#自动化build agent与部分插件
./elkeidup agent build --package package_community/
#部署结束，根据前端引导进行agent部署
```


**必读事项**

* **安装后不要删除 `~/.elkeidup` 目录**
* **除了Kafka其他的组件的 install 字段必须为true**
* **不要修改任何组件的密码，包括Elkeid Console(Manager)初始默认用户**

### Agent Install Remark
* Driver 模块依赖预编译ko，具体支持列表参考：[ko_list](https://github.com/bytedance/Elkeid/blob/main/driver/ko_list.md)
* 检测 Driver 是否存在的方式：`lsmod | grep hids_driver`


### Raw Data Usage Tutorial
[Raw Data Usage Tutorial](raw_data_usage_tutorial-zh_CN.md)

### 1-30 Agent 测试环境配置参考

Minimum 8C16G 200G server

|         | Component                                                    |
| ------- | ------------------------------------------------------------ |
| Server1 | Redis<br />Mongodb<br />Nginx<br />Kafka<br />HUB<br />Service Discovery<br />Manager<br />Agent Center |



### 300-500 Agent 测试环境配置参考

Minimum 8C16G 200G server

| Server List | Component                      |
| ----------- | ------------------------------ |
| Server1     | Redis<br />Mongodb<br />Nginx  |
| Server2     | Kafka                          |
| Server3     | HUB                            |
| Server4     | Service Discovery<br />Manager |
| Server5     | Agent Center                   |



### 5000 Agent 生产环配置境参考

| Server List | Component                  | Recommended Configuration |
|-------------|----------------------------| ------------------------- |
| Server1/2/3 | Redis<br />Mongodb               | 8C16G 500G                |
| Server4/5/6 | Kafka                      | 8C32G 2T 10-Gigabit NIC   |
| Server7/8   | Manager<br />Service Discovery | 8C16G                     |
| Server9/10  | Agent Center               | 16C32G  10-Gigabit NIC    |
| Server13    | Nginx                      | 8C16G                     |

A single HUB does not support 5000 agents.


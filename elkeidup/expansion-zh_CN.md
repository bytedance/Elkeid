# Elkeid 社区版 扩容指南

## ServiceDiscovery

### 自身扩容(依赖elkeidup)

1.  修改config.yaml 在sd中添加其他的host，登录条件与安装时相同。
2.  执行以下命令 elkeidup reinstall --component ServiceDiscovery --re-init

### 自身扩容(手动操作)

1.  拷贝已安装好SD机器的 /elkeid/service_discovery 到待扩容机器上。
2.  更新全部SD的配置文件 /elkeid/service_discovery/conf/conf.yaml 的 Cluster.Members项，该项为所有sd实例的数组，每台sd都要填写全部实例的地址。
3.  执行新SD实例的 /elkeid/service_discovery/install.sh ，会自动启动sd。
4.  重启所有旧的sd实例 `systemctl restart elkeid_sd` 。

### 同步修改上下游配置

sd目前同时被AgentCenter，Manager和Nginx所依赖，扩容SD后，需要同步重启。

-   AgentCenter: 配置文件位于/elkeid/agent_center/conf/svr.yml 的 sd.addrs，重启命令 `systemctl restart elkeid_ac`。
-   Manager: 配置文件位于/elkeid/manager/conf/svr.yml 的 sd.addrs，重启命令 `systemctl restart elkeid_manager`。
-   Nginx: 配置文件位于/elkeid/nginx/nginx/nginx.conf 的 upstream sd_list，重启命令 `systemctl restart elkeid_nginx`。

## AgentCenter

### 自身扩容(依赖elkeidup)

1.  修改config.yaml 在ac中添加其他的host，登录条件与安装时相同。
2.  执行以下命令 elkeidup reinstall --component AgentCenter --re-init

### 自身扩容(手动操作)

1.  拷贝已安装好AC机器的 /elkeid/agent_center 到待扩容机器上。
2.  执行新AC实例的 /elkeid/agent_center/install.sh ，会自动安装和启动AC。

### 同步修改上下游配置

若agent通过服务发现的方式连接到AC，则不需要手动同步上下游配置。

若agent通过编码的AC地址连接AC，需要重新编译agent，将新的AC地址加入到agent连接配置中。
# Elkeid CWPP v1.9.1 社区版 资源配置手册
## 版本

社区版v1.9.1

## 架构介绍
注：目前受社区版限制，Hub部分仅支持单机部署

![arch](../server/docs/server_new.png)

## 组件详情

| **组件名称**                   | **测试环境下最小部署方式**           | **生产环境建议部署方式**                         | **组件使用端口**                         | **说明**     |
|----------------------------|---------------------------|----------------------------------------|------------------------------------|------------|
| **Redis**                  | 单台                        | 三台，哨兵模式（仅支持3台，更大规模集群需要自行部署后替换）         | 6379 26379                         | 缓存数据库      |
| **Mongodb**                | 单台                        | 三台，副本集模式（仅支持3台，更大规模集群需要自行部署后替换）        | 27017 9982                         | 数据库        |
| **Kafka**                  | 单台                        | 按Agent量进行计算（自动化部署情况下仅支持3台，多台需要自行部署后替换） | 2181 9092 12888 13888              | 消息通道       |
| **Nginx**                  | 单台                        | 单台或多台均可，下载功能建议使用内部CDN，若需要外部接入，建议使用自建LB | 8080 8081 8082 8071 8072 8089 8090 | 文件服务器及反向代理 |
| **Service Discovery**      | 单台                        | 两至三台                                   | 8088                               | 服务发现       |
| **HUB**                    | 单台                        | 社区版仅支持单台（生产环境是否使用社区版，请进行额外评估）          | 8091 8092                          | 规则引擎       |
| **HUB Leader**             | 单台                        | 社区版仅支持单台（生产环境是否使用社区版，请进行额外评估）          | 12310 12311                        | 规则引擎集群控制层  |
| **HIDS Manager**           | 单台                        | 两至三台                                   | 6701                               | HIDS控制层    |
| **Agent Center**           | 单台                        | 按Agent量进行计算                            | 6751 6752 6753                     | HIDS接入层    |
| **Prometheus**             | 单台                        | 单台或两台均可                                | 9090 9993 9994 9981 9983 9984      | 监控用数据库     |
| **Prometheus Alermanager** | 与Prometheus共用服务器          | -                                      |                                    |            |
| **Grafana**                | 单台                        | 单台                                     | 8083                               | 监控面板       |
| **Kinaba**                 | 单台                        | 单台                                     | 5601                               | ES面板       |
| **NodeExporter**           | 不需指定单独的服务器，所有机器都需要部署该监控服务 | -                                      | 9990                               | 监控探针       |
| **ProcessExporter**        | 不需指定单独的服务器，所有机器都需要部署该监控服务 | -                                      | 9991                               | 监控探针       |

## 配置文件说明

1.  ssh\_host 为通用配置，表示该组件在哪些机器上进行部署，若为数组类型，说明该组件支持集群部署，否则只支持单机部署，具体限制见配置文件注释。
2. quota为通用配置，最终会转变为cgroup限制。
3. 单机测试环境下，所有机器都填同一地址即可。

```
# redis 单台或3台，3台时为哨兵模式
redis:
  install: true
  quota: 1C2G
  ssh_host:
    - redis-1
    - redis-2
    - redis-3

# MongoDB 单台或3台，3台时为副本集模式
mongodb:
  install: true
  quota: 2C4G
  ssh_host:
    - monogo-1
    - monogo-2
    - monogo-3

# MongoDB 单台或3台，3台时为进群模式
kafka:
  install: true
  topic: hids_svr
  partition_num: 12 # 默认单topic分区数
  quota: 2C4G
  ssh_host:
    - kafka-1
    - kafka-2
    - kafka-3

# leader 社区版目前仅支持单机模式
leader:
  install: true
  quota: 1C2G
  ssh_host: leader-1

# nginx 单台多台即可，但其他组件默认只会使用第一台
nginx:
  install: true
  quota: 1C2G
  ssh_host:
    - nginx-1
    - nginx-2
  domain: # 指向nginx机器的域名，仅支持单个
  public_addr: # nginx机器的公网IP，仅支持单个

# sd 单台多台即可
service_discovery:
  install: true
  quota: 1C2G
  ssh_host:
    - sd-1
    - sd-2

# hub 社区版目前仅支持单机模式
hub:
  install: true
  quota: 2C4G
  ssh_host: hub-1

# manager 单台多台即可
manager:
  install: true
  quota: 2C4G
  ssh_host:
    - manager-1

# ac 单台多台即可
agent_center:
  install: true
  grpc_conn_limit: 1500 # 单个AC的最大连接数限制
  quota: 1C2G
  ssh_host:
    - ac-1

# prometheus 单台多台即可，默认只会请求第一台，第二台处于双写状态，不会被查询
prometheus:
  quota: 1C2G
  ssh_host:
    - prometheus-1

# grafana 仅支持一台
grafana:
  quota: 1C2G
  ssh_host: grafana-1
```
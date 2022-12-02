# Resource Configuration of Elkeid Community Edition

## Elkeid Architecture diagram
> Note: Currently, Elkeid HUB's community version only supports stand-alone deployment


![arch](../server/docs/server_new.png)

# **Components in detail**

<table>
  <tr>
   <td><strong>Component name</strong>
   </td>
   <td><strong>Minimum deployment in the testing environment</strong>
   </td>
   <td><strong>Production environment</strong>
   </td>
   <td><strong>Listen ports</strong>
   </td>
   <td><strong>Description</strong>
   </td>
  </tr>
  <tr>
   <td>Redis
   </td>
   <td>single
   </td>
   <td>Three, Sentry mode (only supports 3, larger clusters need to be replaced after deployment)
   </td>
   <td>
<ul>

<li>6379

<li>26379
</li>
</ul>
   </td>
   <td>cache database
   </td>
  </tr>
  <tr>
   <td>MongoDB
   </td>
   <td>single
   </td>
   <td>Three replicas mode (only 3 are supported, larger clusters need to be replaced after deployment)
   </td>
   <td>
<ul>

<li>27017

<li>9982
</li>
</ul>
   </td>
   <td>db.table
   </td>
  </tr>
  <tr>
   <td>Kafka
   </td>
   <td>single
   </td>
   <td>Calculated by the number of agents (only 3 units are supported in the case of automatic deployment, and multiple units need to be replaced after deployment)
   </td>
   <td>
<ul>

<li>2181

<li>9092

<li>12888

<li>13888
</li>
</ul>
   </td>
   <td>message channel
   </td>
  </tr>
  <tr>
   <td>Nginx
   </td>
   <td>single
   </td>
   <td>Single or multiple units can be used. The download function is recommended to use internal CDN , if you need external access, it is recommended to use self-built LB
   </td>
   <td>
<ul>

<li>8080

<li>8081

<li>8082

<li>8071

<li>8072

<li>8089

<li>8090
</li>
</ul>
   </td>
   <td>File server and reverse proxy
   </td>
  </tr>
  <tr>
   <td>Service Discovery
   </td>
   <td>single
   </td>
   <td>two to three
   </td>
   <td>
<ul>

<li>8088
</li>
</ul>
   </td>
   <td>Service Discovery
   </td>
  </tr>
  <tr>
   <td>HUB
   </td>
   <td>single
   </td>
   <td>The community version only supports a single station (whether the production environment uses the community version, please conduct additional evaluation)
   </td>
   <td>
<ul>

<li>8091

<li>8092
</li>
</ul>
   </td>
   <td>rules engine
   </td>
  </tr>
  <tr>
   <td>HUB Leader
   </td>
   <td>single
   </td>
   <td>The community version only supports a single station (whether the production environment uses the community version, please conduct additional evaluation)
   </td>
   <td>
<ul>

<li>12310

<li>12311
</li>
</ul>
   </td>
   <td>Rules engine Cluster control layer
   </td>
  </tr>
  <tr>
   <td>HIDS Manager
   </td>
   <td>single
   </td>
   <td>two to three
   </td>
   <td>
<ul>

<li>6701
</li>
</ul>
   </td>
   <td>HIDS Control layer
   </td>
  </tr>
  <tr>
   <td>Agent Center
   </td>
   <td>single
   </td>
   <td>Calculate by Agent quantity
   </td>
   <td>
<ul>

<li>6751

<li>6752

<li>6753
</li>
</ul>
   </td>
   <td>HIDS Access layer
   </td>
  </tr>
  <tr>
   <td>Prometheus
   </td>
   <td>single
   </td>
   <td>Single or both
   </td>
   <td>
<ul>

<li>9090

<li>9993

<li>9994

<li>9981

<li>9983

<li>9984
</li>
</ul>
   </td>
   <td>Database for monitoring
   </td>
  </tr>
  <tr>
   <td>Prometheus Alermanager
   </td>
   <td>with Prometheus Shared server
   </td>
   <td>-
   </td>
   <td>
   </td>
   <td>
   </td>
  </tr>
  <tr>
   <td>Grafana
   </td>
   <td>single
   </td>
   <td>single
   </td>
   <td>
<ul>

<li>8083
</li>
</ul>
   </td>
   <td>monitoring panel
   </td>
  </tr>
  <tr>
   <td>NodeExporter
   </td>
   <td>No need to specify a separate server; all machines need to deploy the monitoring service
   </td>
   <td>-
   </td>
   <td>
<ul>

<li>9990
</li>
</ul>
   </td>
   <td>monitoring probe
   </td>
  </tr>
  <tr>
   <td>ProcessExporter
   </td>
   <td>No need to specify separate a separate server, all machines need to deploy the monitoring service
   </td>
   <td>-
   </td>
   <td>
<ul>

<li>9991
</li>
</ul>
   </td>
   <td>monitoring probe
   </td>
  </tr>
</table>



# **Configure Elkeidup**

Notes for keywords:



1. **_ssh_host_** is a generic configuration, indicating which machines the component is deployed on. If it is an array type, it means that the component supports Clustered Deployment. Otherwise, it only supports stand-alone deployment. See the configuration file notes for specific restrictions.
1. **Quotas** are generic configurations that will eventually turn into cgroup limits.
1. In a stand-alone testing environment, all machines can fill-in with the same address.

```
# Redis: Single or 3 hosts, 3 hosts infers it will be in Sentinel mode
redis:
  install: true
  quota: 1C2G
  ssh_host:
    - redis-1
    - redis-2
    - redis-3

# MongoDB: Single or 3 hosts, 3 hosts infers it will be in Replica-Set mode
mongodb:
  install: true
  quota: 2C4G
  ssh_host:
    - monogo-1
    - monogo-2
    - monogo-3

# Kafka: Single or 3 hosts, 3 hosts infers it will be in Cluster mode
kafka:
  install: true
  topic: hids_svr
  partition_num: 12 # Default partition number for one topic
  quota: 2C4G
  ssh_host:
    - kafka-1
    - kafka-2
    - kafka-3

# leader: The community edition currently only supports stand-alone mode
leader:
  install: true
  quota: 1C2G
  ssh_host: leader-1

# nginx: one or more hosts, but other components will only use the first one by default
nginx:
  install: true
  quota: 1C2G
  ssh_host:
    - nginx-1
    - nginx-2
  domain: # 指向nginx机器的域名，仅支持单个
  public_addr: # nginx机器的公网IP，仅支持单个

# sd: one or more hosts
service_discovery:
  install: true
  quota: 1C2G
  ssh_host:
    - sd-1
    - sd-2

# hub: The community edition currently only supports stand-alone mode
hub:
  install: true
  quota: 2C4G
  ssh_host: hub-1

# manager: one or more hosts
manager:
  install: true
  quota: 2C4G
  ssh_host:
    - manager-1

# ac: one or more hosts
agent_center:
  install: true
  grpc_conn_limit: 1500 # 单个AC的最大连接数限制
  quota: 1C2G
  ssh_host:
    - ac-1

# prometheus: one or two host, The second one will be used for double-write only.
prometheus:
  quota: 1C2G
  ssh_host:
    - prometheus-1

# grafana: one host only
grafana:
  quota: 1C2G
  ssh_host: grafana-1
```
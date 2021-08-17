[English](qa.md) | 简体中文

Q&A
一些常见的问题和解决方法，遇到异常之前，请先查看下本篇里面的内容，或许可以找到满意的答案。

### 1. Mangager API 使用过程中遇到报错 CLUSTERDOWN Hash slot not served
如果是单节点的redis集群，运行可能会遇到报错 CLUSTERDOWN Hash slot not served，需要执行如下命令修复： redis-cli --cluster fix 127.0.0.1:6379
### 2. 服务发现异常排查 
1. 首先请确认manager/agentcenter配置文件中服务发现的地址写的是正确的地址。
2. 如果地址配置没错，则是aksk配置的问题：
类似返回 `{"code":-1,"data":"User not exist","msg":"auth failed"}` 类似的错误，一般情况下是因为没将manager/agentcenter的aksk写到服务发现配置文件中导致的。  
请按照如下方法排查：
    - 查看manager/conf/svr.yml的配置文件:  
确保`manager/conf/svr.yml`文件里面的sd.credentials.ak和sd.credentials.sk已经配置到service_discovery的配置文件Auth.Keys里面。  
    - 查看agent_center/conf/svr.yml的配置文件  
确保上面`agent_center/conf/svr.yml`文件里面的sd.auth.ak和sd.auth.sk已经配置到service_discovery的配置文件Auth.Keys里面。

### 3. 首次使用manager接口时，发现有异常
首次使用manager api时，如果发现有controlTask接口下发任务失败、无响应；getStatus接口查询不到agent数据等情况。请按照如下步骤排查：
1. 如果是单节点的redis集群，请先执行如下命令修复集群状态：redis-cli --cluster fix 127.0.0.1:6379
2. manager接口的数据是定时采集，所以接口数据会有30秒-90秒的时间延迟，如果上述操作都执行完成后，manager接口仍然有异常，可稍稍2分钟再尝试。
### 4. Manager API接口响应慢，db耗性能等
请参照 上面 Server编译和部署-->部署Manager -->3 服务初始化--> 新增索引 步骤来给mongodb增加必要的索引。

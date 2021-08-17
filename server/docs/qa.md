English | [简体中文](qa-zh_CN.md)

Q&A  
For some common problems and solutions, please check the contents of this article first before encountering exceptions, and you may find satisfactory answers.

### 1. An error was reported during the use of Mangager API: `CLUSTERDOWN Hash slot not served`.
If it is a single-node redis cluster, you may encounter an error `CLUSTERDOWN Hash slot not served` during operation, and you need to execute the following command to fix it: `redis-cli --cluster fix 127.0.0.1:6379`

### 2. Service discovery exception troubleshooting.
1. First, please make sure that the address found by the service in the manager/agentcenter configuration file is the correct address.
2. If the address configuration is correct, it is a problem with the aksk configuration:
If it returns `{"code":-1,"data":"User not exist","msg":"auth failed"}` similar errors, in general, it is because the aksk of manager/agentcenter is not written to the service Found the cause in the configuration file.  
Please confirm as follows:
    -View the configuration file of manager/conf/svr.yml:
Make sure that the sd.credentials.ak and sd.credentials.sk in the `manager/conf/svr.yml` file have been configured into the service_discovery configuration file Auth.Keys.
    -View the configuration file of agent_center/conf/svr.yml
Make sure that the sd.auth.ak and sd.auth.sk in the above `agent_center/conf/svr.yml` file have been configured in the service_discovery configuration file Auth.Keys.

### 3. When using the manager api for the first time, an exception was found.
When the manager api is used for the first time, if it is found that the controlTask ​​interface fails to deliver a task and does not respond; the getStatus interface cannot query the agent data, etc. 
Please follow the steps below to troubleshoot:
1. If it is a single-node redis cluster, please execute the following command to fix the cluster status first: `redis-cli --cluster fix 127.0.0.1:6379`
2. The data of the manager interface is collected regularly, so the interface data will have a time delay of 30-90 seconds. If the manager interface is still abnormal after the above operations are performed, you can try again for a while.

### 4. Manager API interface response is slow, db consumes performance, etc.
Please refer to the above Server Compilation and Deployment --> Deployment Manager -->3 Service Initialization --> Add Index Steps to add necessary indexes to mongodb.

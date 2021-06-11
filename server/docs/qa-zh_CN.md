Q&A
一些常见的问题和解决方法，遇到异常之前，请先查看下本篇里面的内容，或许可以找到满意的答案。

#### Q1
**Question**: 首次使用manager接口时，发现有异常：controlTask接口下发任务失败、无响应；getStatus接口查询不到agent数据等。
****
**Answer**: 如果manager接口如果有异常，先确认：  
1、如果是单节点的redis集群，请先执行如下命令修复集群状态：`redis-cli --cluster fix 127.0.0.1:6379`  
2、注意首次使用时，需要设置agent默认配置，可以设置为空(为空意味着新接入的agent不会自动开启任何插件):
```
curl --location --request POST 'http://127.0.0.1:6701/api/v1/agent/updateDefaultConfig' -H "token:BUVUDcxsaf%^&%4643667" \
--data-raw '{
    "type": "agent_config",
    "version": 0,
    "config": []
}'
```
3、manager接口的数据是定时采集，所以接口数据会有30秒-90秒的时间延迟，如果上述操作都执行完成后，manager接口仍然有异常，可稍稍2分钟再尝试。

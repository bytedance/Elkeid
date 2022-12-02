# Elkeid HUB 单独部署
如果需要单独部署HUB，可以使用elkeidup中的`--hub_only`参数，具体步骤如下：
### 1、配置目标机器root用户ssh免密登录
如果部署机器为本机，依旧需要配置本机免密登录，登录耗时需要小于1s。
可用以下命令进行验证，两次date命令的输出结果需要相同。
```
date && ssh root@{ip} date
# 输出时间差小于1s
```

### 2、下载release产物并配置目录
```
mkdir -p /root/.elkeidup && cd /root/.elkeidup
wget https://github.com/bytedance/Elkeid/releases/download/v1.9.1/elkeidup_hub_v1.9.1.tar.gz -O elkeidup.tar.gz && tar -xf elkeidup.tar.gz
chmod a+x /root/.elkeidup/elkeidup
```
### 3、生成并修改config.yaml
ip为本机非 `127.0.0.1` ip，若不为单机部署，请参考[部署资源手册](./configuration-zh_CN.md)修改config.yaml
```
cd /root/.elkeidup
## 生成hub only 配置
./elkeidup init --host {ip} --hub_only
mv config_example.yaml config.yaml
```
### 4、部署
```
cd /root/.elkeidup

# 命令为交互式
./elkeidup deploy --hub_only

## status
./elkeidup status --hub_only

## undeploy
./elkeidup undeploy --hub_only
```

### 5、访问HUB前端
顺利安装完成后，执行`cat /root/.elkeidup/elkeid_passwd`将看到各组件的随机生成的密码和相关的url。

| 字段                         | 说明               |
| -------------------------- |------------------|
| elkeid_hub_frontend        | hub前端账号密码        |
| grafana        | grafana账号密码      |
| grafana      | grafana 地址       |
| elkeid_hub_frontend      | elkeid hub前端地址   |
| elkeid_service_discovery | 服务发现地址           |

访问 elkeid_hub_frontend，参照 [Elkeid HUB 社区版快速上手教程](https://github.com/bytedance/Elkeid-HUB/blob/main/docs/quick_start/quick_start.md) 使用。

## 6、HTTPS配置
请参考[Elkeid https配置文档](./https_config/https.md)
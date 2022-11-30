# Elkeid 完整部署

## 单机docker快速部署 (单机测试环境推荐)

### 1、导入镜像
```bash
# 从release下载的是分卷的镜像，需要先合并镜像
wget https://github.com/bytedance/Elkeid/releases/download/v1.9.1/elkeidup_image_v1.9.1.tar.gz.00
wget https://github.com/bytedance/Elkeid/releases/download/v1.9.1/elkeidup_image_v1.9.1.tar.gz.01
wget https://github.com/bytedance/Elkeid/releases/download/v1.9.1/elkeidup_image_v1.9.1.tar.gz.02
wget https://github.com/bytedance/Elkeid/releases/download/v1.9.1/elkeidup_image_v1.9.1.tar.gz.03
cat elkeidup_image_v1.9.1.tar.gz.* > elkeidup_image_v1.9.1.tar.gz

#导入镜像
docker load -i elkeidup_image_v1.9.1.tar.gz
```

### 2、运行容器

```
docker run -d --name elkeid_community \
--restart=unless-stopped \
-v /sys/fs/cgroup:/sys/fs/cgroup:ro \
-p 8071:8071 -p 8072:8072 -p 8080:8080 \
-p 8081:8081 -p 8082:8082 -p 8089:8080  -p 8090:8090\
--privileged \
elkeid/all-in-one:v1.9.1
```

### 3、设置对外IP

使用本机IP，不能使用127.0.0.1。

```bash
docker exec -it elkeid_community bash

cd /root/.elkeidup/

# 命令为交互式
./elkeidup public {ip}


./elkeidup agent init
./elkeidup agent build
./elkeidup agent policy create

cat elkeid_password
```

### 4、拷贝预编译ko(若需要)

如果在执行elkeidup deploy中未同意声明，需要自行编译ko或下载[release](../driver/README-zh_CN.md#我们提供部分预编译好的-ko-文件)中的ko_{version}.tar.xz并解压获取其中的ko，然后将需要的ko和对应的sign文件拷贝到以下目录并修改文件权限，确保新安装agent有ko可以加载。

```bash
# ko 目录
/elkeid/nginx/ElkeidAgent/agent/component/driver/ko

# 修改权限
chown -R nginx:nginx /elkeid/nginx
```


### 5、访问前端console并安装Agent
顺利安装完成后，`/root/.elkeidup/elkeid_passwd`文件记录了各组件的密码和相关的url。
> 初始密码在构建镜像的时候已经固定了的，为了安全性请不要用于生产环境

| 字段                         | 说明               |
| -------------------------- |------------------|
| elkeid_console            | console账号密码      |
| elkeid_hub_frontend        | hub前端账号密码        |
| grafana        | grafana账号密码      |
| grafana      | grafana 地址       |
| elkeid_hub_frontend      | elkeid hub前端地址   |
| elkeid_console      | elkeid console地址 |
| elkeid_service_discovery | 服务发现地址           |

访问elkeid_console，按照[Console使用手册-安装配置](../server/docs/console_tutorial/Elkeid_Console_manual.md#安装配置) 界面的命令进行Agent安装部署。

## 使用elkeidup进行完整部署

### 1、配置目标机器root用户ssh免密登录

如果部署机器为本机，依旧需要配置本机免密登录，登录耗时需要小于1s。
可用以下命令进行验证，两次date命令的输出结果需要相同。

```bash
date && ssh root@{ip} date
# 输出时间差小于1s
```

### 2、解压release产物并配置目录
- 下载release产物（分卷压缩包），并合并压缩包
```
wget https://github.com/bytedance/Elkeid/releases/download/v1.9.1/elkeidup_package_v1.9.1.tar.gz.00
wget https://github.com/bytedance/Elkeid/releases/download/v1.9.1/elkeidup_package_v1.9.1.tar.gz.01
wget https://github.com/bytedance/Elkeid/releases/download/v1.9.1/elkeidup_package_v1.9.1.tar.gz.02
cat elkeidup_package_v1.9.1.tar.gz.* > elkeidup_package_v1.9.1.tar.gz
```
也可以参考[从源码构建 Elkeid](./build_package.md)，自行编译和构建package包。

- 解压release产物并配置目录
```
mkdir -p /root/.elkeidup && cd /root/.elkeidup
mv {DownloadDir}/elkeidup_package_v1.9.1.tar.gz elkeidup_package_v1.9.1.tar.gz
tar -xf elkeidup_package_v1.9.1.tar.gz
chmod a+x /root/.elkeidup/elkeidup
```

### 3、生成并修改config.yaml

ip为本机非127.0.0.1 ip，若不为单机部署，请参考[资源手册](./configuration.md#配置文件说明)修改config.yaml

```bash
cd /root/.elkeidup
./elkeidup init --host {ip}
mv config_example.yaml config.yaml
```

### 4、部署

```bash
cd /root/.elkeidup

# 命令为交互式
./elkeidup deploy
```

### 5、构建Agent

```bash
cd /root/.elkeidup

./elkeidup agent init
./elkeidup agent build
./elkeidup agent policy create
```

### 6、拷贝预编译ko(若需要)

如果在执行elkeidup deploy中未同意声明，需要自行编译ko或下载[release](../driver/README-zh_CN.md#我们提供部分预编译好的-ko-文件)中的ko_{version}.tar.xz并解压获取其中的ko，然后将需要的ko和对应的sign文件拷贝到以下目录并修改文件权限，确保新安装agent有ko可以加载。

```bash
# ko 目录
/elkeid/nginx/ElkeidAgent/agent/component/driver/ko

# 修改权限
chown -R nginx:nginx /elkeid/nginx
```

### 7、访问前端console并安装Agent
顺利安装完成后，执行`cat /root/.elkeidup/elkeid_passwd`将看到各组件的随机生成的密码和相关的url。

| 字段                         | 说明               |
| -------------------------- |------------------|
| elkeid_console            | console账号密码      |
| elkeid_hub_frontend        | hub前端账号密码        |
| grafana        | grafana账号密码      |
| grafana      | grafana 地址       |
| elkeid_hub_frontend      | elkeid hub前端地址   |
| elkeid_console      | elkeid console地址 |
| elkeid_service_discovery | 服务发现地址           |

访问elkeid_console，按照[Console使用手册-安装配置](../server/docs/console_tutorial/Elkeid_Console_manual.md#安装配置) 界面的命令进行Agent安装部署。
# Elkeid 完整部署

## 单机docker快速部署 (单机测试环境推荐)

### 1、导入镜像

```bash
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

如果在执行elkeidup public中未同意声明，需要自行编译ko或下载release中的ko_{version}.tar.xz并解压获取其中的ko，然后将需要的ko和对应的sign文件拷贝到以下目录并修改文件权限，确保新安装agent有ko可以加载。

```bash
# ko 目录
/elkeid/nginx/ElkeidAgent/agent/component/driver/ko

# 修改权限
chown -R nginx:nginx /elkeid/nginx
```

## 使用elkeidup进行完整部署

### 1、配置目标机器root用户ssh免密登录

如果部署机器为本机，依旧需要配置本机免密登录，登录耗时需要小于1s。
可用以下命令进行验证，两次date命令的输出结果需要相同。

```bash
date && ssh root@{ip} date
# 输出时间差小于1s
```

### 2、下载release产物并配置目录

```bash
mkdir -p /root/.elkeidup && cd /root/.elkeidup
wget https://*.*.*/elkeidup_package_v1.9.1.tar.gz -O elkeidup_package_v1.9.1.tar.gz
tar -xf elkeidup_package_v1.9.1.tar.gz
chmod a+x /root/.elkeidup/elkeidup
```

### 3、生成并修改config.yaml

ip为本机非127.0.0.1 ip，若不为单机部署，请参考部署资源手册修改config.yaml

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

如果在执行elkeidup deploy中未同意声明，需要自行编译ko或下载release中的ko_{version}.tar.xz并解压获取其中的ko，然后将需要的ko和对应的sign文件拷贝到以下目录并修改文件权限，确保新安装agent有ko可以加载。

```bash
# ko 目录
/elkeid/nginx/ElkeidAgent/agent/component/driver/ko

# 修改权限
chown -R nginx:nginx /elkeid/nginx
```
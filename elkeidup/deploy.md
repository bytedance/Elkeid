# Elkeid Full Deployment

## 1、Stand-alone docker rapid deployment (stand-alone testing environment recommended)

### 1.1、Import Mirroring
```bash
wget https://github.com/bytedance/Elkeid/releases/download/v1.9.1.4/elkeidup_image_v1.9.1.tar.gz.00
wget https://github.com/bytedance/Elkeid/releases/download/v1.9.1.4/elkeidup_image_v1.9.1.tar.gz.01
wget https://github.com/bytedance/Elkeid/releases/download/v1.9.1.4/elkeidup_image_v1.9.1.tar.gz.02
wget https://github.com/bytedance/Elkeid/releases/download/v1.9.1.4/elkeidup_image_v1.9.1.tar.gz.03
cat elkeidup_image_v1.9.1.tar.gz.* > elkeidup_image_v1.9.1.tar.gz

docker load -i elkeidup_image_v1.9.1.tar.gz
```

### 1.2、Run the container

```
docker run -d --name elkeid_community \
  --restart=unless-stopped \
  -v /sys/fs/cgroup:/sys/fs/cgroup:ro \
  -p 8071:8071 -p 8072:8072 -p 8080:8080 \
  -p 8081:8081 -p 8082:8082 -p 8089:8080  -p 8090:8090\
  --privileged \
  elkeid/all-in-one:v1.9.1
```

### 1.3、Set external IP

Using this machine IP cannot use 127.0.0.1.

```bash
docker exec -it elkeid_community bash

cd /root/.elkeidup/

# This command will start interactive input
./elkeidup public {ip}


./elkeidup agent init
./elkeidup agent build
./elkeidup agent policy create

cat ~/.elkeidup/elkeid_passwd
```

### 1.4、Access the front console and install Agent
After a successful installation, the `/root/.elkeidup/elkeid_passwd` file records the passwords and associated URLs of each component.

> The initial password is fixed when mirroring is built, please do not use it in the production environment for security

| Field                    | Description                    |
|--------------------------|--------------------------------|
| elkeid_console           | Console account password       |
| elkeid_hub_frontend      | hub front-end account password |
| grafana                  | grafana account password       |
| grafana                  | grafana address                |
| elkeid_hub_frontend      | elkeid hub front-end address   |
| elkeid_console           | elkeid console address         |
| elkeid_service_discovery | Service Discovery Address      |

To access elkeid_console, follow the [Console instruction manual - Install configuration](../server/docs/console_tutorial/Elkeid_Console_manual.md#安装配置) to install and deploy the Agent.

## 2、Full deployment with elkeidup

### 2.1、Configure the target machine root user ssh ssh password-free login

If the deployment machine is local, you still need to configure the local password-free login, and the login time needs to be less than 1s.
The following command can be used to verify that the output of the two date commands needs to be the same.

```bash
date && ssh root@{ip} date
# The output time difference should be less than 1s
```

### 2.2、Download the release product and configure the catalog
- Download the release product (rolled compressed packet) and merge compressed packets
```
wget https://github.com/bytedance/Elkeid/releases/download/v1.9.1.4/elkeidup_package_v1.9.1.tar.gz.00
wget https://github.com/bytedance/Elkeid/releases/download/v1.9.1.4/elkeidup_package_v1.9.1.tar.gz.01
wget https://github.com/bytedance/Elkeid/releases/download/v1.9.1.4/elkeidup_package_v1.9.1.tar.gz.02
cat elkeidup_package_v1.9.1.tar.gz.* > elkeidup_package_v1.9.1.tar.gz
```
You can also refer to [Build Elkeid from Source](./build_package.md) to compile and build packages yourself.

> If installed before, delete the `/root/.elkeidup` and `/elkeid` folders to avoid interference

- Unzip and release products and configuration catalog
```
mkdir -p /root/.elkeidup && cd /root/.elkeidup
mv {DownloadDir}/elkeidup_package_v1.9.1.tar.gz elkeidup_package_v1.9.1.tar.gz
tar -xf elkeidup_package_v1.9.1.tar.gz
chmod a+x /root/.elkeidup/elkeidup
```

### 2.3、Generate and modify config.yaml

If it is not a standalone deployment, please refer to the [deployment resource manual](./configuration.md) to modify config.yaml

```bash
cd /root/.elkeidup
./elkeidup init --host {ip}
mv config_example.yaml config.yaml
```

### 2.4、Deployment

```bash
cd /root/.elkeidup

# This command will start interactive input
./elkeidup deploy
```

### 2.5、Build Agent

```bash
cd /root/.elkeidup

./elkeidup agent init
./elkeidup agent build
./elkeidup agent policy create
```

### 2.6、Access the front console and install Agent
After a successful installation, the `/root/.elkeidup/elkeid_passwd` file records the passwords and associated URLs of each component.

| Field                    | Description                    |
|--------------------------|--------------------------------|
| elkeid_console           | Console account password       |
| elkeid_hub_frontend      | hub front-end account password |
| grafana                  | grafana account password       |
| grafana                  | grafana address                |
| elkeid_hub_frontend      | elkeid hub front-end address   |
| elkeid_console           | elkeid console address         |
| elkeid_service_discovery | Service Discovery Address      |

To access elkeid_console, follow the [Console instruction manual - Install configuration](../server/docs/console_tutorial/Elkeid_Console_manual.md#安装配置) to install and deploy the Agent.

## 3、Agent Install Remark
- Driver module dependency pre-compile ko, specific support list reference: [ko_list](https://github.com/bytedance/Elkeid/blob/main/driver/ko_list.md)
- Under normal circumstances, after the installation of the Agent is completed, it takes about 10 minutes for the Driver module to work normally (involving the automatic download and installation of KO).
- The way the Driver exists: `lsmod | grep hids_driver`
    - If the test machine kernel version is not in the supported list, [compile ko](https://github.com/bytedance/Elkeid/blob/main/driver/README-zh_CN.md) file and generate sign file (sha256) and import it into Nginx.
    - **If you do not agree to the declaration** in the execution of elkeidup deploy, you also need to [compile ko yourself](https://github.com/bytedance/Elkeid/blob/main/driver/README-zh_CN.md) or download the corresponding [pre-compile ko](https://github.com/bytedance/Elkeid/releases/download/v1.9.1/ko_1.7.0.9.tar.xz) ([support list](https://github.com/bytedance/Elkeid/blob/main/driver/ko_list.md)) and sign files in the Release, and import it into Nginx.

### 3.1, ko import Nginx method
The format of the ko/sign file should follow: `hids_driver_1.7.0.4_{uname -r}_{arch}.ko/sign` format, the file needs to be placed on the corresponding nginx server: `/elkeid/nginx/ElkeidAgent/agent/component/driver/ko`, and modify the permissions `chown -R nginx: nginx /elkeid/nginx`. After the placement is completed, the Agent can be restarted.

## 4、HTTPS配置
[Elkeid https Configuration documentation](./https_config/https.md)


## 5、Upgrade specified components
If a component has been updated, or if a component has been recompiled, you can reinstall the specified component using the elkeidup reinstall command.
For example, the Hub Community Edition has been updated in release: v 1.9.1.1, and you can reinstall it with the following command.

```bash
# {v1.9.1.1} is the unzipped package directory for v1.9.1.1
# reinstall hub
cp {v1.9.1.1}/package/hub/hub.tar.gz /root/.elkeidup/package/hub/hub.tar.gz
cp {v1.9.1.1}/package/hub_leader/hub_leader.tar.gz /root/.elkeidup/package/hub_leader/hub_leader.tar.gz

/root/.elkeidup/elkeidup reinstall --component Hub
/root/.elkeidup/elkeidup reinstall --component HubLeader

```

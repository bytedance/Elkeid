# HUB deployed separately
If you need to deploy the HUB separately, you can use the -- hub_only parameter in elkeidup. The specific steps are as follows:
### 1、Configure the target machine root user ssh ssh password-free login
If the deployment machine is local, you still need to configure the local password-free login, and the login time needs to be less than 1s.
The following command can be used to verify that the output of the two date commands needs to be the same.
```
date && ssh root@{ip} date
# The output time difference should be less than 1s
```

### 2、Download the release product and configure the catalog
```
mkdir -p /root/.elkeidup && cd /root/.elkeidup
wget https://github.com/bytedance/Elkeid/releases/download/v1.9.4/elkeidup_hub_v1.9.1.tar.gz -O elkeidup.tar.gz && tar -xf elkeidup.tar.gz
chmod a+x /root/.elkeidup/elkeidup
```
### 3、Generate and modify config.yaml
If it is not a standalone deployment, please refer to the [deployment resource manual](./configuration.md) to modify config.yaml

```
cd /root/.elkeidup
## Generate hub only configurations
./elkeidup init --host {ip} --hub_only
mv config_example.yaml config.yaml
```

### 4、Deployment
```
cd /root/.elkeidup

# Command is interactive
./elkeidup deploy --hub_only

## status
./elkeidup status --hub_only

## undeploy
./elkeidup undeploy --hub_only
```

### 5、Visit the HUB front end
After a successful installation, executing `cat /root/.elkeidup/elkeid_passwd` will see the randomly generated passwords and associated URLs for each component.

| Field                    | Description                    |
|--------------------------|--------------------------------|
| elkeid_hub_frontend      | hub front-end account password |
| grafana                  | grafana account password       |
| grafana                  | grafana address                |
| elkeid_hub_frontend      | elkeid hub front-end address   |
| elkeid_service_discovery | Service Discovery Address      |

To access elkeid_hub_frontend, refer to the [Elkeid HUB Quick Start Tutorial](https://github.com/bytedance/Elkeid-HUB/blob/main/docs/quick_start/quick_start.md).

## 6、HTTPS configuration
Please refer to [Elkeid https configuration documentation](./https_config/https.md)

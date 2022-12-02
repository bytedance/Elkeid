# 从源码构建 Elkeid CWPP

当前社区版本中，部分组件尚未开源，主要是Elkeidup和Hub的相关组件目前仅能提供社区版二进制，所以无法提供从零到一提供完全从源码构建的构建手册。您可以通过在安装前替换package中的指定文件，或安装后替换可执行程序的方式，达到运行从源码构建的可执行程序的效果。具体文件位置和对应关系说明如下。

## 安装前替换

### Agent

Agent部分在elkeidup deploy过程中会从源码build，所以替换package中的以下文件即可，建议解压该文件，确认该文件与目录结构与替换前的文件相同。

```bash
package/agent/v1.9.1/agent/elkeid-agent-src_1.7.0.24.tar.gz
```

### Driver Plugin

Driver plugin同样会在elkeidup deploy过程中会从源码build，所以同样替换package中的以下文件即可，建议解压该文件，确认该文件与目录结构与替换前的文件相同。

```bash
package/agent/v1.9.1/driver/driver-src_1.0.0.15.tar.gz
```

### 其他agent plugin

其他agent plugin都是预编译好的，按照各plugin的文档，编译好后替换对应的文件即可。注意plugin存在plg格式和tar.gz格式，plg格式为可执行文件，tar.gz为压缩包。版本号目前写死在elkeidup中，需要保持一致，请勿更改。

```bash
package/agent/v1.9.1/driver/driver-src_1.0.0.15.tar.gz
package/agent/v1.9.1/baseline/baseline-default-aarch64-1.0.1.23.tar.gz
package/agent/v1.9.1/baseline/baseline-default-x86_64-1.0.1.23.tar.gz
package/agent/v1.9.1/collector/collector-default-aarch64-1.0.0.140.plg
package/agent/v1.9.1/collector/collector-default-x86_64-1.0.0.140.plg
package/agent/v1.9.1/etrace/etrace-default-x86_64-1.0.0.92.tar.gz
package/agent/v1.9.1/journal_watcher/journal_watcher-default-aarch64-1.0.0.23.plg
package/agent/v1.9.1/journal_watcher/journal_watcher-default-x86_64-1.0.0.23.plg
package/agent/v1.9.1/rasp/rasp-default-x86_64-1.9.1.44.tar.gz
package/agent/v1.9.1/scanner/scanner-default-aarch64-3.1.9.6.tar.gz
package/agent/v1.9.1/scanner/scanner-default-x86_64-3.1.9.6.tar.gz
```

### ko

默认deploy时不会降预编译的ko拷贝到nginx中，在release界面同时会提供预编译的ko，下载预编译的ko或自行编译ko后，替换以下文件即可，文件为tar.xz格式，解压后有一个ko文件夹，格式必须相同。

```bash
package/to_upload/agent/component/driver/ko.tar.xz
```

### Manager & ServiceDiscovery & AgentCenter

编译好对应的二进制，解压以下路径的tar.gz，然后替换好二进制后打包回tar.gz即可。

```bash
# manager
package/manager/bin.tar.gz
# service discovery
package/service_discovery/bin.tar.gz
# agent center
package/agent_center/bin.tar.gz
```

## 安装后替换

### Agent 相关

Agent部分均可以通过前端上传，具体见agent发布文档

### ko

拷贝对应ko和sing文件到以下目录即可，之后执行命令修改目录权限

```bash
# ko 目录
/elkeid/nginx/ElkeidAgent/agent/component/driver/ko

# 修改权限
chown -R nginx:nginx /elkeid/nginx
```

### Manager & ServiceDiscovery & AgentCenter

暂停服务，替换对应的二进制文件，然后重启服务

```bash
# manager
systemctl stop elkeid_manager
mv new_manager_bin /elkeid/manager/manager
systemctl start elkeid_manager

# service discovery
systemctl stop elkeid_sd
mv new_sd_bin /elkeid/service_discovery/sd
systemctl start elkeid_sd

# agent center
systemctl stop elkeid_ac
mv new_ac_bin /elkeid/agent_center/agent_center
systemctl start elkeid_ac
```
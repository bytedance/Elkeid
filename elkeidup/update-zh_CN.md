Elkeidup 社区版升级指南 1.7.1 --> 1.9.1

# 前言

首先需要配置elkeidup 1.7.1 与 1.9.1 版本共存，然后按情况进行切换。

详细操作请同时参照1.7.1 与 1.9.1 的文档。

```
# rename .elkeidup dir
cd /root
mv .elkeidup .elkeidup_v1.7.1
ln -s .elkeidup_v1.7.1 .elkeidup

# copy cert to v1.9.1
mkdir -p /root/.elkeidup_v1.9.1
cp -r /root/.elkeidup_v1.7.1/elkeid_password /root/.elkeidup_v1.9.1
cp -r /root/.elkeidup_v1.7.1/cert /root/.elkeidup_v1.9.1
# download v1.9.1 package to /root/.elkeidup_v1.9.1
```

切换到 1.7.1

```
rm /root/.elkeidup && ln -s /root/.elkeidup_v1.7.1 /root/.elkeidup
```

切换到 1.9.1

```
rm /root/.elkeidup && ln -s /root/.elkeidup_v1.9.1 /root/.elkeidup
```

# 后端

v1.9.1后端目前无法与v1.7.1兼容，需要卸载v1.7.1后端后重新安装v1.9.1。

## 备份数据

根据需要选择备份数据：

1.  备份 MongoDB：目录位于 /elkeid/mongodb 仅是备份DB，备份的数据无法直接使用，如果有恢复需求，目前尚无自动化脚本，需要手动转换。
2.  备份Hub策略：目录位于 /elkeid/hub 策略可以在Hub web界面中进行导入。

## 卸载v1.7.1

> 在卸载v1.7.1后端后，Agent将在1min后自动关闭所有插件，并进入守护状态，直到新的后端被安装

```
# 按照前言操作切换到 v1.7.1

cd /root/.elkeidup 
./elkeidup undeploy
```

## 安装v1.9.1

> 在安装v1.9.1后端后，Agent将在1min内重连，但此时还尚未加载任何插件，您可以在Console上看到这个状态

```
# 按照前言操作切换到 v1.9.1
# 安装文档详见v1.9.1 安装文档
cd /root/.elkeidup 
./elkeidup deploy
```

# Agent

## 确认配置及状态

-   `/root/.elkeidup_v1.7.1/cert` `/root/.elkeidup_v1.9.1/cert` 三个目录内的所有文件内容均保持一致

-   `/root/.elkeidup_v1.7.1/elkeid_server.yaml` `/root/.elkeidup_v1.9.1/elkeidup_config.yaml` 三个文件中，下述相关配置均保持一致。

    -     注：具体字段filed值以`v1.9.1`为准，请勿直接覆盖。

    -   nginx

        -   domain
        -   ssh_host
        -   public_addr

    -   mg

        -   ssh_host

-   确认后端更新完成后，所有v1.7.1的Agent均已成功上线

## Build v1.9.1组件

```
./elkeidup agent init
./elkeidup agent build
./elkeidup agent policy create
```

## 下发任务

> 可根据需要进行灰度升级，此时新上线/重连的客户端会自动拉取最新配置升级，其他客户端需要手动同步配置升级

1.  在 [Elkeid Console - 任务管理](../server/docs/console_tutorial/Elkeid_Console_manual.md#任务管理) 界面，点击“新建任务”，选择单台主机，点击下一步，选择“同步配置”任务类型，点击确认。随后，在此页面找到刚刚创建的任务，点击运行，观察升级后的主机是否符合预期。
2.  在 [Elkeid Console - 任务管理](../server/docs/console_tutorial/Elkeid_Console_manual.md#任务管理) 界面，点击“新建任务”，选择全部主机，点击下一步，选择“同步配置”任务类型，点击确认。随后，在此页面找到刚刚创建的任务，点击运行，即可对存量旧版本Agent进行升级。
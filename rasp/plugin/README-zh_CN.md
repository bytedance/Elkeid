# RASP plugin

## 制品形式

* 包含有 rasp 插件以及各 runtime 探针的 tar.gz 压缩包。
* 可在 [`bytedance/Elkeid: release`](https://github.com/bytedance/Elkeid/releases) 页面下载最新的制品。

## 组成
RASP 插件包含以下部件：

```console
├── rasp 插件主入口，由 agent 启动，与 agent 双向通信，与探针双向通信。
├── settings.toml 插件配置文件。
├── elkeid_rasp 仅用于对指定进程进行探针植入与通信使用，数据输出到 stdout。
├── lib-1.9.1.68 包含有各探针的目录，与版本号一致。
│     ├── golang
│     ├── java
│     ├── node
│     ├── pangolin
│     ├── php
│     ├── python
│     └── rasp_server
├── nsenter
└── mount_script
```
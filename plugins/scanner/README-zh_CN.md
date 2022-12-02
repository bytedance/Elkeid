<!-- vscode-markdown-toc -->
* 1. [ 关于 Scanner 插件](#Scanner)
	* 1.1. [ 平台兼容性](#)
	* 1.2. [Agent/后端 兼容性](#Agent)
* 2. [<font color=red>构建</font>](#fontcolorredfont)
	* 2.1. [Docker 完整docker编译环境 & 编译产物](#Dockerdocker)
	* 2.2. [编译](#-1)
* 3. [ 自定义编译配置（可选）](#-1)
	* 3.1. [ [检控扫描目录配置](./src/config.rs)](#.srcconfig.rs)
	* 3.2. [ [引擎配置](./src/model/engine/clamav/config.rs)](#.srcmodelengineclamavconfig.rs)
	* 3.3. [可选 : 1.  [Clamav  Database配置](./src/model/engine/clamav/updater.rs)](#:1.ClamavDatabase.srcmodelengineclamavupdater.rs)
	* 3.4. [可选 : 2. database 中的规则](#:2.database)
* 4. [插件任务](#-1)
* 5. [上报数据类型](#-1)
* 6. [已知问题](#-1)
* 7. [License](#License)

<!-- vscode-markdown-toc-config
	numbering=true
	autoSave=true
	/vscode-markdown-toc-config -->
<!-- /vscode-markdown-toc -->
[English](README.md) | 简体中文

# Elkeid-Scanner #

##  1. <a name='Scanner'></a> 关于 Scanner 插件
当前版本 1.9.X

Scanner 使用 [clamav 引擎](https://docs.clamav.net/Introduction.html)对系统进程和敏感目录进行周期扫描，以发现可疑静态文件（UPX/挖矿二进制/后门/木马/可疑脚本文件/...）。

###  1.1. <a name=''></a> 平台兼容性
与[Elkeid Agent](../README-zh_CN.md#平台兼容性)相同，目前预编译产物已支持 x86_64、Aarch64。

###  1.2. <a name='Agent'></a>Agent/后端 兼容性
向前兼容： 1.7.X、1.8.X


##  2. <a name='fontcolorredfont'></a><font color=red>构建</font>

开源版本通过 [Github Action](https://docs.github.com/cn/actions) 自动构建，完整编译环境与遍历流程可参考对应 Dockerfile。用户可通过 Dockerfile 创建 Docker 自动执行编译步骤。

###  2.1. <a name='Dockerdocker'></a>Docker 完整docker编译环境 & 编译产物
* aarch64
    * [Dockerfile.aarch64](docker/Dockerfile.aarch64)
    * [CI.aarch64](../../.github/workflows/Elkeid_plugin_scanner_aarch64.yml)
    * 预编译包 
    ```json
    {
        "id_list":[
            "xxxxxxxx"
        ],
        "data":{
            "config":[
                {
                    "name":"scanner",
                    "version":"3.1.9.6",
                    "download_url":[
                        "http://lf3-elkeid.bytetos.com/obj/elkeid-download/plugin/scanner/scanner-default-aarch64-3.1.9.6.tar.gz",
                        "http://lf6-elkeid.bytetos.com/obj/elkeid-download/plugin/scanner/scanner-default-aarch64-3.1.9.6.tar.gz",
                        "http://lf9-elkeid.bytetos.com/obj/elkeid-download/plugin/scanner/scanner-default-aarch64-3.1.9.6.tar.gz",
                        "http://lf26-elkeid.bytetos.com/obj/elkeid-download/plugin/scanner/scanner-default-aarch64-3.1.9.6.tar.gz"
                    ],
                    "type": "tar.gz",
                    "sha256": "d75a5c542a2d7c0900ad96401d65833833232fcf539896ac2d2a95619448850b",
                    "signature": "1089b8fdcb69eac690323b0d092d8386901ded2155a057bf4d044679a2b83a9c",
                    "detail":""
                }
            ]
        }
    }
    ```

* x86_64
    * [Dockerfile.x86_64](docker/Dockerfile.x86_64)
    * [CI.x86_64](../../.github/workflows/Elkeid_plugin_scanner_x86_64.yml)
    * 预编译包 
    ```json
    {
        "id_list":[
            "xxxxxxxx"
        ],
        "data":{
            "config":[
                {
                    "name":"scanner",
                    "version":"3.1.9.6",
                    "download_url":[
                        "http://lf3-elkeid.bytetos.com/obj/elkeid-download/plugin/scanner/scanner-default-x86_64-3.1.9.6.tar.gz",
                        "http://lf6-elkeid.bytetos.com/obj/elkeid-download/plugin/scanner/scanner-default-x86_64-3.1.9.6.tar.gz",
                        "http://lf9-elkeid.bytetos.com/obj/elkeid-download/plugin/scanner/scanner-default-x86_64-3.1.9.6.tar.gz",
                        "http://lf26-elkeid.bytetos.com/obj/elkeid-download/plugin/scanner/scanner-default-x86_64-3.1.9.6.tar.gz"
                    ],
                    "type": "tar.gz",
                    "sha256": "e17e7380233c64172c767aa7587a9e303b11132e97c0d36a42e450469c852fdf",
                    "signature": "527c6ea0caac3b0604021de5aa2d34e4b9fae715e5e6cdd37e8f485869f923c2",
                    "detail":""
                }
            ]
        }
    }
    ```

###  2.2. <a name='-1'></a>编译

```bash
# x86_64
docker build -t scanner -f docker/Dockerfile.x86_64 ../../ 
docker create --name scanner scanner
docker cp scanner:/Elkeid/plugins/scanner/output/scanner-x86_64.tar.gz ./
docker rm -f scanner

# aarch64
docker build -t scanner -f docker/Dockerfile.aarch64 ../../ 
docker create --name scanner scanner
docker cp scanner:/Elkeid/plugins/scanner/output/scanner-aarch64.tar.gz ./
docker rm -f scanner
```

##  3. <a name='-1'></a> 自定义编译配置（可选）
在下列文件中，有一些常量，可根据实际情况进行配置（出于性能考虑，除规则外，建议保持默认）。
* 检控扫描目录配置 [src/config.rs](./src/config.rs)
* 引擎配置 [src/model/engine/clamav/config.rs](./src/model/engine/clamav/config.rs)
* Database配置 [src/model/engine/clamav/updater.rs](./src/model/engine/clamav/updater.rs)

###  3.1. <a name='.srcconfig.rs'></a> [检控扫描目录配置](./src/config.rs)
* `SCAN_DIR_CONFIG` 定义扫描目录，以及递归深度
* `SCAN_DIR_FILTER` 定义过滤目录，按照前缀匹配过滤扫描白名单

###  3.2. <a name='.srcmodelengineclamavconfig.rs'></a> [引擎配置](./src/model/engine/clamav/config.rs)
* `CLAMAV_MAX_FILESIZE` 定义扫描的文件的最大文件大小，跳过大文件


###  3.3. <a name=':1.ClamavDatabase.srcmodelengineclamavupdater.rs'></a>可选 : 1.  [Clamav  Database配置](./src/model/engine/clamav/updater.rs)


通过如下 url 获取默认 database（解压密码为 `clamav_default_passwd`）:

```bash
wget http://lf26-elkeid.bytetos.com/obj/elkeid-download/18249e0cbe7c6aca231f047cb31d753fa4604434fcb79f484ea477f6009303c3/archive_db_default_20220817.zip

#wget http://lf3-elkeid.bytetos.com/obj/elkeid-download/18249e0cbe7c6aca231f047cb31d753fa4604434fcb79f484ea477f6009303c3/archive_db_default_20220817.zip

#wget http://lf6-elkeid.bytetos.com/obj/elkeid-download/18249e0cbe7c6aca231f047cb31d753fa4604434fcb79f484ea477f6009303c3/archive_db_default_20220817.zip

#wget http://lf9-elkeid.bytetos.com/obj/elkeid-download/18249e0cbe7c6aca231f047cb31d753fa4604434fcb79f484ea477f6009303c3/archive_db_default_20220817.zip
```



clamav scanner 插件会在启动时，从 `TMP_PATH/archive_db_default_XXXX.zip` 使用默认密码 `ARCHIVE_DB_PWD`, [加载本地database](src/model/engine/updater.rs) 。同时, 从  `ARCHIVE_DB_VERSION_FILE` 文件中检查 `ARCHIVE_DB_VERSION` ，并且检查密码 `ARCHIVE_DB_PWD`.

更过逻辑细节参考代码 [src/model/engine/updater.rs](src/model/engine/updater.rs)

###  3.4. <a name=':2.database'></a>可选 : 2. database 中的规则

默认的 database 包括裁剪过的 clamav 官方数据库，以及开源的 yara 规则。
```bash
root@hostname$ ls
main.ldb  main.ndb  online_XXXXX.yar
```

在 debian9+ 或 ubuntu18+的 linux 中，可以通过如下方式，从最新的 clamav 官方数据库中生成裁剪过的 clamav 数据库。
```bash
root@hostname$ bash ./db_updater.sh
```

更多细节参考 [clamav 官方文档](https://docs.clamav.net/manual/Signatures.html)

* Notice
    - There are currently a few [limitations](https://docs.clamav.net/manual/Signatures/YaraRules.html) on using YARA rules within ClamAV


##  4. <a name='-1'></a>插件任务
scanner 插件任务支持
* 指定目录扫描
* 全盘扫描
* 快速扫描

详情参考[Elkeid 前端使用文档](../../server/docs/console_tutorial/Elkeid_Console_manual.md#病毒扫描)


##  5. <a name='-1'></a>上报数据类型

| 数据类型 | 6000-扫描任务结束 | 字段含义                           |
|------|-------------|--------------------------------|
| 1    | status      | 扫描任务结束状态: failed 失败，succeed 成功 |
| 2    | msg         | 日志                             |

| 数据类型 | 6001-检出静态文件 | 字段含义                      |
|------|-------------|---------------------------|
| 1    | types       | 检出文件类型                    |
| 2    | class       | 恶意样本分类                    |
| 3    | name        | 恶意样本家族                    |
| 4    | exe         | 检出文件目录                    |
| 5    | static_file | 检出文件目录                    |
| 6    | exe_size    | 检出文件 大小                   |
| 7    | exe_hash    | 检出文件 32kb xxhash          |
| 8    | md5_hash    | 检出文件 md5 hash             |
| 9    | create_at   | 检出文件 创建时间                 |
| 10   | modify_at   | 检出文件 最后修改时间               |
| 11   | hit_data    | yara命中数据（如果命中了Yara才会有此字段） |
| 12   | token       | 任务 token（全盘扫描任务才会有此字段）    |


| 数据类型 | 6002-检出进程exe | 字段含义                      |
|------|--------------|---------------------------|
| 1    | types        | exe文件类型                   |
| 2    | class        | 恶意样本分类                    |
| 3    | name         | 恶意样本家族                    |
| 4    | exe          | exe文件目录                   |
| 5    | static_file  | exe文件目录                   |
| 6    | exe_size     | exe文件 大小                  |
| 7    | exe_hash     | exe文件 32kb xxhash         |
| 8    | md5_hash     | exe文件 md5 hash            |
| 9    | create_at    | exe文件 创建时间                |
| 10   | modify_at    | exe文件 最后修改时间              |
| 11   | hit_data     | yara命中数据（如果命中了Yara才会有此字段） |
| 12   | pid          | 进程 id                     |
| 13   | ppid         | 父进程 id                    |
| 14   | pgid         | 进程组 id                    |
| 15   | tgid         | 线程组 id                    |
| 16   | argv         | 执行命令行                     |
| 17   | comm         | 进程名                       |
| 18   | sessionid    | proc/pid/stat/sessionid   |
| 19   | uid          | 用户ID                      |
| 20   | pns          | 进程 namespace              |
| 21   | token        | 任务 token（全盘扫描任务才会有此字段）    |


| 数据类型 | 6003-目录扫描任务 | 字段含义                      |
|------|-------------|---------------------------|
| 1    | types       | 检出文件类型                    |
| 2    | class       | 恶意样本分类                    |
| 3    | name        | 恶意样本家族                    |
| 4    | exe         | 检出文件目录                    |
| 5    | static_file | 检出文件目录                    |
| 6    | exe_size    | 检出文件 大小                   |
| 7    | exe_hash    | 检出文件 32kb xxhash          |
| 8    | md5_hash    | 检出文件 md5 hash             |
| 9    | create_at   | 检出文件 创建时间                 |
| 10   | modify_at   | 检出文件 最后修改时间               |
| 11   | hit_data    | yara命中数据（如果命中了Yara才会有此字段） |
| 12   | token       | 任务 token                  |
| 13   | error       | 错误信息 （任务出错时不为空）           |

##  6. <a name='-1'></a>已知问题
* Creation time / birth_time is not available for some filesystems
```bash
error: "creation time is not available for the filesystem
```
* Centos7 default compile tool-chains didn't work,  high version of tool-chains needed.


##  7. <a name='License'></a>License
Scanner plugin is distributed under the Apache-2.0 license.
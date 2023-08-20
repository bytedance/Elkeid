<!-- vscode-markdown-toc -->
* 1. [ 关于 Scanner 插件](#Scanner)
	* 1.1. [ 平台兼容性](#)
	* 1.2. [Agent/后端 兼容性](#Agent)
* 2. [ 配置](#-1)
	* 2.1. [ [检控扫描目录配置](./src/config.rs)](#.srcconfig.rs)
	* 2.2. [ [引擎配置](./src/model/engine/clamav/config.rs)](#.srcmodelengineclamavconfig.rs)
	* 2.3. [可选 : 1.  [Clamav  Database配置](./src/model/engine/clamav/updater.rs)](#:1.ClamavDatabase.srcmodelengineclamavupdater.rs)
	* 2.4. [可选 : 2. database 中的规则](#:2.database)
* 3. [<font color=red>构建</font>](#fontcolorredfont)
	* 3.1. [编译依赖](#-1)
	* 3.2. [编译](#-1)
	* 3.3. [Docker 完整编译环境](#Docker)
* 4. [插件任务](#-1)
	* 4.1. [ 自定义目录扫描任务](#-1)
	* 4.2. [ 全盘扫描任务](#-1)
	* 4.3. [防勒索任务(默认关闭)](#-1)
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
当前版本 2.0.X

Scanner 使用 [clamav 引擎](https://docs.clamav.net/Introduction.html)对系统进程和敏感目录进行周期扫描，以发现可疑静态文件（UPX/挖矿二进制/后门/木马/可疑脚本文件/...）。

###  1.1. <a name=''></a> 平台兼容性
与[Elkeid Agent](../README-zh_CN.md#平台兼容性)相同，目前预编译产物已支持 x86_64、Aarch64。

###  1.2. <a name='Agent'></a>Agent/后端 兼容性
向前兼容： 1.7.X、1.8.X、1.9.X

##  2. <a name='-1'></a> 配置
在下列文件中，有一些常量，可根据实际情况进行配置（出于性能考虑，除规则外，建议保持默认）。
* 检控扫描目录配置 [src/config.rs](./src/config.rs)
* 引擎配置 [src/model/engine/clamav/config.rs](./src/model/engine/clamav/config.rs)
* Database配置 [src/model/engine/clamav/updater.rs](./src/model/engine/clamav/updater.rs)

###  2.1. <a name='.srcconfig.rs'></a> [检控扫描目录配置](./src/config.rs)
* `SCAN_DIR_CONFIG` 定义扫描目录，以及递归深度
* `SCAN_DIR_FILTER` 定义过滤目录，按照前缀匹配过滤扫描白名单
* `FANOTIFY_CONFIGS` 定义文件监控目录，清空此配置以关闭文件监控功能（scanner 2.0+版本在内核支持的情况下默认开启）

###  2.2. <a name='.srcmodelengineclamavconfig.rs'></a> [引擎配置](./src/model/engine/clamav/config.rs)
* `CLAMAV_MAX_FILESIZE` 定义扫描的文件的最大文件大小，跳过大文件


###  2.3. <a name=':1.ClamavDatabase.srcmodelengineclamavupdater.rs'></a>可选 : 1.  [Clamav  Database配置](./src/model/engine/clamav/updater.rs)


通过如下 url 获取默认 database（解压密码为 `clamav_default_passwd`）:

```bash
wget http://lf26-elkeid.bytetos.com/obj/elkeid-download/18249e0cbe7c6aca231f047cb31d753fa4604434fcb79f484ea477f6009303c3/archive_db_default_20220930.zip

#wget http://lf3-elkeid.bytetos.com/obj/elkeid-download/18249e0cbe7c6aca231f047cb31d753fa4604434fcb79f484ea477f6009303c3/archive_db_default_20220930.zip

#wget http://lf6-elkeid.bytetos.com/obj/elkeid-download/18249e0cbe7c6aca231f047cb31d753fa4604434fcb79f484ea477f6009303c3/archive_db_default_20220930.zip

#wget http://lf9-elkeid.bytetos.com/obj/elkeid-download/18249e0cbe7c6aca231f047cb31d753fa4604434fcb79f484ea477f6009303c3/archive_db_default_20220930.zip
```



clamav scanner 插件会在启动时，从 `TMP_PATH/archive_db_default_XXXX.zip` 使用默认密码 `ARCHIVE_DB_PWD`, [加载本地database](src/model/engine/updater.rs) 。同时, 从  `ARCHIVE_DB_VERSION_FILE` 文件中检查 `ARCHIVE_DB_VERSION` ，并且检查密码 `ARCHIVE_DB_PWD`.

更过逻辑细节参考代码 [src/model/engine/updater.rs](src/model/engine/updater.rs)

###  2.4. <a name=':2.database'></a>可选 : 2. database 中的规则

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


##  3. <a name='fontcolorredfont'></a><font color=red>构建</font>

###  3.1. <a name='-1'></a>编译依赖
```bash
debian 9+ or ubuntu18+

llvm
musl-gcc
cmake >= 3.15 (requried by clamav-buildchain)
ninjia-build
libclang >= 3.9 (requried by rust-bindgen)
gcc >= 6.3 (suggested gcc 6.3.0 which is the default version in debian 9)
libstdc++.a (libstdc++-6-dev in debian9, libstdc++-9-dev in ubuntu18)
python3  >= 3.6 (requried by clamav-buildchain)
python3-pip (requried by clamav-buildchain)
```
clamav source and buildchain ( seen in [./get_deps.sh](./get_deps.sh) and [./libclamav.sh](./libclamav.sh))


* Rust 1.64.0+ stable 准备

Please install [rust](https://www.rust-lang.org/tools/install) environment:
```
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
# add build target x86_64-unknown-linux-gnu
rustup target add x86_64-unknown-linux-gnu
```

* 运行脚本以获取 libclamav 编译链依赖
```bash
# 以 debian9 为例
bash ./get_deps.sh
```

###  3.2. <a name='-1'></a>编译

*  编译 libclamav 静态库和静态依赖库
```bash
# debian & ubuntu
bash ./libclamav.sh
```

* 指定 `libstdc++` 的所在路径 `STDLIBCXX_STATIC_PATH` 

    不同Linux发行版，不同的`libstdc++`版本，安装后对应不同的目录，需要手动指定 环境变量
   - debian9 中安装 libstdc++-6-dev 版本，需要 `export STDLIBCXX_STATIC_PATH='/usr/lib/gcc/x86_64-linux-gnu/6/'`
   - debian10 中安装 libstdc++-7-dev 版本，需要 `export STDLIBCXX_STATIC_PATH='/usr/lib/gcc/x86_64-linux-gnu/7/'`
   - debian10 中安装 libstdc++-8-dev 版本，需要 `export STDLIBCXX_STATIC_PATH='/usr/lib/gcc/x86_64-linux-gnu/8/'`

*  编译 elkeid clamav scanner 插件 和  cli 测试工具
```bash
# debian & ubuntu
bash ./build.sh
```

*  检查静态二进制编译产物
```
ldd ./output/scanner
#output
   not a dynamic executable
```

* elkeid 插件 （包模式）

插件下发格式.

```json
{
    "id_list":[
        "xxxxxxxx"
    ],
    "data":{
        "config":[
            {
                "name":"scanner",
                "version":"",
                "download_url":[
                    "http://xxxxxxxx/scanner-default-x86_64-3.2.0.6.tar.gz",
                    "http://xxxxxxxx/scanner-default-x86_64-3.2.0.6.tar.gz"
                ],
                "type": "tar.gz",
                "sha256": "sha256sum of scanner.tar.gz",
                "signature": "sha256sum of scanner elf binary",
                "detail":""
            }
        ]
    },
}
```

###  3.3. <a name='Docker'></a>Docker 完整编译环境

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
                    "version":"3.2.0.6",
                    "download_url":[
                        "http://lf3-elkeid.bytetos.com/obj/elkeid-download/plugin/scanner/scanner-default-aarch64-3.2.0.6.tar.gz",
                        "http://lf6-elkeid.bytetos.com/obj/elkeid-download/plugin/scanner/scanner-default-aarch64-3.2.0.6.tar.gz",
                        "http://lf9-elkeid.bytetos.com/obj/elkeid-download/plugin/scanner/scanner-default-aarch64-3.2.0.6.tar.gz",
                        "http://lf26-elkeid.bytetos.com/obj/elkeid-download/plugin/scanner/scanner-default-aarch64-3.2.0.6.tar.gz"
                    ],
                    "type": "tar.gz",
                    "sha256": "82350369c47e501fe25edf2fd05c811a4e0c855b7acc9b4cd51a1227b112ec4f",
                    "signature": "ae47e1b82520af8585ad1d073ba87f9b46fecb44e0bb8adb5e43c9d5a0888eda",
                    "detail":""
                }
            ]
        },
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
                    "version":"3.2.0.6",
                    "download_url":[
                        "http://lf3-elkeid.bytetos.com/obj/elkeid-download/plugin/scanner/scanner-default-x86_64-3.2.0.6.tar.gz",
                        "http://lf6-elkeid.bytetos.com/obj/elkeid-download/plugin/scanner/scanner-default-x86_64-3.2.0.6.tar.gz",
                        "http://lf9-elkeid.bytetos.com/obj/elkeid-download/plugin/scanner/scanner-default-x86_64-3.2.0.6.tar.gz",
                        "http://lf26-elkeid.bytetos.com/obj/elkeid-download/plugin/scanner/scanner-default-x86_64-3.2.0.6.tar.gz"
                    ],
                    "type": "tar.gz",
                    "sha256": "b14db1b9c533e61cc66b7ff505dd8bfffd50efdd8220ab35e7f7337460eea5c4",
                    "signature": "8540dd1442680946af2e371376f6e34627c78fabac9bf86296a14a8022b14dc4",
                    "detail":""
                }
            ]
        },
    }
    ```


##  4. <a name='-1'></a>插件任务

通过 manager API 下发插件任务
* 方式1.创建-执行
    * 创建任务 : POST http://{{IP}}:{PORT}/api/v1/agent/createTask/task
    * 执行任务 : POST http://{{IP}}:{PORT}/api/v1/agent/controlTask
* 方式2.快速执行
    * 快速执行 : POST http://{{IP}}:{PORT}/api/v1/agent/quickTask/task
    ```json
    {
        "agent_id":"33623333-3365-4905-b417-331e183333ff",
        "command": {
            "task": {
                "data_type":6053,
                "name": "scanner",
                "data": "{\"exe\":\"/usr/local/bin/xmirg\"}"
            }
        }
    }
    ```


###  4.1. <a name='-1'></a> 自定义目录扫描任务
* 创建扫描任务 POST http://{{IP}}:{PORT}/api/v1/agent/createTask/task

data_type : 6053
data : json strings
- exe : The absolute path of the file (not dir) to be scanned.


```json
{
    "tag": "test_all", // scan task for all the agent tagged as "test_all"
    "id_list": [
        "33623333-3365-4905-b417-331e183333ff"
    ],
    "data": {
        "task": {
            "data_type":6053,
            "name": "scanner",
            "data": "{\"exe\":\"/path/to/target\"}"
        }
    }
}
```

###  4.2. <a name='-1'></a> 全盘扫描任务
* 创建扫描任务 POST http://{{IP}}:{PORT}/api/v1/agent/createTask/task

data_type : 6057
data : json strings
- mode : 全盘扫描模式，full 全盘扫描，quick 快速扫描（进程和配置的关键目录），默认 快速扫描
- cpu_idle : 扫描过程占用 空闲 CPU 总资源的百分比，默认 仅使用单核10%
- timeout : scanner 执行 全盘/快速扫描 默认的超时时间，超时候终止扫描，默认 48 小时

```json
{
    "tag": "test_all", // scan task for all the agent tagged as "test_all"
    "id_list": [
        "33623333-3365-4905-b417-331e183333ff"
    ],
    "data": {
        "task": {
            "data_type":6057,
            "name": "scanner",
            "data": "{\"model\":\"/path/to/target\"}"
        }
    }
}
```

###  4.3. <a name='-1'></a>防勒索任务(默认关闭)

* 创建扫描任务 POST http://{{IP}}:{PORT}/api/v1/agent/createTask/task

data_type
- 6051 : 开启/重置 防勒索功能
- 6052 : 开启/重置 文件监控，并关闭 防勒索功能

```json
{
    "tag": "test_all", // scan task for all the agent tagged as "test_all"
    "id_list": [
        "33623333-3365-4905-b417-331e183333ff"
    ],
    "data": {
        "task": {
            "data_type":6051,
            "name": "scanner",
            "data": ""
        }
    }
}
```

##  5. <a name='-1'></a>上报数据类型

| 数据类型 | 6000-扫描任务结束  |  字段含义 |
|---|---|---|
|  1 | status  | 扫描任务结束状态: failed 失败，succeed 成功 |
|  2 | msg  |  日志 |

| 数据类型 | 6001-检出静态文件  |  字段含义 |
|---|---|---|
| 1| types        | 检出文件类型 |
| 2| class        | 恶意样本分类 |
| 3| name         | 恶意样本家族  |
| 4| exe          | 检出文件目录  |
| 5| static_file  | 检出文件目录  |
| 6| exe_size     | 检出文件 大小  |
| 7| exe_hash     | 检出文件 32kb xxhash  |
| 8| md5_hash     | 检出文件 md5 hash  |
| 9| create_at    | 检出文件 创建时间 |
|10| modify_at    | 检出文件 最后修改时间  |
|11| hit_data     | yara命中数据（如果命中了Yara才会有此字段） |
|12| token        | 任务 token（全盘扫描任务才会有此字段） |


| 数据类型 | 6002-检出进程exe  |  字段含义 |
|---|---|---|
| 1| types        | exe文件类型 |
| 2| class        | 恶意样本分类 |
| 3| name         | 恶意样本家族  |
| 4| exe          | exe文件目录  |
| 5| static_file  | exe文件目录  |
| 6| exe_size     | exe文件 大小  |
| 7| exe_hash     | exe文件 32kb xxhash  |
| 8| md5_hash     | exe文件 md5 hash  |
| 9| create_at    | exe文件 创建时间 |
|10| modify_at    | exe文件 最后修改时间  |
|11| hit_data     | yara命中数据（如果命中了Yara才会有此字段） |
|12| pid          | 进程 id |
|13| ppid         | 父进程 id  |
|14| pgid         | 进程组 id |
|15| tgid         | 线程组 id |
|16| argv         | 执行命令行 |
|17| comm         | 进程名 |
|18| sessionid    | proc/pid/stat/sessionid |
|19| uid          | 用户ID |
|20| pns          | 进程 namespace |
|21| token        | 任务 token（全盘扫描任务才会有此字段） |


| 数据类型 | 6003-目录扫描任务  |  字段含义 |
|---|---|---|
| 1| types        | 检出文件类型 |
| 2| class        | 恶意样本分类 |
| 3| name         | 恶意样本家族  |
| 4| exe          | 检出文件目录  |
| 5| static_file  | 检出文件目录  |
| 6| exe_size     | 检出文件 大小  |
| 7| exe_hash     | 检出文件 32kb xxhash  |
| 8| md5_hash     | 检出文件 md5 hash  |
| 9| create_at    | 检出文件 创建时间 |
|10| modify_at    | 检出文件 最后修改时间  |
|11| hit_data     | yara命中数据（如果命中了Yara才会有此字段） |
|12| token        | 任务 token |
|13| error        | 错误信息 （任务出错时不为空）|

| 数据类型 | 6005-防勒索事件  |  字段含义 |
|---|---|---|
| 1| types        | exe文件类型 (未命中为 not_detected) |
| 2| class        | 恶意样本分类 (防勒索事件 anti_ransom) |
| 3| name         | 恶意样本家族  |
| 4| exe          | exe文件目录  |
| 5| static_file  | exe文件目录  |
| 6| exe_size     | exe文件 大小  |
| 7| exe_hash     | exe文件 32kb xxhash  |
| 8| md5_hash     | exe文件 md5 hash  |
| 9| create_at    | exe文件 创建时间 |
|10| modify_at    | exe文件 最后修改时间  |
|11| hit_data     | yara命中数据（如果命中了Yara才会有此字段） |
|12| pid          | 进程 id |
|13| ppid         | 父进程 id  |
|14| pgid         | 进程组 id |
|15| tgid         | 线程组 id |
|16| argv         | 执行命令行 |
|17| comm         | 进程名 |
|18| sessionid    | proc/pid/stat/sessionid |
|19| uid          | 用户ID |
|20| pns          | 进程 namespace |
|21| file_path    | 变动文件目录 |
|22| file_hash    | 变动文件目录sha256 |
|23| file_mask    | 变动文件事件掩码 |


| 数据类型 | 6011-防勒索状态上报  |  字段含义 |
|---|---|---|
| 1|  status      | 防勒索状态(开启on,关闭off,不支持则不上报) |

| 数据类型 | 6012-文件监控事件  |  字段含义 |
|---|---|---|
| 1| exe          | exe文件目录  |
| 2| static_file  | exe文件目录  |
| 3| exe_size     | exe文件 大小  |
| 4| exe_hash     | exe文件 32kb xxhash  |
| 5| md5_hash     | exe文件 md5 hash  |
| 6| create_at    | exe文件 创建时间 |
| 7| modify_at    | exe文件 最后修改时间  |
| 9| pid          | 进程 id |
|10| ppid         | 父进程 id  |
|11| pgid         | 进程组 id |
|12| tgid         | 线程组 id |
|13| argv         | 执行命令行 |
|14| comm         | 进程名 |
|15| sessionid    | proc/pid/stat/sessionid |
|16| uid          | 用户ID |
|17| pns          | 进程 namespace |
|18| file_path    | 变动文件目录 |
|19| file_hash    | 变动文件目录sha256 |
|20| file_mask    | 变动文件事件掩码 |


##  6. <a name='-1'></a>已知问题
* Creation time / birth_time is not available for some filesystems
```bash
error: "creation time is not available for the filesystem
```
* Centos7 default compile tool-chains didn't work,  high version of tool-chains needed.


##  7. <a name='License'></a>License
Scanner plugin is distributed under the Apache-2.0 license.
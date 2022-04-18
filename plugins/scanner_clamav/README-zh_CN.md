[English](README.md) | 简体中文
## 关于 Clamav Scanner 插件
Clamav Scanner 使用 [clamav 引擎](https://docs.clamav.net/Introduction.html)对系统进程和敏感目录进行周期扫描，以发现可疑静态文件（UPX/挖矿二进制/挖矿脚本/可疑脚本文件/...）。

## 平台兼容性
与[Elkeid Agent](../README-zh_CN.md#平台兼容性)相同。

## 配置
在[config.rs](./src/config.rs)中,有下面一些常量，可根据实际情况进行配置（出于性能考虑，除规则外，建议保持默认）。

### 扫描配置
* `SCAN_DIR_CONFIG` 定义扫描目录，以及递归深度
* `SCAN_DIR_FILTER` 定义过滤目录，按照前缀匹配过滤扫描白名单

### 性能限制配置
* `LOAD_MMAP_MAX_SIZE` 定义扫描的文件的最大文件大小，跳过大文件
* `WAIT_INTERVAL_DAILY` 定义周期扫描每轮的间隔时间
* `WAIT_INTERVAL_DIR_SCAN` 定义周期扫描目录的间隔时间
* `WAIT_INTERVAL_PROC_SCAN` 定义周期扫描proc进程的间隔时间

### 可选 : 1. Clamav database 

通过如下 url 获取默认 database（解压密码为 `clamav_default_passwd`）:

```bash
wget http://lf26-elkeid.bytetos.com/obj/elkeid-download/18249e0cbe7c6aca231f047cb31d753fa4604434fcb79f484ea477f6009303c3/archive_db_default_20220414.zip

#wget http://lf3-elkeid.bytetos.com/obj/elkeid-download/18249e0cbe7c6aca231f047cb31d753fa4604434fcb79f484ea477f6009303c3/archive_db_default_20220414.zip

#wget http://lf6-elkeid.bytetos.com/obj/elkeid-download/18249e0cbe7c6aca231f047cb31d753fa4604434fcb79f484ea477f6009303c3/archive_db_default_20220414.zip

#wget http://lf9-elkeid.bytetos.com/obj/elkeid-download/18249e0cbe7c6aca231f047cb31d753fa4604434fcb79f484ea477f6009303c3/archive_db_default_20220414.zip
```



clamav scanner 插件会在启动时，从 `TMP_PATH/archive_db_default_XXXX.zip` 使用默认密码 `ARCHIVE_DB_PWD`, [加载本地database](src/updater.rs) 。同时, 从  `ARCHIVE_DB_VERSION_FILE` 文件中检查 `ARCHIVE_DB_VERSION` ，并且检查密码 `ARCHIVE_DB_PWD`.

更过逻辑细节参考代码 [src/updater.rs](src/updater.rs)

### 可选 : 2. database 中的规则

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



## <font color=red>需要的编译环境</font>

* 编译依赖
```bash
debian 9+ or ubuntu18+
llvm
musl-gcc
cmake
ninjia-build
libclang >= 3.9 (requried by rust-bindgen)
gcc >= 6.3 (suggested gcc 6.3.0 which is the default version in debian 9)
libstdc++.a (libstdc++-6-dev in debian9, libstdc++-9-dev in ubuntu18)
python3  >= 3.6 (requried by clamav-buildchain)
python3-pip (requried by clamav-buildchain)
```
clamav source and buildchain ( seen in [./get_deps.sh](./get_deps.sh))


* Rust 1.59.0+ stable 准备

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

## 编译

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
ldd ./output/scanner_clamav
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
                "name":"scanner_clamav",
                "version":"",
                "download_url":[
                    "http://xxxxxxxx/scanner_clamav-1.6.0.1.tar.gz",
                    "http://xxxxxxxx/scanner_clamav-1.6.0.1.tar.gz"
                ],
                "type": "tar.gz",
                "sha256": "sha256sum of scanner_clamav.tar.gz",
                "signature": "sha256sum of scanner_clamav elf binary",
                "detail":""
            }
        ]
    },
}
```

* 预编译包

```json
{
    "id_list":[
        "xxxxxxxx"
    ],
    "data":{
        "config":[
            {
                "name":"scanner_clamav",
                "version":"1.7.1.2",
                "download_url":[
                    "http://lf3-elkeid.bytetos.com/obj/elkeid-download/plugin/scanner_clamav/scanner_clamav-1.7.1.2.tar.gz",
                    "http://lf6-elkeid.bytetos.com/obj/elkeid-download/plugin/scanner_clamav/scanner_clamav-1.7.1.2.tar.gz",
                    "http://lf9-elkeid.bytetos.com/obj/elkeid-download/plugin/scanner_clamav/scanner_clamav-1.7.1.2.tar.gz",
                    "http://lf26-elkeid.bytetos.com/obj/elkeid-download/plugin/scanner_clamav/scanner_clamav-1.7.1.2.tar.gz"
                ],
                "type": "tar.gz",
                "sha256": "4785de04501cd2043c5a9a1b145faf4d297f3ab0156319e3fc5fa19137e68c37",
                "signature": "222e02064b9d2fff0ef4c53269e8f2ee3cc628c9befbf583ba93056766f32e68",
                "detail":""
            }
        ]
    },
}
```


## 插件任务

通过 manager API 下发插件任务

* 创建任务 : POST http://{{IP}}:{PORT}/api/v1/agent/createTask/task
* 执行任务 : POST http://{{IP}}:{PORT}/api/v1/agent/controlTask



###  扫描任务
* 创建扫描任务 POST http://{{IP}}:{PORT}/api/v1/agent/createTask/task

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
            "name": "scanner_clamav",
            "data": "{\"exe\":\"/path/to/target\"}"
        }
    }
}
```

## 已知问题
* Creation time / birth_time is not available for some filesystems
```bash
error: "creation time is not available for the filesystem
```
* Centos7 default compile tool-chains didn't work,  high version of tool-chains needed.


## License
Yara Scanner plugin is distributed under the Apache-2.0 license.
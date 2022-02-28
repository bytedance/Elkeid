English | [简体中文](README-zh_CN.md)
## About Clamav Scanner Plugin
Clamav Scanner is a Elkied plugin for scanning static files (using [clamav](https://docs.clamav.net/Introduction.html) engine).

## Supported Platforms
Same as [Elkeid Agent](../README.md#supported-platforms).


Reasons for not providing static link based on musl-libc : Seen Known Errors & Bugs


## Config
In `config.rs`, there are the following constants. In order to avoid occupying too much system resources, it is recommended to use the default parameters.

### Scan config
* `SCAN_DIR_CONFIG` define the scan directory list and recursion depth
* `SCAN_DIR_FILTER` define the filter directory list matched by prefix

### Performance limit config
* `LOAD_MMAP_MAX_SIZE` define the maximum file size of scanned files (skip large files)
* `WAIT_INTERVAL_DAILY` define the interval of each round of scanning
* `WAIT_INTERVAL_DIR_SCAN` define the interval between scanning directories
* `WAIT_INTERVAL_PROC_SCAN` define the interval between scanning processes

### Option : 1. Clamav database 

Get default database url with default password `clamav_default_passwd`:

```bash
wget http://lf26-elkeid.bytetos.com/obj/elkeid-download/18249e0cbe7c6aca231f047cb31d753fa4604434fcb79f484ea477f6009303c3/archive_db_default.zip

#wget http://lf3-elkeid.bytetos.com/obj/elkeid-download/18249e0cbe7c6aca231f047cb31d753fa4604434fcb79f484ea477f6009303c3/archive_db_default.zip

#wget http://lf6-elkeid.bytetos.com/obj/elkeid-download/18249e0cbe7c6aca231f047cb31d753fa4604434fcb79f484ea477f6009303c3/archive_db_default.zip

#wget http://lf9-elkeid.bytetos.com/obj/elkeid-download/18249e0cbe7c6aca231f047cb31d753fa4604434fcb79f484ea477f6009303c3/archive_db_default.zip
```

The clamav scanner plugin will [load local database](src/updater.rs) from `TMP_PATH/archive_db_default.zip` with password `ARCHIVE_DB_PWD`, besides, it will also check `ARCHIVE_DB_VERSION` from `ARCHIVE_DB_VERSION_FILE` and `ARCHIVE_DB_PWD`.

More details in [src/updater.rs](src/updater.rs)

### Option : 2. Rules

The default database includes cropped clamav database and open source yara rules.
```bash
root@hostname$ ls
main.ldb  main.ndb  online_20220222.yar
```

More details in [Clamav Docs](https://docs.clamav.net/manual/Signatures.html)

* Notice
    - There are currently a few [limitations](https://docs.clamav.net/manual/Signatures/YaraRules.html) on using YARA rules within ClamAV


## Compilation Environment Requirements


* Build Requirements
```bash
debian 9+ or ubuntu18+

llvm
musl-gcc
libclang >= 3.9 (requried by rust-bindgen)
gcc >= 6.3 (suggested gcc 6.3.0 which is the default version in debian 9)
libstdc++.a (libstdc++-6-dev in debian9, libstdc++-9-dev in ubuntu18)
python3  >= 3.4 (requried by clamav-buildchain)
clamav source and buildchain
```

* Rust 1.58.1 stable

Please install [rust](https://www.rust-lang.org/tools/install) environment:
```
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
# add build target x86_64-unknown-linux-gnu
rustup target add x86_64-unknown-linux-gnu
```

Run script to get dependencies
```bash
# for example : debian9
bash ./get_deps.sh
```

## Build

*  build libclamav static lib
```bash
# debian & ubuntu
bash ./libclamav.sh
```
*  build elkeid scanner and cli tool
```bash
# debian & ubuntu
bash ./build.sh
```

*  check static binary

```
ldd ./output/scanner_clamav
#output
   not a dynamic executable
```

* output

The `output/scanner_clamav.tar.gz` is used for agent config.

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

* pre-compiled package

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


## plugin task

Sending plugin-task using manager API

* create task : POST http://{{IP}}:{PORT}/api/v1/agent/createTask/task
* run task : POST http://{{IP}}:{PORT}/api/v1/agent/controlTask



### scan task
* create task POST http://{{IP}}:{PORT}/api/v1/agent/createTask/task

data : The absolute path of the file (not dir) to be scanned.


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
            "data": "/root/xmirg"
        }
    }
}
```



## Known Errors & issues
* Creation time / birth_time is not available for some filesystems
```bash
error: "creation time is not available for the filesystem
```
* Centos7 default compile tool-chains didn't work,  high version of tool-chains needed.

## License
Clamav Scanner Plugin is distributed under the Apache-2.0 license.
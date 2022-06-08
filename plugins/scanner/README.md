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
wget http://lf26-elkeid.bytetos.com/obj/elkeid-download/18249e0cbe7c6aca231f047cb31d753fa4604434fcb79f484ea477f6009303c3/archive_db_default_20220607.zip

#wget http://lf3-elkeid.bytetos.com/obj/elkeid-download/18249e0cbe7c6aca231f047cb31d753fa4604434fcb79f484ea477f6009303c3/archive_db_default_20220607.zip

#wget http://lf6-elkeid.bytetos.com/obj/elkeid-download/18249e0cbe7c6aca231f047cb31d753fa4604434fcb79f484ea477f6009303c3/archive_db_default_20220607.zip

#wget http://lf9-elkeid.bytetos.com/obj/elkeid-download/18249e0cbe7c6aca231f047cb31d753fa4604434fcb79f484ea477f6009303c3/archive_db_default_20220607.zip
```

The clamav scanner plugin will [load local database](src/model/engine/updater.rs) from `TMP_PATH/archive_db_default.zip` with password `ARCHIVE_DB_PWD`, besides, it will also check `ARCHIVE_DB_VERSION` from `ARCHIVE_DB_VERSION_FILE` and `ARCHIVE_DB_PWD`.

More details in [src/model/engine/updater.rs](src/model/engine/updater.rs)

### Option : 2. Rules

The default database includes cropped clamav database and open source yara rules.
```bash
root@hostname$ ls
main.ldb  main.ndb  online_XXXXXXXX.yar
```

More details in [Clamav Docs](https://docs.clamav.net/manual/Signatures.html)

* Notice
    - There are currently a few [limitations](https://docs.clamav.net/manual/Signatures/YaraRules.html) on using YARA rules within ClamAV



## <font color=red>Compilation Environment Requirements</font>


* Build Requirements
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


* Rust 1.60.0+ stable

Please install [rust](https://www.rust-lang.org/tools/install) environment:
```
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
# add build target x86_64-unknown-linux-gnu
rustup target add x86_64-unknown-linux-gnu
```

Run script to get build-tool-chain & dependencies of libclamav
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


* export `libstdc++` path `STDLIBCXX_STATIC_PATH` 

   - debian9 with libstdc++-6-dev `export STDLIBCXX_STATIC_PATH='/usr/lib/gcc/x86_64-linux-gnu/6/'`
   - debian10 with libstdc++-7-dev  `export STDLIBCXX_STATIC_PATH='/usr/lib/gcc/x86_64-linux-gnu/7/'`
   - debian10 with libstdc++-8-dev  `export STDLIBCXX_STATIC_PATH='/usr/lib/gcc/x86_64-linux-gnu/8/'`


*  build elkeid scanner and cli tool
```bash
# debian & ubuntu
bash ./build.sh
```

*  check static binary

```
ldd ./output/scanner
#output
   not a dynamic executable
```

* output

The `output/scanner.tar.gz` is used for agent config.

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
                    "http://xxxxxxxx/scanner-3.1.9.1.tar.gz",
                    "http://xxxxxxxx/scanner-3.1.9.1.tar.gz"
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

* pre-compiled package

```json
{
    "id_list":[
        "xxxxxxxx"
    ],
    "data":{
        "config":[
            {
                "name":"scanner",
                "version":"3.1.9.1",
                "download_url":[
                    "http://lf3-elkeid.bytetos.com/obj/elkeid-download/plugin/scanner/scanner-3.1.9.1.tar.gz",
                    "http://lf6-elkeid.bytetos.com/obj/elkeid-download/plugin/scanner/scanner-3.1.9.1.tar.gz",
                    "http://lf9-elkeid.bytetos.com/obj/elkeid-download/plugin/scanner/scanner-3.1.9.1.tar.gz",
                    "http://lf26-elkeid.bytetos.com/obj/elkeid-download/plugin/scanner/scanner-3.1.9.1.tar.gz"
                ],
                "type": "tar.gz",
                "sha256": "528ddd83cdcdcba90d11efa4a34279f2593b7489a8e71143ef11abf6a513fb9e",
                "signature": "4114058a2c2c8dbf40a04360dcc1a3de8b229a420e23c5ea3d4d3c2f005c6047",
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



## Known Errors & issues
* Creation time / birth_time is not available for some filesystems
```bash
error: "creation time is not available for the filesystem
```
* Centos7 default compile tool-chains didn't work,  high version of tool-chains needed.

## License
Clamav Scanner Plugin is distributed under the GPLv2 license.
<!-- vscode-markdown-toc -->
* 1. [About Scanner Plugin](#AboutScannerPlugin)
	* 1.1. [Supported Platforms](#SupportedPlatforms)
	* 1.2. [Agent/DataFlow compatibility](#AgentDataFlowcompatibility)
* 2. [Config](#Config)
	* 2.1. [[Scan Path config](./src/config.rs)](#ScanPathconfig.srcconfig.rs)
	* 2.2. [[Engine config](./src/model/engine/clamav/config.rs)](#Engineconfig.srcmodelengineclamavconfig.rs)
	* 2.3. [Option : 1. [Clamav database Database config](./src/model/engine/clamav/updater.rs).](#Option:1.ClamavdatabaseDatabaseconfig.srcmodelengineclamavupdater.rs.)
	* 2.4. [Option : 2. Rules](#Option:2.Rules)
* 3. [<font color=red>Build</font>](#fontcolorredBuildfont)
	* 3.1. [Compilation Environment Requirements](#CompilationEnvironmentRequirements)
	* 3.2. [Compile](#Compile)
	* 3.3. [Docker Builder](#DockerBuilder)
* 4. [plugin task](#plugintask)
	* 4.1. [ path scan task](#pathscantask)
	* 4.2. [ fulldisk scan task](#fulldiskscantask)
	* 4.3. [AntiRansom config task (off by defualt)](#AntiRansomconfigtaskoffbydefualt)
* 5. [ Scanner Report DataType](#ScannerReportDataType)
* 6. [Known Errors & issues](#KnownErrorsissues)
* 7. [License](#License)

<!-- vscode-markdown-toc-config
	numbering=true
	autoSave=true
	/vscode-markdown-toc-config -->
<!-- /vscode-markdown-toc -->
English | [简体中文](README-zh_CN.md)

# Elkeid-Scanner #

##  1. <a name='AboutScannerPlugin'></a>About Scanner Plugin
Current Version: 2.0.X

Scanner is a Elkied plugin for scanning static files (using [clamav](https://docs.clamav.net/Introduction.html) engine).

###  1.1. <a name='SupportedPlatforms'></a>Supported Platforms
Same as [Elkeid Agent](../README.md#supported-platforms). Pre-Compiled binary support : x86_64, Aarch64

###  1.2. <a name='AgentDataFlowcompatibility'></a>Agent/DataFlow compatibility
forward compatible: 1.7.X、1.8.X、1.9.X

##  2. <a name='Config'></a>Config
There are following files, with some constants. In order to avoid occupying too much system resources, it is recommended to use the default parameters.
* Scan Path config [src/config.rs](./src/config.rs)
* Engine config [src/model/engine/clamav/config.rs](./src/model/engine/clamav/config.rs)
* Database config [src/model/engine/clamav/updater.rs](./src/model/engine/clamav/updater.rs)

###  2.1. <a name='ScanPathconfig.srcconfig.rs'></a>[Scan Path config](./src/config.rs)
* `SCAN_DIR_CONFIG` define the scan directory list and recursion depth
* `SCAN_DIR_FILTER` define the filter directory list matched by prefix
* `FANOTIFY_CONFIGS` define the fanotify monitor directory list, which cound be disabled by clear this config.(scanner 2.0+ will turn on by default)

###  2.2. <a name='Engineconfig.srcmodelengineclamavconfig.rs'></a>[Engine config](./src/model/engine/clamav/config.rs)
* `CLAMAV_MAX_FILESIZE` define the maximum file size of scanned files (skip large files)


###  2.3. <a name='Option:1.ClamavdatabaseDatabaseconfig.srcmodelengineclamavupdater.rs.'></a>Option : 1. [Clamav database Database config](./src/model/engine/clamav/updater.rs). 

Get default database url with default password `clamav_default_passwd`:

```bash
wget http://lf26-elkeid.bytetos.com/obj/elkeid-download/18249e0cbe7c6aca231f047cb31d753fa4604434fcb79f484ea477f6009303c3/archive_db_default_20220930.zip

#wget http://lf3-elkeid.bytetos.com/obj/elkeid-download/18249e0cbe7c6aca231f047cb31d753fa4604434fcb79f484ea477f6009303c3/archive_db_default_20220930.zip

#wget http://lf6-elkeid.bytetos.com/obj/elkeid-download/18249e0cbe7c6aca231f047cb31d753fa4604434fcb79f484ea477f6009303c3/archive_db_default_20220930.zip

#wget http://lf9-elkeid.bytetos.com/obj/elkeid-download/18249e0cbe7c6aca231f047cb31d753fa4604434fcb79f484ea477f6009303c3/archive_db_default_20220930.zip
```

The clamav scanner plugin will [load local database](src/model/engine/updater.rs) from `TMP_PATH/archive_db_default.zip` with password `ARCHIVE_DB_PWD`, besides, it will also check `ARCHIVE_DB_VERSION` from `ARCHIVE_DB_VERSION_FILE` and `ARCHIVE_DB_PWD`.

More details in [src/model/engine/updater.rs](src/model/engine/updater.rs)

###  2.4. <a name='Option:2.Rules'></a>Option : 2. Rules

The default database includes cropped clamav database and open source yara rules.
```bash
root@hostname$ ls
main.ldb  main.ndb  online_XXXXXXXX.yar
```

More details in [Clamav Docs](https://docs.clamav.net/manual/Signatures.html)

* Notice
    - There are currently a few [limitations](https://docs.clamav.net/manual/Signatures/YaraRules.html) on using YARA rules within ClamAV



##  3. <a name='fontcolorredBuildfont'></a><font color=red>Build</font>

###  3.1. <a name='CompilationEnvironmentRequirements'></a>Compilation Environment Requirements
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


* Rust 1.64.0+ stable

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

###  3.2. <a name='Compile'></a>Compile

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


###  3.3. <a name='DockerBuilder'></a>Docker Builder

* aarch64
    * [Dockerfile.aarch64](docker/Dockerfile.aarch64)
    * [CI.aarch64](../../.github/workflows/Elkeid_plugin_scanner_aarch64.yml)
    * aarch64 scanner Binary
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
    * x86_64 scanner Binary
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


##  4. <a name='plugintask'></a>plugin task

Sending plugin-task using manager API

* Method-1.create-run
    * create task : POST http://{{IP}}:{PORT}/api/v1/agent/createTask/task
    * run task : POST http://{{IP}}:{PORT}/api/v1/agent/controlTask
* Method-2.quicktask
    * quicktask : POST http://{{IP}}:{PORT}/api/v1/agent/quickTask/task
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



###  4.1. <a name='pathscantask'></a> path scan task
* create task POST http://{{IP}}:{PORT}/api/v1/agent/createTask/task

data_type : 6053
data : json strings
- exe : The absolute path of the file (or dir) to be scanned.


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

###  4.2. <a name='fulldiskscantask'></a> fulldisk scan task
* create task POST http://{{IP}}:{PORT}/api/v1/agent/createTask/task

data_type : 6057
data : json strings
- mode : scan mode,`full` for fulldisk scan,`quick` for quickscan (process and key dir), quickscan by defualt
- cpu_idle : the percentage of total idle CPU resources occupied by the scanning process, the default is only 10% of one single core.
- timeout : The `timeout` for scanner to execute the full/quick scan task, the task will be terminated after the `timeout`(48 hours by defualt) . 

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
            "data": "{\"mode\":\"full\",\"cpu_idle\":\"20\",\"timeout\":\"3600\"}"
        }
    }
}
```

###  4.3. <a name='AntiRansomconfigtaskoffbydefualt'></a>AntiRansom config task (off by defualt)

* create task POST http://{{IP}}:{PORT}/api/v1/agent/createTask/task

data_type
- 6051 : on/reset antiransom feature
- 6052 : on/reset fanotify feature and turn off antiransom feature

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
            "data": "{}"
        }
    }
}
```

##  5. <a name='ScannerReportDataType'></a> Scanner Report DataType

| DataType | 6000-ScanTaskFinished  |  description |
|---|---|---|
|  1 | status  | task status : failed,succeed|
|  2 | msg  |  log |

| DataType | 6001-StaticMalwareFound  |  description |
|---|---|---|
| 1| types        | FileType |
| 2| class        | MalwareClass |
| 3| name         | MalwareName  |
| 4| exe          | target file path  |
| 5| static_file  | target file path  |
| 6| exe_size     | target file size  |
| 7| exe_hash     | target file 32kb xxhash  |
| 8| md5_hash     | target file md5 hash  |
| 9| create_at    | target file birth time |
|10| modify_at    | target file last modify time  |
|11| hit_data     | yara hit data(if yara hit） |
|12| token        | task token (only in 6057 task report) |


| DataType | 6002-ProcessMalwareFound  |  description |
|---|---|---|
| 1| types        | FileType |
| 2| class        | MalwareClass |
| 3| name         | MalwareName  |
| 4| exe          | exe file path  |
| 5| static_file  | exe file path  |
| 6| exe_size     | exe file size |
| 7| exe_hash     | exe 32kb xxhash  |
| 8| md5_hash     | exe md5 hash  |
| 9| create_at    | exe birth time |
|10| modify_at    | exe last modify time  |
|11| hit_data     | yara hit data(if yara hit） |
|12| pid          | process id |
|13| ppid         | parent process id  |
|14| pgid         | process group id |
|15| tgid         | thread group id |
|16| argv         | exe cmdline |
|17| comm         | process comm name |
|18| sessionid    | proc/pid/stat/sessionid |
|19| uid          | use ID |
|20| pns          | process namespace |
|21| token        | task token (only in 6057 task report) |


| DataType | 6003-PathScanTaskResult  |  description |
|---|---|---|
| 1| types        | target FileType |
| 2| class        | MalwareClass |
| 3| name         | MalwareName  |
| 4| exe          | target file path  |
| 5| static_file  | target file path  |
| 6| exe_size     | target file size  |
| 7| exe_hash     | target file 32kb xxhash  |
| 8| md5_hash     | target file md5 hash  |
| 9| create_at    | target file birth time |
|10| modify_at    | target file last modify time  |
|11| hit_data     | yara hit data(if yara hit） |
|12| token        | task token |
|13| error        | error log |

| DataType | 6005-Antiransom Event  |  description |
|---|---|---|
| 1| types        | exeFileType (not_detected if not hit) |
| 2| class        | MalwareClass (anti_ransom) |
| 3| name         | MalwareName  |
| 4| exe          | exe file path  |
| 5| static_file  | exe file path  |
| 6| exe_size     | exe file size  |
| 7| exe_hash     | exe 32kb xxhash  |
| 8| md5_hash     | exe md5 hash  |
| 9| create_at    | exe birth time |
|10| modify_at    | exe last modify time  |
|11| hit_data     | yara hit data(if yara hit） |
|12| pid          | process id |
|13| ppid         | parent process id  |
|14| pgid         | process group id |
|15| tgid         | thread group id |
|16| argv         | exe cmdline |
|17| comm         | process comm name |
|18| sessionid    | proc/pid/stat/sessionid |
|19| uid          | user ID |
|20| pns          | process namespace |
|21| file_path    | fanotify event file path |
|22| file_hash    | fanotify event file pathsha256 |
|23| file_mask    | fanotify event mask |


| DataType | 6011-Antiransom Status  |  description |
|---|---|---|
| 1|  status      | Antiransom Status(on,off, no report if not supported) |

| DataType | 6012-Fanotify Event  |  description |
|---|---|---|
| 1| exe          | exe file path  |
| 2| static_file  | exe file path  |
| 3| exe_size     | exe size  |
| 4| exe_hash     | exe 32kb xxhash  |
| 5| md5_hash     | exe md5 hash  |
| 6| create_at    | exe birth time |
| 7| modify_at    | exe last modify time  |
| 9| pid          | process id |
|10| ppid         | parent process id  |
|11| pgid         | process group id |
|12| tgid         | thread group id |
|13| argv         | exe cmdline |
|14| comm         | process comm name |
|15| sessionid    | proc/pid/stat/sessionid |
|16| uid          | user ID |
|17| pns          | process namespace |
|18| file_path    | fanotify event file path |
|19| file_hash    | fanotify event file pathsha256 |
|20| file_mask    | fanotify event mask |


##  6. <a name='KnownErrorsissues'></a>Known Errors & issues
* Creation time / birth_time is not available for some filesystems
```bash
error: "creation time is not available for the filesystem
```
* Centos7 default compile tool-chains didn't work,  high version of tool-chains needed.

##  7. <a name='License'></a>License
Clamav Scanner Plugin is distributed under the GPLv2 license.
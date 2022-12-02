<!-- vscode-markdown-toc -->
* 1. [About Scanner Plugin](#AboutScannerPlugin)
	* 1.1. [Supported Platforms](#SupportedPlatforms)
	* 1.2. [Agent/DataFlow compatibility](#AgentDataFlowcompatibility)
* 2. [<font color=red>Build</font>](#fontcolorredBuildfont)
	* 2.1. [Docker Builder](#DockerBuilder)
	* 2.2. [Compile](#Compile)
* 3. [Config](#Config)
	* 3.1. [[Scan Path config](./src/config.rs)](#ScanPathconfig.srcconfig.rs)
	* 3.2. [[Engine config](./src/model/engine/clamav/config.rs)](#Engineconfig.srcmodelengineclamavconfig.rs)
	* 3.3. [Option : 1. [Clamav database Database config](./src/model/engine/clamav/updater.rs).](#Option:1.ClamavdatabaseDatabaseconfig.srcmodelengineclamavupdater.rs.)
	* 3.4. [Option : 2. Rules](#Option:2.Rules)
* 4. [plugin task](#plugintask)
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
Current Version: 1.9.X

Scanner is a Elkied plugin for scanning static files (using [clamav](https://docs.clamav.net/Introduction.html) engine).

###  1.1. <a name='SupportedPlatforms'></a>Supported Platforms
Same as [Elkeid Agent](../README.md#supported-platforms). Pre-Compiled binary support : x86_64, Aarch64

###  1.2. <a name='AgentDataFlowcompatibility'></a>Agent/DataFlow compatibility
forward compatible: 1.7.X、1.8.X


##  2. <a name='fontcolorredBuildfont'></a><font color=red>Build</font>

Scanner CI workflow seen [Github Action](https://docs.github.com/cn/actions).

###  2.1. <a name='DockerBuilder'></a>Docker Builder
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

###  2.2. <a name='Compile'></a>Compile

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


##  3. <a name='Config'></a>Config
There are following files, with some constants. In order to avoid occupying too much system resources, it is recommended to use the default parameters.
* Scan Path config [src/config.rs](./src/config.rs)
* Engine config [src/model/engine/clamav/config.rs](./src/model/engine/clamav/config.rs)
* Database config [src/model/engine/clamav/updater.rs](./src/model/engine/clamav/updater.rs)

###  3.1. <a name='ScanPathconfig.srcconfig.rs'></a>[Scan Path config](./src/config.rs)
* `SCAN_DIR_CONFIG` define the scan directory list and recursion depth
* `SCAN_DIR_FILTER` define the filter directory list matched by prefix

###  3.2. <a name='Engineconfig.srcmodelengineclamavconfig.rs'></a>[Engine config](./src/model/engine/clamav/config.rs)
* `CLAMAV_MAX_FILESIZE` define the maximum file size of scanned files (skip large files)


###  3.3. <a name='Option:1.ClamavdatabaseDatabaseconfig.srcmodelengineclamavupdater.rs.'></a>Option : 1. [Clamav database Database config](./src/model/engine/clamav/updater.rs). 

Get default database url with default password `clamav_default_passwd`:

```bash
wget http://lf26-elkeid.bytetos.com/obj/elkeid-download/18249e0cbe7c6aca231f047cb31d753fa4604434fcb79f484ea477f6009303c3/archive_db_default_20220817.zip

#wget http://lf3-elkeid.bytetos.com/obj/elkeid-download/18249e0cbe7c6aca231f047cb31d753fa4604434fcb79f484ea477f6009303c3/archive_db_default_20220817.zip

#wget http://lf6-elkeid.bytetos.com/obj/elkeid-download/18249e0cbe7c6aca231f047cb31d753fa4604434fcb79f484ea477f6009303c3/archive_db_default_20220817.zip

#wget http://lf9-elkeid.bytetos.com/obj/elkeid-download/18249e0cbe7c6aca231f047cb31d753fa4604434fcb79f484ea477f6009303c3/archive_db_default_20220817.zip
```

The clamav scanner plugin will [load local database](src/model/engine/updater.rs) from `TMP_PATH/archive_db_default.zip` with password `ARCHIVE_DB_PWD`, besides, it will also check `ARCHIVE_DB_VERSION` from `ARCHIVE_DB_VERSION_FILE` and `ARCHIVE_DB_PWD`.

More details in [src/model/engine/updater.rs](src/model/engine/updater.rs)

###  3.4. <a name='Option:2.Rules'></a>Option : 2. Rules

The default database includes cropped clamav database and open source yara rules.
```bash
root@hostname$ ls
main.ldb  main.ndb  online_XXXXXXXX.yar
```

More details in [Clamav Docs](https://docs.clamav.net/manual/Signatures.html)

* Notice
    - There are currently a few [limitations](https://docs.clamav.net/manual/Signatures/YaraRules.html) on using YARA rules within ClamAV



      
##  4. <a name='plugintask'></a>plugin task
scanner plugin task (Seen [Elkeid Console Doc](../../server/docs/console_tutorial/Elkeid_Console_manual.md#病毒扫描)):
* Dir scan
* Fulldisk scan
* Quick scan

##  5. <a name='ScannerReportDataType'></a> Scanner Report DataType

| DataType | 6000-ScanTaskFinished | description                  |
|----------|-----------------------|------------------------------|
| 1        | status                | task status : failed,succeed |
| 2        | msg                   | log                          |

| DataType | 6001-StaticMalwareFound | description                           |
|----------|-------------------------|---------------------------------------|
| 1        | types                   | FileType                              |
| 2        | class                   | MalwareClass                          |
| 3        | name                    | MalwareName                           |
| 4        | exe                     | target file path                      |
| 5        | static_file             | target file path                      |
| 6        | exe_size                | target file size                      |
| 7        | exe_hash                | target file 32kb xxhash               |
| 8        | md5_hash                | target file md5 hash                  |
| 9        | create_at               | target file birth time                |
| 10       | modify_at               | target file last modify time          |
| 11       | hit_data                | yara hit data(if yara hit）            |
| 12       | token                   | task token (only in 6057 task report) |


| DataType | 6002-ProcessMalwareFound | description                           |
|----------|--------------------------|---------------------------------------|
| 1        | types                    | FileType                              |
| 2        | class                    | MalwareClass                          |
| 3        | name                     | MalwareName                           |
| 4        | exe                      | exe file path                         |
| 5        | static_file              | exe file path                         |
| 6        | exe_size                 | exe file size                         |
| 7        | exe_hash                 | exe 32kb xxhash                       |
| 8        | md5_hash                 | exe md5 hash                          |
| 9        | create_at                | exe birth time                        |
| 10       | modify_at                | exe last modify time                  |
| 11       | hit_data                 | yara hit data(if yara hit）            |
| 12       | pid                      | process id                            |
| 13       | ppid                     | parent process id                     |
| 14       | pgid                     | process group id                      |
| 15       | tgid                     | thread group id                       |
| 16       | argv                     | exe cmdline                           |
| 17       | comm                     | process comm name                     |
| 18       | sessionid                | proc/pid/stat/sessionid               |
| 19       | uid                      | use ID                                |
| 20       | pns                      | process namespace                     |
| 21       | token                    | task token (only in 6057 task report) |


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


##  6. <a name='KnownErrorsissues'></a>Known Errors & issues
* Creation time / birth_time is not available for some filesystems
```bash
error: "creation time is not available for the filesystem
```
* Centos7 default compile tool-chains didn't work,  high version of tool-chains needed.

##  7. <a name='License'></a>License
Clamav Scanner Plugin is distributed under the GPLv2 license.
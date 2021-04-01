[![License](https://img.shields.io/badge/License-Apache%20v2-blue.svg)](https://github.com/bytedance/Elkeid/blob/main/agent/LICENSE)
[![Project Status: Active – The project has reached a stable, usable state and is being actively developed.](https://www.repostatus.org/badges/latest/active.svg)](https://www.repostatus.org/#active)

English | [简体中文](README-zh_CN.md)
## About Elkeid Agent
Elkeid Agent is a User Space program designed to supplement multiple functionalities through build-in or third party plugins. The main program controls plugins' behavior via configurations and forwards data, collected by various Agent plugins, to the configured remote backend. 

Elkeid Agent is written in Golang, but plugins are designed to support other languages ​​([rust is currently supported](support/rust), and the next will be Golang).

A plugin is a program with a specific function that can be independently updated and configured. The plugin's resource usage will be monitored once it gets registered on the agent. The plugin's log will also be passed to the Agent and logged together.

You may check out two examples of plugin implementation in [driver](driver/) and [journal_watcher](journal_watcher/) directories. The former one parses and enriches the data transmitted by the Elkeid Driver from the kernel. The latter one is used for log monitoring.

We decoupled basic functionalities through this Agent-Plugins struct. Functional modules such as process monitoring and file auditioning could be implemented for specific needs, while basic modules, like communication and control/resource monitoring could stay the same across various Linux distributions.

The current version of Elkeid Agent is recommended only for local testing. Without Elkeid Server, it does not support remote control and configurations. 

## Supported Platforms
In theory, all Linux distribution systems are compatible, but only Debian (including Ubuntu) and RHEL (including CentOS) have been fully tested. All tests have been made only for the **x86_64** platform.
We recommend running the Elkeid Agent with **root privileges** in a **physical machine** or a **virtual machine** instead of a container for better compatibility with the current plugins.

## Compilation Environment Requirements
* Golang 1.15(Recommended)
## To Start Using Elkeid Agent
```
git clone --recursive https://github.com/bytedance/Elkeid
cd Elkeid/agent
go build
```
You will see the `agent` binary program in the current directory.
## Parameters And Options
If you want to see the parameters supported by the agent, please execute:
```
./agent --help
```
You will see: 
```
Usage:
  agent [OPTIONS]
Application Options:
  -v, --version                  Print agent version
      --plugin=                  Plugin socket path (default: plugin.sock)
      --log=                     Log file path (default: log/hids_agent.log)
      --config=                  Config file path(.yaml) (default: config.yaml)
      --data=[file|stdout|kafka] Set data output (default: stdout)
      --file_path=               If data option is file ,this option is used to set the file path (default: data.log)
      --addr=                    If data option is kafka ,this option is used to set kafka addr
      --topic=                   If data option is kafka ,this option is used to set kafka topic name

Help Options:
  -h, --help                     Show this help message

```
The configuration file is used to control the currently running plugin instance. Suppose you want to start running the Agent itself simply and quickly without enabling any plugin functions. In that case, you can directly execute `./agent`, and you will see the data output on the *stdout* of the current terminal.
```
[{"data_type":"1001","level":"error","msg":"no such file or directory","source":"config/config.go:114","timestamp":"${current_timestamp}"}]
[{"cpu":"0.00000","data_type":"1000","distro":"${your_distro}","io":"8192","kernel_version":"${your_kernel_version}","memory":"${current_agent_memory_usage}","plugins":"[]","slab":"${current_sys_slab_usage}","timestamp":"${current_timestamp}"}]
```
The error in the first line is caused by the configuration file not being found and can be ignored for now. The second line is the agent's heartbeat data. Each field in it describes the current Agent and Plugin information.
## Data Output
Elkeid Agent supports data transmission to local output or a remote message queue (via sarama/kafka). 
### Stdout(Default)
Flush all data in stdout. Note: This method does not save the data persistently. When data sending speed is too fast, it may cause the current terminal to run slowly.
### File
Save the data to the specified file. By default, it is the `data.log` in the agent working directory.
### Kafka
The Agent will start a synchronous producer to send data to Kafka. Please remember to configure the `addr` and `topic` parameters.
### Other Methods
You can use custom data output by implementing `Transport interface` under [transport](transport/transport.go). You should also modify the `main` function and set it as the default transport method.We will support gRPC in the future.
## Logs
You may configure the log file's storage path by setting thee `log` parameter(default is `log/hids_agent.log`). For more detailed log configuration, please modify the corresponding configurations in the `main`  function. All logs of error level or above will be sent to [Data Output](#data-output).
## Config File
For local testing purposes, a configuration file is provided to control the addition and deletion of plugins. This raises a significant security risk. Please do not deploy the current version directly in a production environment. 

When Agent starts, the config file, which is set by `--config`(default is `config.yaml` in working directory) will be monitored(via inotify). Whenever a modification event is triggered, the configuration file will be parsed and compared with the currently loaded plugins to achieve dynamic modification. Note: Please don't use vim/gedit and other tools when modifying, [they will not trigger the modification event of inotify](https://stackoverflow.com/questions/13312794/inotify-dont-treat-vim-editting-as-a-modification-event).

A correct configuration file looks like this:
```
plugins :
  -
    name: exmple1
    version: 0.0.0.1
    path: /opt/plugins/exmple1
    sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
  -
    name: exmple2
    version: 0.0.1.0
    path: /opt/plugins/exmple2
    sha256: 01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b
```
Among them, `name` and `version` need to be the same as the [plugin](support/README.md#registration) config, `path` is used to find the plugin binary file, and `sha256` is used to verify the actual startup file.

All events related to the plugin can be seen in the [log](#logs) file.
## Example With Elkeid Driver
### Precondition
* The [Linux Kernrl Module](../driver) (a ko file).
* The [Driver Plugin](driver) (a binary file).
* The [Agent](#to-start-using-Elkeid-agent) (a binary file).
### Select a working directory
I will use `/etc/hids` as the working directory for the following steps:
```
mkdir -p /etc/hids
```
### Install
Create the working directory of the plugin and copy the  files to it:
```
cp agent /etc/hids/agent
mkdir -p /etc/hids/plugin/driver/
cp driver /etc/hids/plugin/driver/driver
cp hids_driver.ko /etc/hids/plugin/driver/hids_driver-latest.ko
```
### Create config file
Calculate `sha256` of the plugin:
```
shasum -a 256 /etc/hids/plugin/driver/driver
5b76d3da59d45be3dd5d2326c1f2a87bd454ed4028201750b5b3eebb29cc6eac  /etc/hids/plugin/driver/driver
```
Content of `/etc/hids/config.yaml`:
```
echo "plugins: [{name: hids_driver,version: 1.5.0.0,path: ./plugin/driver/driver,sha256: 5b76d3da59d45be3dd5d2326c1f2a87bd454ed4028201750b5b3eebb29cc6eac}]" > /etc/hids/config.yaml
```
### Run Agent
Execute the following command:
```
/etc/hids/agent
```
You will see the data from kernel module on the screen.
If you want to disable this plugin, modify the configuration file and delete driver related fields:
```
echo "plugins: []" > /etc/hids/config.yaml
```
If you want to enable the Driver Plugin again, just [restore the configuration file](#create-config-file).

## License
Elkeid Agent are distributed under the Apache-2.0 license.

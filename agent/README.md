[![License](https://img.shields.io/badge/License-Apache%20v2-blue.svg)](https://github.com/DianrongSecurity/AgentSmith-HIDS/blob/master/LICENSE)
[![Project Status: Active – The project has reached a stable, usable state and is being actively developed.](https://www.repostatus.org/badges/latest/active.svg)](https://www.repostatus.org/#active)

English | [简体中文](README-zh_CN.md)
## About AgentSmith-HIDS Agent
AgentSmith-HIDS Agent is a user space program,which is used to forward data sent by other plugins to the remote end, and control other plugins according to configuration.

AgentSmith-HIDS Agent is built in golang, but plugins can be built in other languages ​​([rust is currently supported](support/rust), and the next supported one will be golang).

A plugin is a program with a specific function that can be independently updated and configured. After the plugin is registered to the agent, the resource usage of the plugin will be monitored, and the log of the plugin will also be passed to the Agent.

You can see two example plugins in the [driver](driver/) and [journal_watcher](journal_watcher/) directories. The former is used to parse and enrich the data transmitted by the AgentSmith-HIDS Driver from the kernel, and the latter is used for log monitoring.

Through this Agent-Plugins struct, we can decouple basic modules (such as communication and control/resource monitoring, etc.) from functional modules (such as process monitoring/file monitoring/vulnerability analysis, etc.) to achieve dynamic increase and decrease of the modules.

## Supported Platforms
In theory, all distribution systems under Linux are compatible, but Debian (including Ubuntu) and RHEL (including CentOS) have been fully tested.Currently, we have only tested on the x86_64 platform.
In addition, for better compatibility with the plugins, it is recommended to run the AgentSmith-HIDS Agent in a physical machine or a virtual machine instead of a container.
For maximum functionality, you should probably run with root privileges.
## Compilation Environment Requirements
* Golang 1.15(Recommended)
## To Start Using AgentSmith-HIDS Agent
```
git clone https://github.com/bytedance/AgentSmith-HIDS
cd AgentSmith-HIDS/agent
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
      --log=                     Log file path (default: log/agent_smith.log)
      --config=                  Config file path(.yaml) (default: config.yaml)
      --data=[file|stdout|kafka] Set data output (default: stdout)
      --file_path=               If data option is file ,this option is used to set the file path (default: data.log)
      --addr=                    If data option is kafka ,this option is used to set kafka addr
      --topic=                   If data option is kafka ,this option is used to set kafka topic name

Help Options:
  -h, --help                     Show this help message

```
The configuration file is used to control the currently running plugin instance. If you want to start running the Agent itself simply and quickly without enabling any plugin functions, then you can directly execute `./agent`, you will see the data output on the stdout of the current terminal:
```
[{"data_type":"1001","level":"error","msg":"no such file or directory","source":"config/config.go:114","timestamp":"${current_timestamp}"}]
[{"cpu":"0.00000","data_type":"1000","distro":"${your_distro}","io":"8192","kernel_version":"${your_kernel_version}","memory":"${current_agent_memory_usage}","plugins":"[]","slab":"${current_sys_slab_usage}","timestamp":"${current_timestamp}"}]
```
The error in the first line is caused by the configuration file not being found and can be ignored for now. The second line is the agent's heartbeat data, each field in it describes the current Agent and Plugin information.
## Data Output
The current version of AgentSmith-HIDS Agent is more used for local testing. It does not support remote control and configuration, but supports transmission of data to the remote (via sarama/kafka).Note: please do not use it in a production environment.
### Stdout(Default)
Flush all data in stdout. Note: This method does not save the data persistently. When data sending speed is too fast, it may cause the current terminal to run slowly.
### File
Save the data to the specified file, the default is the `data.log` in agent working directory.
### Kafka
Agent will start a synchronous producer to send data to Kafka, please remember to configure the `addr` and `topic` parameters.
### Other Methods
You can use custom data output by implementing `Transport interface` under [transport](transport/transport.go).Next, modify the `main` function and set it as the default transport method.In the future, we will support gRPC.
## Logs
You can configure the storage path of the log file by setting the `log` parameter(default is `log/agent_smith.log`), but for more detailed log configuration, please modify the corresponding configuration in the `main`  function. All logs of error level or above will be sent to [Data Output](#about-data-output).
## Config File
Currently for testing purposes, a configuration file is provided to control the addition and deletion of plugins. This poses a great security risk, please do not use it in a production environment. 

When Agent starts, the config file which is set by `--config`(default is `config.yaml` in working directory) will be monitored(via inotify). Whenever a modification event is triggered, the configuration file will be parsed and compared with the currently loaded plugins to achieve dynamic modification. Note: Please don't use vim/gedit and other tools when modifying, [they will not trigger the modification event of inotify](https://stackoverflow.com/questions/13312794/inotify-dont-treat-vim-editting-as-a-modification-event).

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
## Example With AgentSmith-HIDS Driver
### Precondition
* The [Linux Kernrl Module](../driver) (a ko file).
* The [Driver Plugin](driver) (a binary file).
* The [Agent](#to-start-using-agentsmith-hids-agent) (a binary file).
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
AgentSmith-HIDS Agent are distributed under the Apache-2.0 license.
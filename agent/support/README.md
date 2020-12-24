English | [简体中文](README-zh_CN.md)
## About Plugin
The plugin communicates with the agent through Unix Domain Socket (UDS), and the serialization method of the  message is [messagepack](https://msgpack.org/). 

The current version of the plugin-agent protocol is still relatively rough, and the communication protocol will continue to be improved in the future.
## Startup
The plugin is generally started by the agent. Here we have an assumption: the command (configuration) received by the agent are credible, otherwise some malicious commands will be executed.

The target executed by the agent needs to be a file (binary or script) with executable permissions. Before execution, it will check the `sha256` of the file to be executed. If it is inconsistent with the command (configuration), the plugin will refuse to start.

Before startup, the agent will put the plugin related information into a map with the plugin name. If there was a plugin with the same name in the map, then the version of the two will be compared, and if the version is the same, plugin will not start.

At startup, the agent will set the working directory of the plugin to `plugin/${plugin_name}/`, redirect the `stdout` and `stderr` of the plugin process to files, and reset the plugin `pgig` for convenience management.

At startup, the agent will record the `pid` and `pgid` of the plugin process.

## Registration
After the plugin process is started, it will first connect to the socket of the agent and send a registration request.

The registration request contains the name,the version, and the `pid` of the plugin process.

After the agent receives the registration request, it will query the map according to the plugin name in the request. If it is not found, the connection will be disconnected (only plugins in the map are allowed to establish a connection).

If the corresponding plugin is in the map, the `pgid` corresponding to the `pid` in the request will be compared with the `pgid` saved at startup. If it is inconsistent, the connection will be disconnected.

## Data Transmission 
After the above registration process is completed, plugin can start data transmission.

Data transmission is two-way, plugin sends `Data` to agent, and agent sends `Task` to plugin.

Data will be serialized into a `map[string]string` structure during transmission, and the `struct` in Rust will also be mapped to the above structure. A necessary field in the structure is `data_type` to distinguish different data types.

`Task` structure is as follows:
```
id uint32
content string
token string
```
`id` is used to identify the data type, and then parse `content`. If you need to return `Data` based on `Task`, you can send `Data` with the `token`.
## Exception and Exit
Socket connection runs through the entire life cycle of Plugin. If the connection is disconnected, the plugin needs to exit.
It is peer-to-peer for agent.If agent finds that the connection with a plugin is disconnected, it will delete the corresponding plugin from the map and kill the related child process.

## Plugin SDK
### Rust
* [plugin](rust/plugin)：Encapsulates the underlying communication details and returns the Sender/Receiver.
* [plugin_builder](rust/plugin_builder)：High-level encapsulation of log/communication.
### Golang
* TODO
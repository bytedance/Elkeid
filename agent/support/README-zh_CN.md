[English](README.md) | 简体中文
## 关于插件
插件通过Unix Domain Socket(UDS)与Agent进行通信，通信消息的序列化方式为[messagepack](https://msgpack.org/)。目前版本的插件-Agent协议还比较粗糙，之后会持续完善通信协议。
## 启动
插件一般是被Agent启动的，在这里我们有一个假设：Agent接收到的指令(配置)是可信的，否则会导致一些恶意命令被执行。

Agent执行的目标需要是一个具有可执行权限的文件（二进制或者脚本）。在执行前会校验所要执行文件的`sha256`，如果与命令(配置)中的不一致，则会拒绝启动。

在启动前，Agent会将插件相关信息以插件名为key放入一个map中，以方便后续查询。如果这时map中有同名的插件，那么会对比两者的版本信息，如果版本一致则不会启动。

在启动时Agent会设置插件的工作目录为`plugin/${plugin_name}/`，并将插件进程的`stdout`与`stderr`重定向到文件中，另外还会重设插件`pgig`以方便管理。

启动时，Agent会记录下子进程的`pid`及其`pgid`，等待后续校验。
## 注册
插件进程在被启动后，首先会连接Agent的Socket，并发出一个注册请求。

注册请求中包含着插件的名字、插件的版本以及插件进程的`pid`。

Agent在接收到注册请求后，会根据请求中的插件名字查询map，如果没有查询到则会断开这个连接(只有map中的插件才允许建立连接)。

如果查询到了相应的插件数据，则会查找请求中的`pid`对应的`pgid`，并与启动时记录的`pgid`进行对比，如果不一致则会断开连接。

## 数据传输
在上述注册过程完成之后，Plugin可以开始进行数据传输了。

数据传输是双向的，Plugin向Agent发送Data，Agent向Plugin发送Task。

其中，Data在传输时会被序列化为`map[string]string`结构，在Rust中结构体也会被映射成为上述结构。结构中一个必要的字段为`data_type`以区分不同的数据类型。

Task数据结构如下所示：
```
id uint32
content string
token string
```
`id`用于判别数据类型，进而解析`content`。如果需要根据Task返回数据，则可以在Data字段中增加`token`以进行数据对账。

## 异常与退出
Socket连接贯穿于Plugin的整个生命周期，如果连接中断，则插件需要自行退出。
对等的，如果Agent发现与某个Plugin的连接中断，那么会从map中删除相应插件，并强制结束相关子进程。

## Plugin SDK
### Rust
* [plugin](rust/plugin)：封装了底层通信细节，返回Sender/Receiver两端。
* [plugin_builder](rust/plugin_builder)：以工厂模式对日志/通信做了高级封装。
### Golang
* TODO
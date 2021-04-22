[English](README.md) | 简体中文
## 关于collector插件
collector 会在定时扫描主机上的相关资产与配置，解析、规范数据之后上报到Server，并可根据需要进一步联动威胁情报，提升主机安全基线水位。另外，值得一提的是：在部分数据采集上，我们支持对主机上的容器内相关资产进行采集，以丰富我的资产数据库。

## 平台兼容性
与[Elkeid Agent](../README-zh_CN.md#平台兼容性)相同。

## 需要的编译环境
* Golang 1.16(必需)

## 编译
执行以下命令:
```
go build
```
## 弱口令库
collector使用[自带的弱口令库](weak_password)来检测主机上是否存在弱口令账号，请根据自己的环境随意增删。出于性能考虑，建议弱口令库的口令条数不多于1000条。

## License
collector plugin is distributed under the Apache-2.0 license.

English | [简体中文](README-zh_CN.md)
## About collector Plugin
The collector plugin periodically scans the relevant assets and configurations on the host, parses and standardizes the data, and reports it to the server, and can further link threat intelligence as needed to improve the baseline security level of the host. In addition, it is worth mentioning that in some data collection, we support the collection of related assets in the container on the host to enrich my asset database.

## Supported Platforms
Same as [Elkeid Agent](../README.md#supported-platforms)

## Compilation Environment Requirements
* Golang 1.16 (required)

## Building
Just run:
```
go build
```
## Weak password library
collector uses [self-contained weak password library](weak_password) to detect whether there are weak password accounts on the host. Please add or delete at will according to your own environment. For performance reasons, it is recommended that the number of passwords in the weak password database is not more than 1,000.

## License
collector plugin is distributed under the Apache-2.0 license.

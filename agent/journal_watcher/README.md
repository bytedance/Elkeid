English | [简体中文](README-zh_CN.md)
## About Journal Watcher Plugin
Journal Wacher is a plugin for monitoring systemd logs.
Currently, ssh-related events are mainly collected, which could be used to monitor abnormal login behaviors, such as ssh brute-force attack or krb5 abnormal logins, etc.

## Supported Platforms
Same as [AgentSmith-HIDS Agent](../README.md#supported-platforms)

## Compilation Environment Requirements
* Rust 1.48.0

Please install [rust](https://www.rust-lang.org/tools/install) environment:
```
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

## Building
Just run:
```
make build
```
or
```
cargo build --release
```
You will find the journal_watcher binary file under `target/release/`.

## Config
In `main.rs`, there are the following constants:
```
const AGENT_SOCK_PATH:&str = "/etc/hids/plugin.sock";
const PLUGIN_NAME:&str = "journal_watcher";
const PLUGIN_VERSION:&str = "1.0.0.0";
```
These can be configured as required, but remember those constants need to be consistent with the [agent's parameters ](../README.md#parameters-and-options) and [agent's config.yaml](../README.md#config-file).

## License
Journal Watcher Plugin are distributed under the LGPL-2.1 license.
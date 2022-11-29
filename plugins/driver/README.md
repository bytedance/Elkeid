English | [简体中文](README-zh_CN.md)
## About driver Plugin
The Driver plugin manages [Kernel Module](../../driver/README.md), supplements and filters data, and finally generates different system events to support related alarm functions.
## Runtime requirements
Supports mainstream Linux distributions, including CentOS, RHEL, Debian, Ubuntu, RockyLinux, OpenSUSE, etc. Supports x86-64 and aarch64 architectures.

The kernel version of the host needs to be in the supported list, if not, it needs to be compiled and uploaded separately, see [Description](../../elkeidup/README.md#agent-install-remark) for details.
## Quick start
Through the complete deployment of [elkeidup](../../elkeidup/README.md), this plugin is enabled by default.
## Compiling from source
### Dependency requirements
* [Rust](https://www.rust-lang.org) >= 1.48.0
* [Rust x86_64-unknown-linux-musl aarch64-unknown-linux-musl  compile chain](https://doc.bccnsoft.com/docs/rust-1.36.0-docs-html/edition-guide/rust-2018/platform-and-target-support/musl-support-for-fully-static-binaries.html)
* [musl-gcc](https://command-not-found.com/musl-gcc)
### Confirm related configuration
* It is necessary to ensure that the `DOWNLOAD_HOSTS` variable in `src/config.rs` has been configured as the actual deployed Nginx service address:
     * If it is a manually deployed Server: you need to ensure that it is configured as the address of the Nginx file service, for example: `pub const DOWNLOAD_HOSTS: &'static [&'static str] = &["http://192.168.0.1:8080" ];`
     * If the Server is deployed through [elkeidup](../../elkeidup/README.md), the corresponding configuration can be obtained according to the `~/.elkeidup/elkeidup_config.yaml` file of the deployed Server host, and the specific configuration item is `nginx .sshhost[0].host`, then set the port number to 8080, for example: `pub const DOWNLOAD_HOSTS: &'static [&'static str] = &["http://192.168.0.1:8080"];`
### Compile
In the root directory, execute:
```
BUILD_VERSION=1.0.0.15 bash build.sh
```
During the compilation process, the script will read the `BUILD_VERSION` environment variable to set the version information, which can be modified according to actual needs.

After the compilation is successful, you should see two plg files in the `output` directory of the root directory, which correspond to different system architectures.
### Version Upgrade
1. If no client component has been created, please create a new component in the [Elkeid Console-Component Management]() page.
2. On the [Elkeid Console - Component Management]() page, find the "driver" entry, click "Release Version" on the right, fill in the version information and upload the files corresponding to the platform and architecture, and click OK.
3. On the [Elkeid Console - Component Policy]() page, delete the old "driver" version policy (if any), click "New Policy", select the version just released, and click OK. Subsequent newly installed Agents will be self-upgraded to the latest version.
4. On the [Elkeid Console - Task Management]() page, click "New Task", select all hosts, click Next, select the "Sync Configuration" task type, and click OK. Then, find the task you just created on this page, and click Run to upgrade the old version of the Agent.
## License
driver plugin is distributed under the Apache-2.0 license.
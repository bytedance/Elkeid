English | [简体中文](README-zh_CN.md)
## About journal_watcher Plugin
The journal_watcher plugin reads and parses sshd logs to generate sshd login and gssapi events.
## Runtime requirements
Supports mainstream Linux distributions, including CentOS, RHEL, Debian, Ubuntu, RockyLinux, OpenSUSE, etc. Supports x86-64 and aarch64 architectures.
## Quick start
Through the complete deployment of [elkeidup](../../elkeidup), this plugin is enabled by default.
## Compiling from source
### Dependency requirements
* [Rust](https://www.rust-lang.org) >= 1.48.0
* [Rust x86_64-unknown-linux-musl aarch64-unknown-linux-musl  compile chain](https://doc.bccnsoft.com/docs/rust-1.36.0-docs-html/edition-guide/rust-2018/platform-and-target-support/musl-support-for-fully-static-binaries.html)
* [musl-gcc](https://command-not-found.com/musl-gcc)
### compile
In the root directory, execute:
```
BUILD_VERSION=1.7.0.23 bash build.sh
```
During the compilation process, the script will read the `BUILD_VERSION` environment variable to set the version information, which can be modified according to actual needs.

After the compilation is successful, you should see two plg files in the `output` directory of the root directory, which correspond to different system architectures.
### Version Upgrade
1. If no client component has been created, please create a new component in the [Elkeid Console-Component Management]() page.
2. On the [Elkeid Console - Component Management]() page, find the "journal_watcher" entry, click "Release Version" on the right, fill in the version information and upload the files corresponding to the platform and architecture, and click OK.
3. On the [Elkeid Console - Component Policy]() page, delete the old "journal_watcher" version policy (if any), click "New Policy", select the version just released, and click OK. Subsequent newly installed Agents will be self-upgraded to the latest version.
4. On the [Elkeid Console - Task Management]() page, click "New Task", select all hosts, click Next, select the "Sync Configuration" task type, and click OK. Then, find the task you just created on this page, and click Run to upgrade the old version of the Agent.
## License
The journal_watcher plugin is distributed under the Apache-2.0 license.
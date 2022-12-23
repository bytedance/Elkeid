# ElkeidUP

English | [简体中文](README-zh_CN.md)

Automated deployment of Elkeid tools

## Component List
[Resource configuration manual](./configuration.md)

## Instructions

* The backend server used for deployment needs to be used by Elkeid only
* The back-end server used for deployment needs to ensure intranet interoperability
* The backend server used for deployment requires root user privileges when deploying
* The backend server used for deployment can only be used: Centos7 and above; Ubuntu16 and above; Debian9 and above
* The server which execute elkeidup could execute `ssh root@x.x.x.x` without password to any backend server
* Deployment cannot be manually interrupted
* Only cat use LAN IP, do not use 127.0.0.1 or hostname or public IP
* Don't remove `~/.elkeidup` dir
* Don't fix any components used user's password, Include the Console(Elkeid Manager)

## Awareness of Auto-download missing kernel driver service

In this open-source version, we have integrated a service to provide auto-download capabilities for kernel driver files of those kernel versions that are missing from pre-compiled lists.

Service background: Elkeid Driver works in the kernel state. Since the kernel module loaded by the kernel is strongly bound to the kernel version, the kernel driver would have to match the correct kernel version. We cannot occupy the resources of the client's computer to compile ko files on the client's host machines when installing the agent. Therefore, we precompiled kernels for major Linux system distributions  in the release package to fit general cases. Currently, there are a total of 3435 precompiled ko, but there are still two problems that cannot be solved. One is that it cannot be updated in real-time. After the Major Linux system distributions release new updates to the kernel, we cannot and do not have enough manpower to catch up with those changes in time. The other problem is that you may use your own Linux kernel distribution. To this end, we provide the function of automatically downloading the missing precompiled kernel drivers. This function is mainly to inform our relevant engineer that some specific kernel versions are being used by users, and the release version should be updated as soon as possible.
If you choose to agree and enable this service, we need to collect some basic operating information at the same time, so that we can customize priority scheduling according to users with different needs, and give a reasonable evaluation of resource occupation. The email information filled in is only used to distinguish the identity of the source, real email or any nickname can be used. Specific information is as follows:

1. The kernel version and server architecture (only arm64 or amd64 can be selected, and no other CPU machine information is involved).
2. The number of connections of the agent on the agent center is collected every 30 minutes.
3. The QPS of the agent on the agent center, including send and receive, is collected every 30 minutes, and the average value of 30 minutes is taken.
4. The hub input QPS is collected every 30 minutes, and the average value of 30 minutes is taken.
5. Redis QPS, collected every 30 minutes, takes an average value of 30 minutes.
6. Redis memory usage, collected every 30 minutes, real-time value.
7. The QPS produced and consumed by Kafka are collected every 30 minutes, and the average value of 30 minutes is taken.
8. MongoDB QPS, collects every 30 minutes, and takes an average value of 30 minutes.

If you do not agree to enable this service, you can still have access to all pre-compiled ko included in the release package, and all other functions will not be affected.
The specific operation is to download `ko_1.7.0.9.tar.xz` on the release interface, and then replace `package/to_upload/agent/component/driver/ko.tar.xz`. During deployment, ko will be decompressed to `/elkeid/nginx/ElkeidAgent/agent/component/driver/ko` directory.
You may simply enable related functions during the elkeidup deployment progress. The relative config could also bee found inside `elkeidup_config.yaml` file in the conf directory where the manager is running based upon. If you enable this service during deployment, but need to disable it in the subsequent process, you can set report.enable_report in the `elkeidup_config.yaml` file to false, and then restart the manager.

The codes for collecting information and downloading KO files from Elkeid services are all in the open-sourced code. The relevant functions are listed as follows.
- The on/off switch is located in the InitReport() function of `internal/monitor/report.go`.
- The collection information item is located in the heartbeatDefaultQuery structure of `internal/monitor/report.go`.
- The function of automatically downloading ko is located in the SendAgentDriverKoMissedMsg function of `biz/handler/v6/ko.go`.


### Elkeid Deployment(Recommended)
[Elkeid Deployment](./deploy.md)

### Elkeid HUB Deployment
[Elkeid HUB Deployment Only](./deploy_hub.md)

### Upgrading and Expansion
- [Elkeid Upgrade Guide](./update.md)
- [Elkeid Expansion Guide](./expansion.md)

## Raw Data Usage Tutorial
- [Elkeid Data Description](../server/docs/ElkeidData.xlsx)
- [Raw Data Usage Tutorial](raw_data_usage_tutorial/raw_data_usage_tutorial-zh_CN.md)


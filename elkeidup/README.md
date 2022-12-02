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
* The server which execute elkeidup could execute ssh root@x.x.x.x without password to any backend server
* Deployment cannot be manually interrupted
* Only cat use LAN IP, do not use 127.0.0.1 or hostname or public IP
* Don't remove `~/.elkeidup` dir
* Don't fix any components used user's password, Include the Console(Elkeid Manager)

### Automatic Download Pre-Compile KO Prompt:

**Service Background**:
Elkeid Driver works in kernel mode. Since the kernel requires a strong association between the loaded kernel module and the kernel version, we cannot use the resources of the client to compile ko on the client when installing the agent. Therefore, we provide pre-compiled ko in the release package to avoid the need to manually compile ko every time. Currently, there are 3435 pre-compiled ko in total. But there are still two problems that cannot be solved. One is that it cannot be updated in real time. After the upstream distribution version updates the kernel, we cannot and do not have the manpower to sync up the update of the pre-compiled ko to the release. The kernel used by the distribution version. To this end, we provide the function of automatically downloading the missing pre-compiled ko. This function is mainly to notify our relevant classmates that the ko has customers trying it out, and update or cover the distribution version from the upstream as soon as possible.
If you choose to agree to start this service, we need to collect some basic operation information at the same time, so that we can customize the priority scheduling according to users with different needs, and give a reasonable resource occupation assessment. The email information filled in is only used to distinguish the identity of the source, real email or nickname can be used. The specific information is as follows:
1. The kernel version of the pre-compiled ko is missing, and the server architecture (only one of arm64 or amd64 is selected, and no other CPU machine information is involved).
2. The number of linkages of the agent on the agent center is collected every 30min.
3. The qps of the agent on the agent center, including send and receive, are collected every 30 minutes, and the average value of 30 minutes is taken.
4. Hub input qps, collect it every 30min, and take the average value of 30min.
5. redis qps, collected every 30min, take the average value of 30min.
6. redis memory occupancy, collected every 30min, real-time numeric value.
7. The qps produced and consumed by kafka are collected every 30 minutes and averaged for 30 minutes.
8. mongodb qps, collected every 30min, take the average value of 30min.

If you do not agree to turn on this service, you can still use the pre-compile ko provided in the release package, and other functions will not be affected. The specific operation is to download the ko_1.7.0.9.tar.xz in the release interface, and then replace the `package/to_upload/agent/component/driver/ko.tar.xz`. During deploy, the ko will be decompressed into the `/elkeid/nginx/ElkeidAgent/agent/component/driver/ko` directory. The relevant collection information and the code for downloading ko are in the open source manager code. Whether to turn on the relevant functions depends on the `elkeidup_config.yaml` file in the conf directory when the manager runs. If you have this service turned on during deployment, but need to turn it off later in the process, you can set the `report.enable_report` in the `elkeidup_config.yaml` file to `false` and then restart manager.

> Attachment:
> 
> The relevant functions are located in the following places in the manager code:
> - The switch is located in the InitReport () function of internal/monitor/report.go, clear the function content to close the function entry.
> - The collection information item is located in the heartbeatDefaultQuery structure of internal/monitor/report.go.
> - The auto-download ko function is located in the SendAgentDriverKoMissedMsg function in biz/handler/v6/ko.go.


### Elkeid Deployment(Recommended)
[Elkeid Deployment](./deploy.md)

### Elkeid HUB Deployment
[Elkeid HUB Deployment Only](./deploy_hub.md)

## Raw Data Usage Tutorial
- [Elkeid Data Description](../server/docs/ElkeidData.xlsx)
- [Raw Data Usage Tutorial](raw_data_usage_tutorial/raw_data_usage_tutorial-zh_CN.md)


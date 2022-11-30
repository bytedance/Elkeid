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

### Collect Information Prompt

In order to better build the Elkeid open source community, we hope to collect the following necessary information in your trial or use, so that we can understand your basic operating conditions. We need to refer to relevant information to formulate follow-up plans and give a reasonable resource usage assessment.
We will try to collect and only collect the following information, all the logic and code to collect information are located in the open source manager, the pre-compile manager binary is the same as the open source code, you can recompile:
1. The kernel version of the pre-compiled ko is missing, the server architecture (only one of arm64 or amd64, does not involve any other cpu machine information), only in the driver.
2. The number of linkages of the agent on the agent center is collected every 30min.
3. The qps of the agent on the agent center, including send and receive, are collected every 30 minutes, and the average value of 30 minutes is taken.
4. Hub input qps, collect it every 30min, and take the average value of 30min.
5. redis qps, collected every 30min, take the average value of 30min.
6. redis memory occupancy, collected every 30min, real-time numeric value.
7. The qps produced and consumed by kafka are collected every 30 minutes and averaged for 30 minutes.
8. mongodb qps, collected every 30min, take the average value of 30min.

> If you do not agree to the collection request, the only function of automatically downloading the missing pre-compile ko will not be available and will not affect other functions.

### Elkeid Deployment
[Elkeid Deployment](./deploy.md)

### Elkeid HUB Deployment
[Elkeid HUB Deployment Only](./deploy_hub.md)

## Raw Data Usage Tutorial
- [Elkeid Data Description](../server/docs/ElkeidData.xlsx)
- [Raw Data Usage Tutorial](raw_data_usage_tutorial/raw_data_usage_tutorial-zh_CN.md)


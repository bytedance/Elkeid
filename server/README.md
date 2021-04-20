[![License](https://img.shields.io/badge/License-Apache%20v2-blue.svg)](https://github.com/bytedance/Elkeid/blob/main/agent/LICENSE)
[![Project Status: Active – The project has reached a stable, usable state and is being actively developed.](https://www.repostatus.org/badges/latest/active.svg)](https://www.repostatus.org/#active)

English | [简体中文](README-zh_CN.md)
## System Architecture

<img src="docs/server.png"/>

## Overview
Elkeid Server contains 4 modules:：
1. AgentCenter (AC) is responsible for communicating with the Agent, collecting Agent data and simply processing and then writing to the Kafka cluster. At the same time, it is also responsible for the management of the Agent, including Agent upgrade, configuration modification, task distribution, etc. In addition, the AC also provides HTTP services, through which the Manager manages the AC and the Agent.
2. In ServiceDiscovery (SD), each service module needs to register with SD regularly and synchronize service information, so as to ensure that the instances in each service module are visible to each other and facilitate direct communication. Since SD maintains the status information of each registered service, when a service user requests service discovery, SD will perform load balancing. For example, the Agent requests a list of AC instances, and SD directly returns the AC instance with the least load pressure.
3. Manager is responsible for managing the entire back-end and providing related query and management interfaces. Including the management of the AC cluster, monitoring the status of the AC, and managing all agents through the AC, collecting the running status of the agent, and delivering tasks to the agent. At the same time, the manager also manages real-time and offline computing clusters.
4. The real-time/offline computing module consumes the data collected by AgentCenter in the kafka cluster for real-time and offline analysis and processing. (This part is not open source yet)

In short, AgentCenter collects Agent data, real-time/offline calculation module analyzes and processes the collected data, Manager manages AgentCenter and computing module, ServiceDiscovery connects all services and nodes.

## Features
- Backend infrastructure solutions for million-level Agent
- Distributed, decentralized, highly available cluster
- Simple deployment, few dependencies and easy maintenance

## Deployment document
- [deployment document](docs/install.md)

## API interface documentation
The Manger API uses token for authentication. Before calling all other interfaces, you need to use the /api/v1/user/login interface to get the token.
```
curl --location --request POST 'http://127.0.0.1:6701/api/v1/user/login' \
--data-raw '{
    "username": "hids_test",
    "password": "hids_test"
}'


{
    "code": 0,
    "msg": "success",
    "data": {
        "token": "xxxxxxxxxxx"
    }
}
```
Then add the token to the header of each request.
```
curl --location --request GET 'http://127.0.0.1:6701/api/v1/agent/getStatus'  -H "token:xxxxxxxxxxx"
```
For details, please refer to [API interface documentation](https://documenter.getpostman.com/view/9865152/TzCTZ5Do#intro)
## License
Elkeid Server are distributed under the Apache-2.0 license.

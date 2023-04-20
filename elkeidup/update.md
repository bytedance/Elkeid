Elkeidup Community Edition Upgrade Guide 1.7.1 -- > 1.9.1

# Foreword

First you need to configure elkeidup 1.7.1 to coexist with version 1.9.1, and then switch as the case may be.

For detailed operation, please refer to the documentation of 1.7.1 and 1.9.1 at the same time.

```
# rename .elkeidup dir
cd /root
mv .elkeidup .elkeidup_v1.7.1
ln -s .elkeidup_v1.7.1 .elkeidup

# copy cert to v1.9.1
mkdir -p /root/.elkeidup_v1.9.1
cp -r /root/.elkeidup_v1.7.1/elkeid_password /root/.elkeidup_v1.9.1
cp -r /root/.elkeidup_v1.7.1/cert /root/.elkeidup_v1.9.1
# download v1.9.1 package to /root/.elkeidup_v1.9.1
```

Switch to 1.7.1

```
rm /root/.elkeidup && ln -s /root/.elkeidup_v1.7.1 /root/.elkeidup
```

Switch to 1.9.1

```
rm /root/.elkeidup && ln -s /root/.elkeidup_v1.9.1 /root/.elkeidup
```

# Backend

The v1.9.1 backend is currently not compatible with v1.7.1, you need to uninstall the v1.7.1 backend and reinstall v1.9.1.

## backup data

Select backup data as needed:

1. Backup MongoDB: The directory is located /elkeid/mongodb is only a backup DB, and the backed up data cannot be used directly. If there is a recovery need, there is no automated script at present, and manual conversion is required.
2. Backup Hub Policies: The directory is located /elkeid/hub Policies can be imported in the Hub web interface.

## uninstall v1.7.1

> After uninstalling the v1.7.1 backend, Agent will automatically close all plugins after 1 minute and enter the daemon state until the new backend is installed

```
#switch to v1.7.1 according to the preface

cd /root/.elkeidup 
./elkeidup undeploy
```

## install v1.9.1

> After installing the v1.9.1 backend, the Agent will be reconnected within 1min, but no plugins have been loaded at this time, you can see this state on the Console

```
#switch to v1.9.1 according to the preface
#For installation documentation, see v1.9.1 installation documentation
cd /root/.elkeidup
./elkeidup deploy
```

# Agent

## Confirm configuration and state

- '/root/elkeidup_v1/cert'/root/elkeidup_v1/cert 'The contents of all files in the three directories are consistent

- '/root/elkeidup_v1/elkeid_server.yaml'/root/elkeidup_v1/elkeidup_config.yaml 'The following related configurations are consistent.

    - Note: The filed value of the specific field is subject to'v1.9.1 ', please do not directly cover.

    - nginx

        - domain
        - ssh_host
        - public_addr

    - mg

        - ssh_host

- After confirming that the backend update is complete, all v1.7.1 Agents have been successfully launched

## Build v1.9.1 component

```
./elkeidup agent init
./elkeidup agent build
./elkeidup agent policy created
```

## Submit a task

> Grey release upgrade can be performed as needed. At this time, the newly launched/reconnected client/client side/client end will automatically pull the latest configuration upgrade, and other client/client side/client ends need to manually sync up configuration upgrade

1. In the [Elkeid Console - Task Management](../server/docs/console_tutorial/Elkeid_Console_manual.md#任务管理) interface, click "New Task", select a single host, click Next, select the "sync up configuration" task type, and click Confirm. Then, find the task you just created on this page, click Run, and observe whether the upgraded host meets expectations.
2. In the [Elkeid Console - Task Management](../server/docs/console_tutorial/Elkeid_Console_manual.md#任务管理) interface, click "New Task", select all hosts, click Next, select "sync up configuration" task type, and click Confirm. Then, find the task you just created on this page and click Run to upgrade the old version of Agent.
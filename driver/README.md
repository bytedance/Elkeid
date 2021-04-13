[![License](https://img.shields.io/badge/License-GPL%20v2-blue.svg)](https://github.com/bytedance/Elkeid/blob/main/driver/LICENSE) [![Project Status: Active – The project has reached a stable, usable state and is being actively developed.](https://www.repostatus.org/badges/latest/active.svg)](https://www.repostatus.org/#active)

## About Elkeid(AgentSmith-HIDS) Driver

English | [简体中文](README-zh_CN.md)



Elkeid Driver is a one-of-a-kind Kernel Space HIDS agent designed for Cyber-Security. 

Elkeid Driver hooks kernel functions via Kprobe, providing rich and accurate data collection capabilities,  including kernel-level process execve probing, privilege escalation monitoring, network audition, and much more. The Driver treats Container-based monitoring as a first-class citizen as Host-based data collection by supporting Linux Namespace. Compare to User Space agents on the market, Elkeid provides more comprehensive information with massive performance improvement. 

Elkeid has already been deployed massively for HIDS usage in world-class production environments. With its marvelous data collection ability, Elkeid also supports Sandbox, Honeypot, and Audition data requirements. 

## Notice
***DO NOT* insmod the ko in the production machines if you have not well tested it.**

## Quick Test

First you need install Linux Headers

```shell script
git clone https://github.com/bytedance/Elkeid.git
cd Elkeid/driver/LKM/
make clean && make
insmod hids_driver.ko
dmesg
cat /proc/hids_driver/1
rmmod hids_driver
```

## About the compatibility with Linux distribution

Distro|Version|x64 kernel|Suffix | On our production env
:- | :- | -: | -| -:
debian|8,9,10|3.16~5.4.X |-| yes
ubuntu|14.04,16.04,18.04,20.04|3.12~5.4.X |generic| no 
centos|7.X,8.X|3.10.0~5.4.X |el7,el8| half 


## About the compatibility with ARM

* Partially support


## About the compatibility with Kernel version

* Linux Kernel Version >= 3.10 and <= 5.4.X



## About the compatibility with Containers

| Source | Nodename       |
| ------ | -------------- |
| Host   | hostname       |
| Docker | container name |
| k8s    | pod name       |



## Hook List

| Hook               | DataType | Note                                           | Default |
| ------------------ | -------- | ---------------------------------------------- | ------- |
| connect            | 42       |                                                | ON      |
| bind               | 49       |                                                | ON      |
| execve             | 59       |                                                | ON      |
| create file        | 602      |                                                | ON      |
| ptrace             | 101      | only PTRACE_POKETEXT or PTRACE_POKEDATA        | ON      |
| dns queny          | 601      |                                                | OFF      |
| init kernel module | 603      |                                                | ON      |
| update cred        | 604      | only old uid ≠0 && new uid == 0                | ON      |
| rename             | 82       |                                                | ON     |
| link               | 86       |                                                | ON     |
| setsid             | 112      |                                                | ON     |
| prctl              | 157      | only PS_SET_NAME                               | ON     |
| memfd_create       | 157      |                                                 | ON     |
| open               | 2        |                                                | OFF     |
| mprotect           | 10       | only PROT_EXEC                                 | OFF     |
| nanosleep          | 35       |                                                | OFF     |
| kill               | 62       |                                                | OFF     |
| tkill              | 200      |                                                | OFF     |
| process exit       | 60       |                                                | OFF     |
| exit group         | 231      |                                                | OFF     |
| rmdir              | 606      |                                                | OFF     |
| unlink             | 605      |                                                | OFF     |
| call_usermodehelper_exec             | 607      |                                         | OFF     |



## Anti Rootkit List

| Rootkit              | DataType | Default |
| -------------------- | -------- | ------- |
| interrupt table hook | 703      | ON      |
| syscall table hook   | 701      | ON      |
| proc file hook       | 700      | ON      |
| hidden kernel module | 702      | ON      |



## Driver TransData Pattern

### Data Protocol

'**\x1e**' is used as **field** deliminator

'**\x17**' is used as **data** deliminator

Hook List data type generats data consists of **Common Data** with each ***privatizated data*** (lists below with same type name)

Anti-rootkit List data does **NOT** contain fields in **Common Data**

### Common data

```
-------------------------------------------------------------------------------
|1  |2        |3  |4  |5   |6   |7   |8  |9   |10      |11       |12 |13      |
-------------------------------------------------------------------------------
|uid|data_type|exe|pid|ppid|pgid|tgid|sid|comm|nodename|sessionid|pns|root_pns|
-------------------------------------------------------------------------------
```



### Connect Data 

```
------------------------------------------------
|14          |15       |16 |17   |18 |19   |20 |
------------------------------------------------
|connect_type|sa_family|dip|dport|sip|sport|res|
------------------------------------------------
```

Note: Connect_type is always -1 in default build settings



### Bind Data

```
-------------------------
|14       |15 |16   |17 |
-------------------------
|sa_family|sip|sport|res|
-------------------------
```



### Execve Data

```
-------------------------------------------------------------------------------------------------------------------------
|14        |15  |16      |17      |18   |19    |20 |21   |22 |23   |24       |25      |26 |27        |28 |29        |30 |
-------------------------------------------------------------------------------------------------------------------------
|socket_exe|argv|run_path|pgid_exe|stdin|stdout|dip|dport|sip|sport|sa_family|pid_tree|tty|socket_pid|ssh|ld_preload|res|
-------------------------------------------------------------------------------------------------------------------------
```

Note:

* **socket_exe/dip/dport/sip/sport/sa_family** is collected from the process's fds

* **ssh/ld_preload** is collected from the process's env



### Create File data

```
----------------------------------------------------
|14 	  |15 |16   |17 |18   |19       |20        |
----------------------------------------------------
|file_path|dip|dport|sip|sport|sa_family|socket_pid|
----------------------------------------------------
```



### Ptrace

```
----------------------------------------------
|14            |15        |16  |17  |18      |
----------------------------------------------
|ptrace_request|target_pid|addr|data|pid_tree|
----------------------------------------------
```



### Dns Query Data

```
-----------------------------------------------------
|14   |15       |16 |17   |18 |19   |20|21    |22   |
-----------------------------------------------------
|query|sa_family|dip|dport|sip|sport|qr|opcode|rcode|
-----------------------------------------------------
```



### Init Kernel Module Data

```
----------------------------
|14      |15      |16      | 
----------------------------
|mod_info|pid_tree|run_path|
----------------------------
```



### Update Cred Data

```
----------------------
|14      |15     |16 | 
----------------------
|pid_tree|old_uid|res|
----------------------
```



### Rename Data

```
----------------------------
|14      |15      |16      | 
----------------------------
|run_path|old_name|new_name|
----------------------------
```



### Link Data

```
----------------------------
|14      |15      |16      | 
----------------------------
|run_path|old_name|new_name|
----------------------------
```



### Setsid Data

Only contains fields in ***Common Data***



### Prctl Data

```
_________________
|14    |15      | 
-----------------
|option|new_name|
-----------------
```

### memfd_create Data

```
______________
|14    |15   | 
--------------
|fdname|flags|
--------------
```



### Open Data

````
---------------------
|14   |15  |16      | 
---------------------
|flags|mode|filename|
---------------------
````



### Mprotect data

```
-----------------------------------------------------
|14           |15       |16        |17     |18      |
-----------------------------------------------------
|mprotect_prot|owner_pid|owner_file|vm_file|pid_tree|
-----------------------------------------------------
```



### Nanosleep Data

```
----------
|14 |15  |
----------
|sec|nsec|
----------
```



### Kill Data

```
----------------
|14        |15 |
----------------
|target_pid|sig|
----------------
```



### Tkill data

```
----------------
|14        |15 |
----------------
|target_pid|sig|
----------------
```



### Process Exit Data

Only contains fields in ***Common Data***



### Exit Group Data

Only contains fields in ***Common Data***



### Rmdir Data

```
------
|14  |
------
|file|
------
```



### Unlink Data

```
------
|14  |
------
|file|
------
```

### call_usermodehelper_exec Data

```
-----------------------------
|1  |2        |3  |4   |5   |
-----------------------------
|uid|data_type|exe|argv|wait|
-----------------------------
```



### Interrupt Table Hook Data

```
---------------------------------------------------
|1  |2        |3          |4     |5               |
---------------------------------------------------
|uid|data_type|module_name|hidden|interrupt_number|
---------------------------------------------------
```

Note:  ***uid*** is always -1



 ### Syscall Table Hook Data

```
-------------------------------------------------
|1  |2        |3          |4     |5             |
-------------------------------------------------
|uid|data_type|module_name|hidden|syscall_number|
-------------------------------------------------
```

Note: ***uid*** is always -1



### Proc File Hook

```
----------------------------------
|1  |2        |3          |4     |
----------------------------------
|uid|data_type|module_name|hidden|
----------------------------------
```

Note:  ***uid*** is always -1



### Hidden Kernel Module Data

````
----------------------------------
|1  |2        |3          |4     |
----------------------------------
|uid|data_type|module_name|hidden|
----------------------------------
````

Note:  ***uid*** is always -1



## About Driver Filter

Elkeid driver supports allowlist to filter out unwanted data. We provide two types of allowlists, **'exe'** allowlist and **'argv'** allowlist.
**'exe'** allowlist acts on ***execve/create file/dns query/connect*** hooks, while **'argv'** allowlist only acts on ***execve*** hook. 
For performance and stability concerns, both 'exe' and 'argv' allowlist only supports 64-elements-wide capacity.

allowlist driver is in: `/dev/hids_driver_allowlist`

| Operations                    | Flag   | Example                                              |
| ----------------------------- | ------ | ---------------------------------------------------- |
| ADD_EXECVE_EXE_SHITELIST      | Y(89)  | `echo Y/bin/ls > /dev/someone_allowlist`             |
| DEL_EXECVE_EXE_SHITELIST      | F(70)  | `echo Y/bin/ls > /dev/someone_allowlist`             |
| DEL_ALL_EXECVE_EXE_SHITELIST  | w(119) | `echo w/del_all > /dev/someone_allowlist`            |
| EXECVE_EXE_CHECK              | y(121) | `echo y/bin/ls > /dev/someone_allowlist && dmesg`    |
| ADD_EXECVE_ARGV_SHITELIST     | m(109) | `echo m/bin/ls -l > /dev/someone_allowlist`          |
| DEL_EXECVE_ARGV_SHITELIST     | J(74)  | `echo J/bin/ls -l > /dev/someone_allowlist`          |
| DEL_ALL_EXECVE_ARGV_SHITELIST | u(117) | `echo u/del_all > /dev/someone_allowlist`            |
| EXECVE_ARGV_CHECK             | z(122) | `echo z/bin/ls -l > /dev/someone_allowlist && dmesg` |
| PRINT_ALL_ALLOWLIST           | .(46)  | `echo ./print_all > /dev/someone_allowlist && dmesg` |

Filter define is:
```c
#define ADD_EXECVE_EXE_SHITELIST 89
#define DEL_EXECVE_EXE_SHITELIST 70
#define DEL_ALL_EXECVE_EXE_SHITELIST 119
#define EXECVE_EXE_CHECK 121
#define PRINT_ALL_ALLOWLIST 46
#define ADD_EXECVE_ARGV_SHITELIST 109
#define DEL_EXECVE_ARGV_SHITELIST 74
#define DEL_ALL_EXECVE_ARGV_SHITELIST 117
#define EXECVE_ARGV_CHECK 122
```



## Performance Stats of Elkeid Driver

### Testing Environment(VM):

| CPU       |  Intel(R) Xeon(R) Platinum 8260 CPU @ 2.40GHz    8 Core |
| --------- | ------------------------------------------------   |
| RAM       | 16GB                                              |
| OS/Kernel | Debian9  / Kernel Version 4.14                   |

Testing Load:

| syscall               | ltp                                    |
| --------------------- | -------------------------------------- |
| connect               | ./runltp -f syscalls -s connect -t 5m  |
| bind                  | ./runltp -f syscalls -s bind -t 5m   |
| execve                | ./runltp -f syscalls -s execve -t 5m   |
| security_inode_create | ./runltp -f syscalls -s open -t 5m     |
| ptrace                | ./runltp -f syscalls -s ptrace -t 5m   |

### Key kprobe Handler Testing Result(90s)

| hook function name                 | Average Delay(us) | TP99(us) | TP95(us) | TP90(us) |
| ---------------------------------- | ----------------- | -------- | -------- | -------- |
| connect_syscall_handler            |  0.7454            |   3.5017   |  1.904   | 1.43    |
| connect_syscall_entry_handler      |  0.0675          | 0.3  | 0.163  | 0.1149  |
| udp_recvmsg_handler                |  9.1290           | 68.7043 |  18.5357   | 15.9528    |
| udp_recvmsg_entry_handler         |  0.5882           | 7.5631  |  0.7811  |  0.3665    |
| bind_handler                      |  2.2558           | 10.0525  |  8.1996     | 7.041     |
| bind_entry_handler                |  0.4704            | 1.0180   | 0.8234    |  0.6739  |
| execve_entry_handler              |  6.9262           | 12.2824  | 9.437  |  8.638  |
| execve_handler                    |  15.2102          | 36.0903 | 25.9272  | 23.068  |
| security_inode_create_pre_handler |  1.5523          | 7.9454 | 5.5806  | 3.1441  |
| ptrace_pre_handler                |  0.2039          | 0.4648 | 0.254  | 0.228  |


`udp_recvmsg_handler` will work only if the port is equal 53 or 5353

Original Testing Data:[Benchmark Data](https://github.com/bytedance/Elkeid/tree/main/driver/benchmark_data/handler)


## About Deploy

You can use DKMS or Pre-packaged ko file

* install driver: `insmod hids_driver.ko`
* remove driver: first you need kill userspace agent and `rmmod hids_driver.ko`

## Pre-build Ko

### Describe
This kernel module has been running for a long time on our debian machines. The probability of kernel driver going error is rarely low, however, some versions of the kernel and distros are not well tested .eg: kernel < 3.10 , kernel > 5.4 and ubuntu. DO NOT insmod the ko in the production machines if you have not tested it.

### Pre-build Ko Contents

#### centos8
4.18.0-147.0.3.el8_1.x86_64<br>
4.18.0-147.3.1.el8_1.x86_64<br>
4.18.0-147.5.1.el8_1.x86_64<br>
4.18.0-147.8.1.el8_1.x86_64<br>
4.18.0-147.el8.x86_64<br>
4.18.0-193.1.2.el8_2.x86_64<br>
4.18.0-193.14.2.el8_2.x86_64<br>
4.18.0-193.19.1.el8_2.x86_64<br>
4.18.0-193.28.1.el8_2.x86_64<br>
4.18.0-193.6.3.el8_2.x86_64<br>
4.18.0-193.el8.x86_64<br>
4.18.0-80.11.1.el8_0.x86_64<br>
4.18.0-80.11.2.el8_0.x86_64<br>
4.18.0-80.1.2.el8_0.x86_64<br>
4.18.0-80.4.2.el8_0.x86_64<br>
4.18.0-80.7.1.el8_0.x86_64<br>
4.18.0-80.7.2.el8_0.x86_64<br>
4.18.0-80.el8.x86_64<br>

#### centos7
3.10.0-1062.1.1.el7.x86_64<br>
3.10.0-1062.12.1.el7.x86_64<br>
3.10.0-1062.1.2.el7.x86_64<br>
3.10.0-1062.18.1.el7.x86_64<br>
3.10.0-1062.4.1.el7.x86_64<br>
3.10.0-1062.4.2.el7.x86_64<br>
3.10.0-1062.4.3.el7.x86_64<br>
3.10.0-1062.7.1.el7.x86_64<br>
3.10.0-1062.9.1.el7.x86_64<br>
3.10.0-1062.el7.x86_64<br>
3.10.0-1127.10.1.el7.x86_64<br>
3.10.0-1127.13.1.el7.x86_64<br>
3.10.0-1127.18.2.el7.x86_64<br>
3.10.0-1127.19.1.el7.x86_64<br>
3.10.0-1127.8.2.el7.x86_64<br>
3.10.0-1127.el7.x86_64<br>
3.10.0-1160.11.1.el7.x86_64<br>
3.10.0-1160.15.2.el7.x86_64<br>
3.10.0-1160.2.1.el7.x86_64<br>
3.10.0-1160.2.2.el7.x86_64<br>
3.10.0-1160.6.1.el7.x86_64<br>
3.10.0-1160.el7.x86_64<br>
3.10.0-229.11.1.el7.x86_64<br>
3.10.0-229.1.2.el7.x86_64<br>
3.10.0-229.14.1.el7.x86_64<br>
3.10.0-229.20.1.el7.x86_64<br>
3.10.0-229.4.2.el7.x86_64<br>
3.10.0-229.7.2.el7.x86_64<br>
3.10.0-327.10.1.el7.x86_64<br>
3.10.0-327.13.1.el7.x86_64<br>
3.10.0-327.18.2.el7.x86_64<br>
3.10.0-327.22.2.el7.x86_64<br>
3.10.0-327.28.2.el7.x86_64<br>
3.10.0-327.28.3.el7.x86_64<br>
3.10.0-327.3.1.el7.x86_64<br>
3.10.0-327.36.1.el7.x86_64<br>
3.10.0-327.36.2.el7.x86_64<br>
3.10.0-327.36.3.el7.x86_64<br>
3.10.0-327.4.4.el7.x86_64<br>
3.10.0-327.4.5.el7.x86_64<br>
3.10.0-327.el7.x86_64<br>
3.10.0-514.10.2.el7.x86_64<br>
3.10.0-514.16.1.el7.x86_64<br>
3.10.0-514.21.1.el7.x86_64<br>
3.10.0-514.21.2.el7.x86_64<br>
3.10.0-514.2.2.el7.x86_64<br>
3.10.0-514.26.1.el7.x86_64<br>
3.10.0-514.26.2.el7.x86_64<br>
3.10.0-514.6.1.el7.x86_64<br>
3.10.0-514.6.2.el7.x86_64<br>
3.10.0-514.el7.x86_64<br>
3.10.0-693.11.1.el7.x86_64<br>
3.10.0-693.11.6.el7.x86_64<br>
3.10.0-693.1.1.el7.x86_64<br>
3.10.0-693.17.1.el7.x86_64<br>
3.10.0-693.21.1.el7.x86_64<br>
3.10.0-693.2.1.el7.x86_64<br>
3.10.0-693.2.2.el7.x86_64<br>
3.10.0-693.5.2.el7.x86_64<br>
3.10.0-693.el7.x86_64<br>
3.10.0-862.11.6.el7.x86_64<br>
3.10.0-862.14.4.el7.x86_64<br>
3.10.0-862.2.3.el7.x86_64<br>
3.10.0-862.3.2.el7.x86_64<br>
3.10.0-862.3.3.el7.x86_64<br>
3.10.0-862.6.3.el7.x86_64<br>
3.10.0-862.9.1.el7.x86_64<br>
3.10.0-862.el7.x86_64<br>
3.10.0-957.10.1.el7.x86_64<br>
3.10.0-957.12.1.el7.x86_64<br>
3.10.0-957.12.2.el7.x86_64<br>
3.10.0-957.1.3.el7.x86_64<br>
3.10.0-957.21.2.el7.x86_64<br>
3.10.0-957.21.3.el7.x86_64<br>
3.10.0-957.27.2.el7.x86_64<br>
3.10.0-957.5.1.el7.x86_64<br>
3.10.0-957.el7.x86_64<br>


#### debian

3.16.0-11-amd64<br>
3.16.0-6-amd64<br>
4.19.0-0.bpo.10-amd64<br>
4.19.0-0.bpo.10-cloud-amd64<br>
4.19.0-0.bpo.10-rt-amd64<br>
4.19.0-0.bpo.11-amd64<br>
4.19.0-0.bpo.11-cloud-amd64<br>
4.19.0-0.bpo.11-rt-amd64<br>
4.19.0-0.bpo.12-amd64<br>
4.19.0-0.bpo.12-cloud-amd64<br>
4.19.0-0.bpo.12-rt-amd64<br>
4.19.0-0.bpo.13-amd64<br>
4.19.0-0.bpo.13-cloud-amd64<br>
4.19.0-0.bpo.13-rt-amd64<br>
4.19.0-0.bpo.14-amd64<br>
4.19.0-0.bpo.14-cloud-amd64<br>
4.19.0-0.bpo.14-rt-amd64<br>
4.19.0-0.bpo.9-amd64<br>
4.19.0-0.bpo.9-cloud-amd64<br>
4.19.0-0.bpo.9-rt-amd64<br>
4.19.0-14-amd64<br>
4.19.0-14-cloud-amd64<br>
4.19.0-14-rt-amd64<br>
4.19.0-16-amd64<br>
4.19.0-16-cloud-amd64<br>
4.19.0-16-rt-amd64<br>
4.9.0-0.bpo.11-amd64<br>
4.9.0-0.bpo.11-rt-amd64<br>
4.9.0-0.bpo.12-amd64<br>
4.9.0-0.bpo.12-rt-amd64<br>
4.9.0-13-amd64<br>
4.9.0-13-rt-amd64<br>
4.9.0-14-amd64<br>
4.9.0-14-rt-amd64<br>
4.9.0-15-amd64<br>
4.9.0-15-rt-amd64<br>

#### ubuntu

3.13.0-100-generic<br>
3.13.0-101-generic<br>
3.13.0-103-generic<br>
3.13.0-105-generic<br>
3.13.0-106-generic<br>
3.13.0-107-generic<br>
3.13.0-108-generic<br>
3.13.0-109-generic<br>
3.13.0-110-generic<br>
3.13.0-112-generic<br>
3.13.0-113-generic<br>
3.13.0-115-generic<br>
3.13.0-116-generic<br>
3.13.0-117-generic<br>
3.13.0-119-generic<br>
3.13.0-121-generic<br>
3.13.0-123-generic<br>
3.13.0-125-generic<br>
3.13.0-126-generic<br>
3.13.0-128-generic<br>
3.13.0-129-generic<br>
3.13.0-132-generic<br>
3.13.0-133-generic<br>
3.13.0-135-generic<br>
3.13.0-137-generic<br>
3.13.0-139-generic<br>
3.13.0-141-generic<br>
3.13.0-142-generic<br>
3.13.0-143-generic<br>
3.13.0-144-generic<br>
3.13.0-145-generic<br>
3.13.0-147-generic<br>
3.13.0-149-generic<br>
3.13.0-151-generic<br>
3.13.0-153-generic<br>
3.13.0-155-generic<br>
3.13.0-156-generic<br>
3.13.0-157-generic<br>
3.13.0-158-generic<br>
3.13.0-160-generic<br>
3.13.0-161-generic<br>
3.13.0-162-generic<br>
3.13.0-163-generic<br>
3.13.0-164-generic<br>
3.13.0-165-generic<br>
3.13.0-166-generic<br>
3.13.0-167-generic<br>
3.13.0-168-generic<br>
3.13.0-169-generic<br>
3.13.0-170-generic<br>
3.13.0-24-generic<br>
3.13.0-27-generic<br>
3.13.0-29-generic<br>
3.13.0-30-generic<br>
3.13.0-32-generic<br>
3.13.0-33-generic<br>
3.13.0-34-generic<br>
3.13.0-35-generic<br>
3.13.0-36-generic<br>
3.13.0-37-generic<br>
3.13.0-39-generic<br>
3.13.0-40-generic<br>
3.13.0-41-generic<br>
3.13.0-43-generic<br>
3.13.0-44-generic<br>
3.13.0-45-generic<br>
3.13.0-46-generic<br>
3.13.0-48-generic<br>
3.13.0-49-generic<br>
3.13.0-51-generic<br>
3.13.0-52-generic<br>
3.13.0-53-generic<br>
3.13.0-54-generic<br>
3.13.0-55-generic<br>
3.13.0-57-generic<br>
3.13.0-58-generic<br>
3.13.0-59-generic<br>
3.13.0-61-generic<br>
3.13.0-62-generic<br>
3.13.0-63-generic<br>
3.13.0-65-generic<br>
3.13.0-66-generic<br>
3.13.0-67-generic<br>
3.13.0-68-generic<br>
3.13.0-70-generic<br>
3.13.0-71-generic<br>
3.13.0-73-generic<br>
3.13.0-74-generic<br>
3.13.0-76-generic<br>
3.13.0-77-generic<br>
3.13.0-79-generic<br>
3.13.0-83-generic<br>
3.13.0-85-generic<br>
3.13.0-86-generic<br>
3.13.0-87-generic<br>
3.13.0-88-generic<br>
3.13.0-91-generic<br>
3.13.0-92-generic<br>
3.13.0-93-generic<br>
3.13.0-95-generic<br>
3.13.0-96-generic<br>
3.13.0-98-generic<br>
3.16.0-25-generic<br>
3.16.0-26-generic<br>
3.16.0-28-generic<br>
3.16.0-29-generic<br>
3.16.0-30-generic<br>
3.16.0-31-generic<br>
3.16.0-33-generic<br>
3.16.0-34-generic<br>
3.16.0-36-generic<br>
3.16.0-37-generic<br>
3.16.0-38-generic<br>
3.16.0-39-generic<br>
3.16.0-40-generic<br>
3.16.0-41-generic<br>
3.16.0-43-generic<br>
3.16.0-44-generic<br>
3.16.0-45-generic<br>
3.16.0-46-generic<br>
3.16.0-48-generic<br>
3.16.0-49-generic<br>
3.16.0-50-generic<br>
3.16.0-51-generic<br>
3.16.0-52-generic<br>
3.16.0-53-generic<br>
3.16.0-55-generic<br>
3.16.0-56-generic<br>
3.16.0-57-generic<br>
3.16.0-59-generic<br>
3.16.0-60-generic<br>
3.16.0-62-generic<br>
3.16.0-67-generic<br>
3.16.0-69-generic<br>
3.16.0-70-generic<br>
3.16.0-71-generic<br>
3.16.0-73-generic<br>
3.16.0-76-generic<br>
3.16.0-77-generic<br>
4.10.0-14-generic<br>
4.10.0-19-generic<br>
4.10.0-20-generic<br>
4.10.0-21-generic<br>
4.10.0-22-generic<br>
4.10.0-24-generic<br>
4.10.0-26-generic<br>
4.10.0-27-generic<br>
4.10.0-28-generic<br>
4.10.0-30-generic<br>
4.10.0-32-generic<br>
4.10.0-33-generic<br>
4.10.0-35-generic<br>
4.10.0-37-generic<br>
4.10.0-38-generic<br>
4.10.0-40-generic<br>
4.10.0-42-generic<br>
4.11.0-13-generic<br>
4.11.0-14-generic<br>
4.13.0-16-generic<br>
4.13.0-17-generic<br>
4.13.0-19-generic<br>
4.13.0-21-generic<br>
4.13.0-25-generic<br>
4.13.0-26-generic<br>
4.13.0-31-generic<br>
4.13.0-32-generic<br>
4.13.0-36-generic<br>
4.13.0-37-generic<br>
4.13.0-38-generic<br>
4.13.0-39-generic<br>
4.13.0-41-generic<br>
4.13.0-43-generic<br>
4.13.0-45-generic<br>
4.15.0-101-generic<br>
4.15.0-106-generic<br>
4.15.0-107-generic<br>
4.15.0-108-generic<br>
4.15.0-109-generic<br>
4.15.0-111-generic<br>
4.15.0-112-generic<br>
4.15.0-115-generic<br>
4.15.0-117-generic<br>
4.15.0-118-generic<br>
4.15.0-120-generic<br>
4.15.0-121-generic<br>
4.15.0-122-generic<br>
4.15.0-123-generic<br>
4.15.0-124-generic<br>
4.15.0-128-generic<br>
4.15.0-129-generic<br>
4.15.0-130-generic<br>
4.15.0-132-generic<br>
4.15.0-133-generic<br>
4.15.0-134-generic<br>
4.15.0-135-generic<br>
4.15.0-136-generic<br>
4.15.0-137-generic<br>
4.15.0-139-generic<br>
4.15.0-13-generic<br>
4.15.0-140-generic<br>
4.15.0-15-generic<br>
4.15.0-20-generic<br>
4.15.0-22-generic<br>
4.15.0-23-generic<br>
4.15.0-24-generic<br>
4.15.0-29-generic<br>
4.15.0-30-generic<br>
4.15.0-32-generic<br>
4.15.0-33-generic<br>
4.15.0-34-generic<br>
4.15.0-36-generic<br>
4.15.0-38-generic<br>
4.15.0-39-generic<br>
4.15.0-42-generic<br>
4.15.0-43-generic<br>
4.15.0-44-generic<br>
4.15.0-45-generic<br>
4.15.0-46-generic<br>
4.15.0-47-generic<br>
4.15.0-48-generic<br>
4.15.0-50-generic<br>
4.15.0-51-generic<br>
4.15.0-52-generic<br>
4.15.0-54-generic<br>
4.15.0-55-generic<br>
4.15.0-58-generic<br>
4.15.0-60-generic<br>
4.15.0-62-generic<br>
4.15.0-64-generic<br>
4.15.0-65-generic<br>
4.15.0-66-generic<br>
4.15.0-69-generic<br>
4.15.0-70-generic<br>
4.15.0-72-generic<br>
4.15.0-74-generic<br>
4.15.0-76-generic<br>
4.15.0-88-generic<br>
4.15.0-91-generic<br>
4.15.0-96-generic<br>
4.15.0-99-generic<br>
4.18.0-13-generic<br>
4.18.0-14-generic<br>
4.18.0-15-generic<br>
4.18.0-16-generic<br>
4.18.0-17-generic<br>
4.18.0-18-generic<br>
4.18.0-20-generic<br>
4.18.0-21-generic<br>
4.18.0-22-generic<br>
4.18.0-24-generic<br>
4.18.0-25-generic<br>
4.2.0-18-generic<br>
4.2.0-19-generic<br>
4.2.0-21-generic<br>
4.2.0-22-generic<br>
4.2.0-23-generic<br>
4.2.0-25-generic<br>
4.2.0-27-generic<br>
4.2.0-30-generic<br>
4.2.0-34-generic<br>
4.2.0-35-generic<br>
4.2.0-36-generic<br>
4.2.0-38-generic<br>
4.2.0-41-generic<br>
4.2.0-42-generic<br>
4.4.0-101-generic<br>
4.4.0-103-generic<br>
4.4.0-104-generic<br>
4.4.0-108-generic<br>
4.4.0-109-generic<br>
4.4.0-111-generic<br>
4.4.0-112-generic<br>
4.4.0-116-generic<br>
4.4.0-119-generic<br>
4.4.0-121-generic<br>
4.4.0-122-generic<br>
4.4.0-124-generic<br>
4.4.0-127-generic<br>
4.4.0-128-generic<br>
4.4.0-130-generic<br>
4.4.0-131-generic<br>
4.4.0-133-generic<br>
4.4.0-134-generic<br>
4.4.0-135-generic<br>
4.4.0-137-generic<br>
4.4.0-138-generic<br>
4.4.0-139-generic<br>
4.4.0-140-generic<br>
4.4.0-141-generic<br>
4.4.0-142-generic<br>
4.4.0-143-generic<br>
4.4.0-144-generic<br>
4.4.0-145-generic<br>
4.4.0-146-generic<br>
4.4.0-148-generic<br>
4.4.0-150-generic<br>
4.4.0-151-generic<br>
4.4.0-154-generic<br>
4.4.0-157-generic<br>
4.4.0-159-generic<br>
4.4.0-161-generic<br>
4.4.0-164-generic<br>
4.4.0-165-generic<br>
4.4.0-166-generic<br>
4.4.0-168-generic<br>
4.4.0-169-generic<br>
4.4.0-170-generic<br>
4.4.0-171-generic<br>
4.4.0-173-generic<br>
4.4.0-174-generic<br>
4.4.0-176-generic<br>
4.4.0-177-generic<br>
4.4.0-178-generic<br>
4.4.0-179-generic<br>
4.4.0-184-generic<br>
4.4.0-185-generic<br>
4.4.0-186-generic<br>
4.4.0-187-generic<br>
4.4.0-189-generic<br>
4.4.0-190-generic<br>
4.4.0-193-generic<br>
4.4.0-194-generic<br>
4.4.0-197-generic<br>
4.4.0-198-generic<br>
4.4.0-200-generic<br>
4.4.0-201-generic<br>
4.4.0-203-generic<br>
4.4.0-204-generic<br>
4.4.0-206-generic<br>
4.4.0-21-generic<br>
4.4.0-22-generic<br>
4.4.0-24-generic<br>
4.4.0-28-generic<br>
4.4.0-31-generic<br>
4.4.0-34-generic<br>
4.4.0-36-generic<br>
4.4.0-38-generic<br>
4.4.0-42-generic<br>
4.4.0-43-generic<br>
4.4.0-45-generic<br>
4.4.0-47-generic<br>
4.4.0-51-generic<br>
4.4.0-53-generic<br>
4.4.0-57-generic<br>
4.4.0-59-generic<br>
4.4.0-62-generic<br>
4.4.0-63-generic<br>
4.4.0-64-generic<br>
4.4.0-66-generic<br>
4.4.0-67-generic<br>
4.4.0-70-generic<br>
4.4.0-71-generic<br>
4.4.0-72-generic<br>
4.4.0-75-generic<br>
4.4.0-77-generic<br>
4.4.0-78-generic<br>
4.4.0-79-generic<br>
4.4.0-81-generic<br>
4.4.0-83-generic<br>
4.4.0-87-generic<br>
4.4.0-89-generic<br>
4.4.0-91-generic<br>
4.4.0-92-generic<br>
4.4.0-93-generic<br>
4.4.0-96-generic<br>
4.4.0-97-generic<br>
4.4.0-98-generic<br>
4.8.0-34-generic<br>
4.8.0-36-generic<br>
4.8.0-39-generic<br>
4.8.0-41-generic<br>
4.8.0-42-generic<br>
4.8.0-44-generic<br>
4.8.0-45-generic<br>
4.8.0-46-generic<br>
4.8.0-49-generic<br>
4.8.0-51-generic<br>
4.8.0-52-generic<br>
4.8.0-53-generic<br>
4.8.0-54-generic<br>
4.8.0-56-generic<br>
4.8.0-58-generic<br>
5.0.0-15-generic<br>
5.0.0-16-generic<br>
5.0.0-17-generic<br>
5.0.0-19-generic<br>
5.0.0-20-generic<br>
5.0.0-23-generic<br>
5.0.0-25-generic<br>
5.0.0-27-generic<br>
5.0.0-29-generic<br>
5.0.0-31-generic<br>
5.0.0-32-generic<br>
5.0.0-35-generic<br>
5.0.0-36-generic<br>
5.0.0-37-generic<br>
5.0.0-41-generic<br>
5.0.0-43-generic<br>
5.0.0-44-generic<br>
5.0.0-47-generic<br>
5.0.0-48-generic<br>
5.0.0-52-generic<br>
5.0.0-53-generic<br>
5.0.0-58-generic<br>
5.0.0-60-generic<br>
5.0.0-61-generic<br>
5.0.0-62-generic<br>
5.0.0-63-generic<br>
5.0.0-65-generic<br>
5.3.0-19-generic<br>
5.3.0-22-generic<br>
5.3.0-23-generic<br>
5.3.0-24-generic<br>
5.3.0-26-generic<br>
5.3.0-28-generic<br>
5.3.0-40-generic<br>
5.3.0-42-generic<br>
5.3.0-45-generic<br>
5.3.0-46-generic<br>
5.3.0-51-generic<br>
5.3.0-53-generic<br>
5.3.0-59-generic<br>
5.3.0-61-generic<br>
5.3.0-62-generic<br>
5.3.0-64-generic<br>
5.3.0-65-generic<br>
5.3.0-66-generic<br>
5.3.0-67-generic<br>
5.3.0-68-generic<br>
5.3.0-69-generic<br>
5.3.0-70-generic<br>
5.3.0-72-generic<br>
5.4.0-26-generic<br>
5.4.0-28-generic<br>
5.4.0-29-generic<br>
5.4.0-31-generic<br>
5.4.0-33-generic<br>
5.4.0-37-generic<br>
5.4.0-39-generic<br>
5.4.0-40-generic<br>
5.4.0-42-generic<br>
5.4.0-45-generic<br>
5.4.0-47-generic<br>
5.4.0-48-generic<br>
5.4.0-51-generic<br>
5.4.0-52-generic<br>
5.4.0-53-generic<br>
5.4.0-54-generic<br>
5.4.0-58-generic<br>
5.4.0-59-generic<br>
5.4.0-60-generic<br>
5.4.0-62-generic<br>
5.4.0-64-generic<br>
5.4.0-65-generic<br>
5.4.0-66-generic<br>
5.4.0-67-generic<br>
5.4.0-70-generic<br>


### How To Get
If all urls failed, please build elkeid.ko yourself.

```bash
wget "http://lf26-elkeid.bytetos.com/obj/elkeid-download/ko/hids_driver_1.6.0.0_$(uname -r).ko"
# or
curl -O "http://lf26-elkeid.bytetos.com/obj/elkeid-download/ko/hids_driver_1.6.0.0_$(uname -r).ko"
# 其他地址
## "http://lf3-elkeid.bytetos.com/obj/elkeid-download/ko/hids_driver_1.6.0.0_$(uname -r).ko"
## "http://lf6-elkeid.bytetos.com/obj/elkeid-download/ko/hids_driver_1.6.0.0_$(uname -r).ko"
## "http://lf9-elkeid.bytetos.com/obj/elkeid-download/ko/hids_driver_1.6.0.0_$(uname -r).ko"
```


## Test the Ko
You can test the kernel module using [LTP](https://linux-test-project.github.io/) or [Kasan](https://www.kernel.org/doc/html/latest/dev-tools/kasan.html).

<br>
LTP-test-case:

```bash
connect01 connect01
connect02 connect02
execve01 execve01
execve02 execve02
execve03 execve03
execve04 execve04
execve05 execve05 -i 5 -n 32
execveat01 execveat01
execveat02 execveat02
execveat03 execveat03
bind01 bind01
bind02 bind02
bind03 bind03
bind04 bind04
bind05 bind05
bind06 bind06
mbind01 mbind01
mbind02 mbind02
mbind03 mbind03
mbind04 mbind04
fsopen01 fsopen01
fsopen02 fsopen02
mq_open01 mq_open01
open01 open01
open01A symlink01 -T open01
open02 open02
open03 open03
open04 open04
open05 open05
open06 open06
open07 open07
open08 open08
open09 open09
open10 open10
open11 open11
open12 open12
open13 open13
open14 open14
openat01 openat01
openat02 openat02
openat03 openat03
openat201 openat201
openat202 openat202
openat203 openat203
open_by_handle_at01 open_by_handle_at01
open_by_handle_at02 open_by_handle_at02
open_tree01 open_tree01
open_tree02 open_tree02
pidfd_open01 pidfd_open01
pidfd_open02 pidfd_open02
pidfd_open03 pidfd_open03
perf_event_open01 perf_event_open01
perf_event_open02 perf_event_open02
ptrace01 ptrace01
ptrace02 ptrace02
ptrace03 ptrace03
ptrace04 ptrace04
ptrace05 ptrace05
ptrace07 ptrace07
ptrace08 ptrace08
ptrace09 ptrace09
ptrace10 ptrace10
ptrace11 ptrace11
mprotect01 mprotect01
mprotect02 mprotect02
mprotect03 mprotect03
mprotect04 mprotect04
rename01 rename01
rename02 rename02
rename03 rename03
rename04 rename04
rename05 rename05
rename06 rename06
rename07 rename07
rename08 rename08
rename09 rename09
rename10 rename10
rename11 rename11
rename12 rename12
rename13 rename13
rename14 rename14
renameat01 renameat01
renameat201 renameat201
renameat202 renameat202 -i 10
chdir01A symlink01 -T chdir01
chmod01A symlink01 -T chmod01
link01 symlink01 -T link01
link02 link02
link03 link03
link04 link04
link05 link05
link06 link06
link07 link07
link08 link08
linkat01 linkat01
linkat02 linkat02
lstat01A symlink01 -T lstat01
lstat01A_64 symlink01 -T lstat01_64
mkdir05A symlink01 -T mkdir05
mq_unlink01 mq_unlink01
prot_hsymlinks prot_hsymlinks
readlink01A symlink01 -T readlink01
readlink01 readlink01
readlink03 readlink03
readlinkat01 readlinkat01
readlinkat02 readlinkat02
rename01A symlink01 -T rename01
rmdir03A symlink01 -T rmdir03
stat04 symlink01 -T stat04
stat04_64 symlink01 -T stat04_64
symlink01 symlink01
symlink02 symlink02
symlink03 symlink03
symlink04 symlink04
symlink05 symlink05
symlinkat01 symlinkat01
unlink01 symlink01 -T unlink01
unlink05 unlink05
unlink07 unlink07
unlink08 unlink08
unlinkat01 unlinkat01
utime01A symlink01 -T utime01
setsid01 setsid01
prctl01 prctl01
prctl02 prctl02
prctl03 prctl03
prctl04 prctl04
prctl05 prctl05
prctl06 prctl06
prctl07 prctl07
prctl08 prctl08
prctl09 prctl09
memfd_create01 memfd_create01
memfd_create02 memfd_create02
memfd_create03 memfd_create03
memfd_create04 memfd_create04
accept01 accept01
accept02 accept02
accept4_01 accept4_01
kill02 kill02
kill03 kill03
kill05 kill05
kill06 kill06
kill07 kill07
kill08 kill08
kill09 kill09
kill10 kill10
kill11 kill11
kill12 kill12
tgkill01 tgkill01
tgkill02 tgkill02
tgkill03 tgkill03
tkill01 tkill01
tkill02 tkill02
exit01 exit01
exit02 exit02
exit_group01 exit_group01
rmdir01 rmdir01
rmdir02 rmdir02
rmdir03 rmdir03
```

## Known Bugs
* Hook point init failed : do_init_module
<br>
Some old version of ubuntu / centos kernels may show the dmesg :
do_init_module register_kprobe failed, returned -2.

* Kernel > 5.4.X or Kernel < 3.10.X
<br>
Make failed : these kernel versions are not yet compatible



## License

Elkeid kernel module are distributed under the GNU GPLv2 license.

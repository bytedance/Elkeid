[![License](https://img.shields.io/badge/License-GPL%20v2-blue.svg)](https://github.com/bytedance/Elkeid/blob/main/driver/LICENSE) [![Project Status: Active – The project has reached a stable, usable state and is being actively developed.](https://www.repostatus.org/badges/latest/active.svg)](https://www.repostatus.org/#active)

## About Elkeid(AgentSmith-HIDS) Driver

English | [简体中文](README-zh_CN.md)



Elkeid Driver is a one-of-a-kind Kernel Space HIDS agent designed for Cyber-Security. 

Elkeid Driver hooks kernel functions via Kprobe, providing rich and accurate data collection capabilities,  including kernel-level process execve probing, privilege escalation monitoring, network audition, and much more. The Driver treats Container-based monitoring as a first-class citizen as Host-based data collection by supporting Linux Namespace. Compare to User Space agents on the market, Elkeid provides more comprehensive information with massive performance improvement. 

Elkeid has already been deployed massively for HIDS usage in world-class production environments. With its marvelous data collection ability, Elkeid also supports Sandbox, Honeypot, and Audition data requirements. 

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

* Fully Tested on: Centos, Debian, Ubuntu


## About the compatibility with ARM

* Partially support


## About the compatibility with Kernel version

* Linux Kernel Version >= 3.10



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

## License

Elkeid kernel module are distributed under the GNU GPLv2 license.

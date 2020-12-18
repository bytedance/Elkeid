## About AgentSmith-HIDS Driver
AgentSmith-HIDS driver hook some kernel function via Kprobe, and is also capable of monitoring containers by being compatible with Linux namespace. Mainly for provide data for cyber security engineer(HIDS/Audit/Sandbox/Honeypot). Can get more comprehensive information compared to userpace agent,but also has better performance.

## Quick Test
```shell script
cd LKM
make claen && make
insmod hids_driver.ko
dmesg
cat /proc/hids_driver/1
rmmod hids_driver
```

## About the compatibility with Linux distribution

* Tested on:Centos,Debian,Ubuntu


## About the compatibility with ARM

* Partial support


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
| dns queny          | 601      |                                                | ON      |
| init kernel module | 603      |                                                | ON      |
| update cred        | 604      | only old uid ≠0 && new uid == 0                | ON      |
| rename             | 82       |                                                | OFF     |
| link               | 86       |                                                | OFF     |
| setsid             | 112      |                                                | OFF     |
| prctl              | 157      | only PS_SET_NAME                               | OFF     |
| open               | 2        |                                                | OFF     |
| mprotect           | 10       | only PROT_EXEC                                 | OFF     |
| nanosleep          | 35       |                                                | OFF     |
| kill               | 62       |                                                | OFF     |
| tkill              | 200      |                                                | OFF     |
| process exit       | 60       |                                                | OFF     |
| exit group         | 231      |                                                | OFF     |
| rmdir              | 606      |                                                | OFF     |
| unlink             | 605      |                                                | OFF     |



## Anti Rootkit List

| Rootkit              | DataType | Default |
| -------------------- | -------- | ------- |
| interrupt table hook | 703      | ON      |
| syscall table hook   | 701      | ON      |
| proc file hook       | 700      | ON      |
| hidden kernel module | 702      | ON      |



## Driver TransData Pattern

### Data Protocol

Use between data fields '**\x1e**' make intervals

Use between data '**\x17**' make intervals

All hook print data consists of **common data** + **privatization data**

All anti rootkit data does not contain **common data**

### common data

```
------------------------------------------------------------------
|1  |2        |3  |4  |5   |6   |7   |8  |9   |10      |11       |
-----------------------------------------------------------------
|uid|data_type|exe|pid|ppid|pgid|tgid|sid|comm|nodename|sessionid|
------------------------------------------------------------------
```



### connect data 

```
------------------------------------------------
|12          |13       |14 |15   |16 |17   |18 |
------------------------------------------------
|connect_type|sa_family|dip|dport|sip|sport|res|
------------------------------------------------
```

Note: default situation connect_type always is -1



### bind data

```
-------------------------
|12       |13 |14   |15 |
-------------------------
|sa_family|sip|sport|res|
-------------------------
```



### execve data

```
-------------------------------------------------------------------------------------------------------------------------
|12        |13  |14      |15      |16   |17    |18 |19   |20 |21   |22       |23      |24 |25        |26 |27        |28 |
-------------------------------------------------------------------------------------------------------------------------
|socket_exe|argv|run_path|pgid_exe|stdin|stdout|dip|dport|sip|sport|sa_family|pid_tree|tty|socket_pid|ssh|ld_preload|res|
-------------------------------------------------------------------------------------------------------------------------
```

Note:

* **socket_exe/dip/dport/sip/sport/sa_family** data from process fd

* **ssh/ld_preload** data from process env



### create file data

```
-----------
|12 	  |
-----------
|file_path|
-----------
```



### ptrace

```
----------------------------------------------
|12            |13        |14  |15  |16      |
----------------------------------------------
|ptrace_request|target_pid|addr|data|pid_tree|
----------------------------------------------
```



### dns query data

```
-----------------------------------------------------
|12   |13       |14 |15   |16 |17   |18|19    |20   |
-----------------------------------------------------
|query|sa_family|dip|dport|sip|sport|qr|opcode|rcode|
-----------------------------------------------------
```



### init kernel module data

```
----------------------------
|12      |13      |14      | 
----------------------------
|mod_info|pid_tree|run_path|
----------------------------
```



### update cred data

```
----------------------
|12      |13     |14 | 
----------------------
|pid_tree|old_uid|res|
----------------------
```



### rename data

```
----------------------------
|12      |13      |14      | 
----------------------------
|run_path|old_name|new_name|
----------------------------
```



### link data

```
----------------------------
|12      |13      |14      | 
----------------------------
|run_path|old_name|new_name|
----------------------------
```



### setsid data

only common data



### prctl data

```
_________________
|12    |13      | 
-----------------
|option|new_name|
-----------------
```



### open data

````
---------------------
|12   |13  |14      | 
---------------------
|flags|mode|filename|
---------------------
````



### mprotect data

```
-----------------------------------------------------
|12           |13       |14        |15     |16      |
-----------------------------------------------------
|mprotect_prot|owner_pid|owner_file|vm_file|pid_tree|
-----------------------------------------------------
```



### nanosleep data

```
----------
|12 |13  |
----------
|sec|nsec|
----------
```



### kill data

```
----------------
|12        |13 |
----------------
|target_pid|sig|
----------------
```



### tkill data

```
----------------
|12        |13 |
----------------
|target_pid|sig|
----------------
```



### process exit data

only common data



### exit group data

only common data



### rmdir data

```
------
|12  |
------
|file|
------
```



### unlink data

```
------
|12  |
------
|file|
------
```



### interrupt table hook data

```
---------------------------------------------------
|1  |2        |3          |4     |5               |
---------------------------------------------------
|uid|data_type|module_name|hidden|interrupt_number|
---------------------------------------------------
```

Note:  uid always is -1



 ### syscall table hook data

```
-------------------------------------------------
|1  |2        |3          |4     |5             |
-------------------------------------------------
|uid|data_type|module_name|hidden|syscall_number|
-------------------------------------------------
```

Note: uid always is -1



### proc file hook

```
----------------------------------
|1  |2        |3          |4     |
----------------------------------
|uid|data_type|module_name|hidden|
----------------------------------
```

Note: uid always is -1



### hidden kernel module data

````
----------------------------------
|1  |2        |3          |4     |
----------------------------------
|uid|data_type|module_name|hidden|
----------------------------------
````

Note: uid always is -1



## About Driver Filter

AgentSmith-HIDS driver support whitelist,We have 'exe' and 'argv' whitelist, 'exe' whitelist acts on **execve/create file/dns query/connect** hook, 'argv' whitelist only acts on **execve** hook.

'exe' and 'argv' whitelist capacity is 64. 

whitelist driver is : `/dev/hids_driver_whitelist`

| Operations                    | Flag   | Example                                              |
| ----------------------------- | ------ | ---------------------------------------------------- |
| ADD_EXECVE_EXE_SHITELIST      | Y(89)  | `echo Y/bin/ls > /dev/someone_whitelist`             |
| DEL_EXECVE_EXE_SHITELIST      | F(70)  | `echo Y/bin/ls > /dev/someone_whitelist`             |
| DEL_ALL_EXECVE_EXE_SHITELIST  | w(119) | `echo w/del_all > /dev/someone_whitelist`            |
| EXECVE_EXE_CHECK              | y(121) | `echo y/bin/ls > /dev/someone_whitelist && dmesg`    |
| ADD_EXECVE_ARGV_SHITELIST     | m(109) | `echo m/bin/ls -l > /dev/someone_whitelist`          |
| DEL_EXECVE_ARGV_SHITELIST     | J(74)  | `echo J/bin/ls -l > /dev/someone_whitelist`          |
| DEL_ALL_EXECVE_ARGV_SHITELIST | u(117) | `echo u/del_all > /dev/someone_whitelist`            |
| EXECVE_ARGV_CHECK             | z(122) | `echo z/bin/ls -l > /dev/someone_whitelist && dmesg` |
| PRINT_ALL_WHITELIST           | .(46)  | `echo ./print_all > /dev/someone_whitelist && dmesg` |

Filter define is:
```c
#define ADD_EXECVE_EXE_SHITELIST 89
#define DEL_EXECVE_EXE_SHITELIST 70
#define DEL_ALL_EXECVE_EXE_SHITELIST 119
#define EXECVE_EXE_CHECK 121
#define PRINT_ALL_WHITELIST 46
#define ADD_EXECVE_ARGV_SHITELIST 109
#define DEL_EXECVE_ARGV_SHITELIST 74
#define DEL_ALL_EXECVE_ARGV_SHITELIST 117
#define EXECVE_ARGV_CHECK 122
```



## About Performance of AgentSmith-HIDS Driver

### Testing Environment(VM):

| CPU       |  Intel(R) Xeon(R) Platinum 8260 CPU @ 2.40GHz    8 Core |
| --------- | ------------------------------------------------   |
| RAM       | 16GB                                              |
| OS/Kernel | Debian9  / Kernel Version 4.14                   |

Testing Load:

| syscall               | ltp                                    |
| --------------------- | -------------------------------------- |
| connect               | ./runltp -f syscalls -s connect -t 5m  |
| bind                  | ./runltp -f syscalls -s ptrace -t 5m   |
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

Original Testing Data:[Benchmark Data](https://github.com/bytedance/AgentSmith-HIDS/tree/main/driver/benchmark_data/handler)


## License

AgentSmith-HIDS kernel module are distributed under the GNU GPLv3 license.

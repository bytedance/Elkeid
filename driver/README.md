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
# clone and build
git clone https://github.com/bytedance/Elkeid.git
cd Elkeid/driver/LKM/
make clean && make
< CentOS only: run build script instead >
sh ./centos_build_ko.sh

# load and test (should run as root)
insmod hids_driver.ko
dmesg | tail -n 20
test/rst -q
< "CTRL + C" to quit >

# unload
rmmod hids_driver
```

## Pre-build Ko

### Pre-build Ko List
[Pre-build Ko lists](./ko_list.md)



### How To Get
If all urls failed, please build elkeid kernel module yourself.

```bash
wget "http://lf26-elkeid.bytetos.com/obj/elkeid-download/ko/hids_driver_1.7.0.4_$(uname -r).ko"
# or
curl -O "http://lf26-elkeid.bytetos.com/obj/elkeid-download/ko/hids_driver_1.7.0.4_$(uname -r).ko"
# other cdn
## "http://lf3-elkeid.bytetos.com/obj/elkeid-download/ko/hids_driver_1.7.0.4_$(uname -r).ko"
## "http://lf6-elkeid.bytetos.com/obj/elkeid-download/ko/hids_driver_1.7.0.4_$(uname -r).ko"
## "http://lf9-elkeid.bytetos.com/obj/elkeid-download/ko/hids_driver_1.7.0.4_$(uname -r).ko"
```


## How to Test
You can test the kernel module with [LTP](https://linux-test-project.github.io/) (better with [KASAN](https://www.kernel.org/doc/html/latest/dev-tools/kasan.html) truned on). Here's the [LTP-test-case](./ltp_testcase) configuration file for your reference:  [LTP-test-case](./ltp_testcase).


## About the compatibility with Linux distributions

Distro|Version|x64 kernel|Suffix
:- | :- | -: | -:
debian|8,9,10|3.16~5.4.X |-
ubuntu|14.04,16.04,18.04,20.04|3.12~5.4.X |generic
centos|6.x,7.X,8.X|2.6.32~5.4.X |el6,el7,el8
amazon|2|4.9.X~4.14.X|amzn2
EulerOS|V2.0|3.10.X|-

## About ARM64 (AArch64) Support

* Yes

## About the compatibility with Kernel versions

* Linux Kernel Version >= 2.6.32 && <= 5.14.X

## About the compatibility with Containers

| Source | Nodename       |
| ------ | -------------- |
| Host   | hostname       |
| Docker | container name |
| k8s    | pod name       |

## Hook List

| Hook               | DataType | Note                                    | Default |
| ------------------ | -------- | --------------------------------------- | ------- |
| write              | 1        |                                         | OFF     |
| open               | 2        |                                         | OFF     |
| mprotect           | 10       | only PROT_EXEC                          | OFF     |
| nanosleep          | 35       |                                         | OFF     |
| connect            | 42       |                                         | ON      |
| accept             | 43       |                                         | OFF     |
| bind               | 49       |                                         | ON      |
| execve             | 59       |                                         | ON      |
| process exit       | 60       |                                         | OFF     |
| kill               | 62       |                                         | OFF     |
| rename             | 82       |                                         | ON     |
| link               | 86       |                                         | ON     |
| ptrace             | 101      | only PTRACE_POKETEXT or PTRACE_POKEDATA | ON      |
| setsid             | 112      |                                         | ON     |
| prctl              | 157      | only PR_SET_NAME                        | ON     |
| mount              | 165      |                                         | ON     |
| tkill              | 200      |                                         | OFF     |
| exit_group         | 231      |                                         | OFF     |
| memfd_create       | 356      |                                         | ON     |
| dns queny          | 601      |                                         | ON     |
| create_file        | 602      |                                         | ON      |
| load_module        | 603      |                                         | ON      |
| update_cred        | 604      | only old uid ≠0 && new uid == 0         | ON      |
| unlink             | 605      |                                         | OFF     |
| rmdir              | 606      |                                         | OFF     |
| call_usermodehelper_exec     | 607      |                               | ON     |
| file_read          | 609      |                                          | OFF     |
| usb_device_event   | 610      |                                          | ON     |
| privilege_escalation   | 611      |                                          | ON     |



## Anti Rootkit List

| Rootkit              | DataType | Default |
| -------------------- | -------- | ------- |
| interrupt table hook | 703      | ON      |
| syscall table hook   | 701      | ON      |
| proc file hook       | 700      | ON      |
| hidden kernel module | 702      | ON      |



## Driver TransData Pattern

### Data Protocol

Every hit of the above hook-points will generate a record.  Each record contains several data itmes and the data items are being seperated by **data deliminator**: '**\x17**'.

A record contains **Common Data** and ***Private Data***, with the exception of Anti-rootkit, which does **NOT** have  **Common Data**.

### Common Data

```
-------------------------------------------------------------------------------
|1        |2  |3  |4  |5   |6   |7   |8  |9   |10      |11       |12 |13      |
-------------------------------------------------------------------------------
|data_type|uid|exe|pid|ppid|pgid|tgid|sid|comm|nodename|sessionid|pns|root_pns|
-------------------------------------------------------------------------------
```

### Write Data (1)

````
-----------
|14   |15 | 
-----------
|file||buf|
-----------
````


### Open Data (2)

````
---------------------
|14   |15  |16      | 
---------------------
|flags|mode|filename|
---------------------
````



### Mprotect Data (10)

```
-----------------------------------------------------
|14           |15       |16        |17     |18      |
-----------------------------------------------------
|mprotect_prot|owner_pid|owner_file|vm_file|pid_tree|
-----------------------------------------------------
```



### Nanosleep Data (35)

```
----------
|14 |15  |
----------
|sec|nsec|
----------
```



### Connect Data (42)

```
-----------------------------------
|14       |15 |16   |17 |18   |19 |
-----------------------------------
|sa_family|dip|dport|sip|sport|res|
-----------------------------------
```

### Accept Data (43)

```
-----------------------------------
|14       |15 |16   |17 |18   |19 |
-----------------------------------
|sa_family|dip|dport|sip|sport|res|
-----------------------------------
```

### Bind Data (49)

```
-------------------------
|14       |15 |16   |17 |
-------------------------
|sa_family|sip|sport|res|
-------------------------
```



### Execve Data (59)

```
-----------------------------------------------------------------------------------------------------
|14  |15      |16   |17    |18 |19   |20 |21   |22       |23      |24 |25        |26 |27        |28 |
-----------------------------------------------------------------------------------------------------
|argv|run_path|stdin|stdout|dip|dport|sip|sport|sa_family|pid_tree|tty|socket_pid|ssh|ld_preload|res|
-----------------------------------------------------------------------------------------------------
```

Note:

* **socket_exe/dip/dport/sip/sport/sa_family** is collected from the process's fds

* **ssh/ld_preload** is collected from the process's env


### Process Exit Data (60)

Only contains fields in ***Common Data***


### Kill Data (62)

```
----------------
|14        |15 |
----------------
|target_pid|sig|
----------------
```



### Rename Data (82)

```
----------------------------
|14      |15      |16      | 
----------------------------
|run_path|old_name|new_name|
----------------------------
```


### Link Data (86)

```
----------------------------
|14      |15      |16      | 
----------------------------
|run_path|old_name|new_name|
----------------------------
```


### Ptrace Data (101)

```
----------------------------------------------
|14            |15        |16  |17  |18      |
----------------------------------------------
|ptrace_request|target_pid|addr|data|pid_tree|
----------------------------------------------
```



### Setsid Data (112)

Only contains fields in ***Common Data***



### Prctl Data (157)

```
_________________
|14    |15      | 
-----------------
|option|new_name|
-----------------
```


### Mount Data (165)

```
_____________________________________
|14      |15 |16       |17    |18   | 
-------------------------------------
|pid_tree|dev|file_path|fstype|flags|
-------------------------------------
```


### Tkill data (200)

```
----------------
|14        |15 |
----------------
|target_pid|sig|
----------------
```

### Exit Group Data (231)

Only contains fields in ***Common Data***


### memfd_create Data (356)

```
______________
|14    |15   | 
--------------
|fdname|flags|
--------------
```



### Dns Query Data (601)

```
--------------------------------------------------
|14   |15       |16 |17   |18 |19   |20    |21   |
--------------------------------------------------
|query|sa_family|dip|dport|sip|sport|opcode|rcode|
--------------------------------------------------
```


### Create File data (602)

```
----------------------------------------------------
|14 	  |15 |16   |17 |18   |19       |20        |
----------------------------------------------------
|file_path|dip|dport|sip|sport|sa_family|socket_pid|
----------------------------------------------------
```


### Load Module Data (603)

```
----------------------------
|14      |15      |16      | 
----------------------------
|ko_file|pid_tree|run_path|
----------------------------
```



### Update Cred Data (604)

```
----------------------
|14      |15     |16 | 
----------------------
|pid_tree|old_uid|res|
----------------------
```


### Unlink Data (605)

```
------
|14  |
------
|file|
------
```


### Rmdir Data (606)

```
------
|14  |
------
|file|
------
```


### call_usermodehelper_exec Data (607)

```
-------------------------
|1        |2  |3   |4   |
-------------------------
|data_type|exe|argv|wait|
-------------------------
```

### File Write Data (608)

```
------------
|14  |15   |
------------
|file|sb_id|
------------
Need to join the to-watch list through Diver Filter, see "About Driver Filter" section for details
```

### File Read Data (609)

```
------------
|14  |15   |
------------
|file|sb_id|
------------
Need to join the to-watch list through Diver Filter, see "About Driver Filter" section for details
```

### USB Device Event Data (610)

```
-----------------------------------------
|14          |15          |16    |17    |
-----------------------------------------
|product_info|manufacturer|serial|action|
-----------------------------------------
action = 1 is USB_DEVICE_ADD
action = 2 is USB_DEVICE_REMOVE
```

### Privilege Escalation (611)

```
------------------------------
|14   |15      |16    |17    |
------------------------------
|p_pid|pid_tree|p_cred|c_cred|
------------------------------
p_cred = uid|euid|suid|fsuid|gid|egid|sgid|fsgid
c_cred = uid|euid|suid|fsuid|gid|egid|sgid|fsgid
```

### Proc File Hook (700)

```
-----------------------
|1        |2          |
-----------------------
|data_type|module_name|
-----------------------
```

### Syscall Table Hook Data (701)

```
--------------------------------------
|1        |2          |3             |
--------------------------------------
|data_type|module_name|syscall_number|
--------------------------------------
```

### Hidden Kernel Module Data (702)

````
-----------------------
|1        |2          |
-----------------------
|data_type|module_name|
-----------------------
````

### Interrupt Table Hook Data (703)

```
----------------------------------------
|1        |2          |3               |
----------------------------------------
|data_type|module_name|interrupt_number|
----------------------------------------
```



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
| ADD_WRITE_NOTIFI           | W(87)  | `echo W/etc/passwd > /dev/someone_allowlist` or `echo W/etc/ssh/ > /dev/someone_allowlist` support dir  |
| DEL_WRITE_NOTIFI           | v(120)  | `echo v/etc/passwd > /dev/someone_allowlist` |
| ADD_READ_NOTIFI           | R(82)  | `echo W/etc/passwd > /dev/someone_allowlist` or `echo W/etc/ssh/ > /dev/someone_allowlist` support dir  |
| DEL_READ_NOTIFI           | s(115)  | `echo v/etc/passwd > /dev/someone_allowlist` |
| DEL_ALL_NOTIFI           | A(65)  | `echo A/del_all_file_notift > /dev/someone_allowlist` |

Filter define is:
```c
#define ADD_EXECVE_EXE_SHITELIST 89         /* Y */
#define DEL_EXECVE_EXE_SHITELIST 70         /* F */
#define DEL_ALL_EXECVE_EXE_SHITELIST 119    /* w */
#define EXECVE_EXE_CHECK 121                /* y */
#define PRINT_ALL_ALLOWLIST 46              /* . */
#define ADD_EXECVE_ARGV_SHITELIST 109       /* m */
#define DEL_EXECVE_ARGV_SHITELIST 74        /* J */
#define DEL_ALL_EXECVE_ARGV_SHITELIST 117   /* u */
#define EXECVE_ARGV_CHECK 122               /* z */

#define ADD_WRITE_NOTIFI 87                 /* W */
#define DEL_WRITE_NOTIFI 120                /* v */
#define ADD_READ_NOTIFI 82                  /* R */
#define DEL_READ_NOTIFI 115                 /* s */
#define DEL_ALL_NOTIFI 65                   /* A */
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




## Known Bugs
* Hook point init failed : do_init_module
<br>
Some old version of ubuntu / centos kernels may show the dmesg :
do_init_module register_kprobe failed, returned -2.



## License

Elkeid kernel module are distributed under the GNU GPLv2 license.

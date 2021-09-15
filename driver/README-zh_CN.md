[![License](https://img.shields.io/badge/License-GPL%20v2-blue.svg)](https://github.com/bytedance/Elkeid/blob/main/driver/LICENSE) [![Project Status: Active – The project has reached a stable, usable state and is being actively developed.](https://www.repostatus.org/badges/latest/active.svg)](https://www.repostatus.org/#active)

## About Elkeid(AgentSmith-HIDS) Driver

[English](README.md) | 简体中文


Elkeid Driver 主要是为信息安全需求而设计的。

Elkeid Driver 主要通过 Kprobe Hook Kernel Funcion 来提供丰富而准确的数据收集功能，包括内核级进程执行探测，特权升级监控，网络审计等等。 并且支持 Linux namespace，因此对容器监控有着很好的实现。与传统的UserSpace HIDS相比，Elkeid由于驱动的存在提供了更全面的信息，并提高了性能。

凭借其出色的数据收集能力，Elkeid Driver还可以支持沙盒，蜜罐和审计等需求。

当前版本的 Elkeid 内核模块代码已经在公司内生产网的 debian 机器上运行了很长的时间，内核模块出错的可能性极低，但是，这并不保证该内核模块在其他版本的内核中能够完美运行。例如，在小于3.10 和 大于 5.4 的内核版本，内核驱动尚未适配；以及 ubuntu 的部分版本机器中，因为定制内核的关系，Linux发行版本众多，很多情况并未经过充分测试。因此，千万不要在未经充分测试的情况下，在生产环境的机器中直接 insmod 使用 Elkeid 内核模块。

如果发现 Bug 欢迎提 Issue 或 加入飞书公开群参与讨论。

## 快速尝试

首先需要安装Linux Headers，Linux Headers 的版本必须等于 uname -r

```shell script
git clone https://github.com/bytedance/Elkeid.git
cd Elkeid/driver/LKM/
make clean && make
insmod hids_driver.ko
dmesg
cat /proc/hids_driver/1
rmmod hids_driver
```

## 我们提供部分预编译好的 Ko 文件

我们提供了一些预编译好的 Elkeid 内核模块，这些 Ko 包括了 debian,centos,ubuntu 等发行版的不同内核版本。

### 描述
当前版本的 Elkeid 内核模块代码已经在公司内生产网的 debian 机器上运行了很长的时间，内核模块出错的可能性极低，但是，这并不保证该内核模块在其他版本的内核中能够完美运行。例如，在小于3.10 和 大于 5.4 的内核版本，该内核驱动尚未适配，以及 ubuntu 的部分版本机器中，因为定制内核的关系，Linux发行版本众多，很多情况并未经过充分测试。因此，千万不要在未经测试的情况下，在生产环境的机器中直接 insmod 使用 Elkeid 内核模块。

### 预编译好的 [Ko 文件列表](./ko_list.md)
若不再列表内，或下载失败，请自行编译 ko


### 获取方式


如果所有链接都获取失败，则说明 [预编译的 Ko](./ko_list.md) 中，不包含当前系统的内核版本所需的 Ko，需要自行编译

```bash
wget "http://lf26-elkeid.bytetos.com/obj/elkeid-download/ko/hids_driver_1.6.0.0_$(uname -r).ko"
# or
curl -O "http://lf26-elkeid.bytetos.com/obj/elkeid-download/ko/hids_driver_1.6.0.0_$(uname -r).ko"
# 其他地址
## "http://lf3-elkeid.bytetos.com/obj/elkeid-download/ko/hids_driver_1.6.0.0_$(uname -r).ko"
## "http://lf6-elkeid.bytetos.com/obj/elkeid-download/ko/hids_driver_1.6.0.0_$(uname -r).ko"
## "http://lf9-elkeid.bytetos.com/obj/elkeid-download/ko/hids_driver_1.6.0.0_$(uname -r).ko"
```

### 内核模块的测试方法

可以通过 [LTP](https://linux-test-project.github.io/) 或者 [Kasan](https://www.kernel.org/doc/html/latest/dev-tools/kasan.html)这两个方法对内核模块进行测试.

这里提供 [LTP测试用例](./ltp_testcase) 文件


## 关于Linux发行版的兼容性

发行版|版本号|x64 架构内核|内核后缀 |生产网大范围使用
:- | :- | -: | -| -:
debian|8,9,10|3.16~5.4.X |-| yes
ubuntu|14.04,16.04,18.04,20.04|3.12~5.4.X |generic| no 
centos|7.X,8.X|3.10.0~5.4.X |el7,el8| half 



## 关于ARM兼容性

* 部分能力支持




## 关于Linux Kernel Version兼容性

* Linux Kernel Version >= 3.10 && <= 5.4.X



## 关于容器兼容性

| Source | Nodename       |
| ------ | -------------- |
| Host   | hostname       |
| Docker | container name |
| k8s    | pod name       |



## Hook List

| Hook               | DataType | Note                                    | Default |
| ------------------ | -------- | --------------------------------------- | ------- |
| connect            | 42       |                                         | ON      |
| bind               | 49       |                                         | ON      |
| execve             | 59       |                                         | ON      |
| create file        | 602      |                                         | ON      |
| ptrace             | 101      | only PTRACE_POKETEXT or PTRACE_POKEDATA | ON      |
| dns queny          | 601      |                                         | OFF      |
| init kernel module | 603      |                                         | ON      |
| update cred        | 604      | only old uid ≠0 && new uid == 0         | ON      |
| rename             | 82       |                                         | ON     |
| link               | 86       |                                         | ON     |
| setsid             | 112      |                                         | ON     |
| prctl              | 157      | only PR_SET_NAME                        | ON     |
| memfd_create       | 356      |                                                 | ON     |
| open               | 2        |                                         | OFF     |
| mprotect           | 10       | only PROT_EXEC                          | OFF     |
| nanosleep          | 35       |                                         | OFF     |
| kill               | 62       |                                         | OFF     |
| tkill              | 200      |                                         | OFF     |
| process exit       | 60       |                                         | OFF     |
| exit group         | 231      |                                         | OFF     |
| rmdir              | 606      |                                         | OFF     |
| unlink             | 605      |                                         | OFF     |
| call_usermodehelper_exec             | 607      |                                         | OFF     |


## Anti Rootkit List

| Rootkit              | DataType | Default |
| -------------------- | -------- | ------- |
| interrupt table hook | 703      | ON      |
| syscall table hook   | 701      | ON      |
| proc file hook       | 700      | ON      |
| hidden kernel module | 702      | ON      |



## 关于驱动数据传输

### 驱动数据协议

字段间使用'**\x1e**'作为间隔符

数据间使用'**\x17**'作为间隔符



数据通常是**公共数据**和**私有数据**组合而成，值得注意的是Anti-rootkit数据不具有**公共数据**。

### 公共数据

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

Note: Connect_type 在默认情况下为 -1



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

* **socket_exe/dip/dport/sip/sport/sa_family** 来自于进程所持fd信息

* **ssh/ld_preload** 来自于进程的环境变量信息



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

该数据没有私有数据，仅有公共数据



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

该数据没有私有数据，仅有公共数据



### Exit Group Data

该数据没有私有数据，仅有公共数据



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

Note:  ***uid*** 为 -1



 ### Syscall Table Hook Data

```
-------------------------------------------------
|1  |2        |3          |4     |5             |
-------------------------------------------------
|uid|data_type|module_name|hidden|syscall_number|
-------------------------------------------------
```

Note: ***uid*** 为 -1



### Proc File Hook

```
----------------------------------
|1  |2        |3          |4     |
----------------------------------
|uid|data_type|module_name|hidden|
----------------------------------
```

Note:  ***uid*** 为 -1



### Hidden Kernel Module Data

````
----------------------------------
|1  |2        |3          |4     |
----------------------------------
|uid|data_type|module_name|hidden|
----------------------------------
````

Note:  ***uid*** 为 -1



## 关于Driver Filter

Elkeid驱动程序支持白名单以过滤出不需要的数据。 我们提供两种类型的白名单，**'exe'**白名单和**'argv'**白名单。
**'exe'**白名单作用于**execve /create filte/ dns query/connect hook**，而**'argv'**白名单仅作用于**execve hook**  。
出于性能和稳定性方面的考虑，‘exe’和‘argv’白名单容量为64。

白名单的字符串驱动位于: `/dev/hids_driver_allowlist`

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



## 关于Elkeid Driver 性能

### Testing Environment(VM):

| CPU       | Intel(R) Xeon(R) Platinum 8260 CPU @ 2.40GHz    8 Core |
| --------- | ------------------------------------------------------ |
| RAM       | 16GB                                                   |
| OS/Kernel | Debian9  / Kernel Version 4.14                         |

Testing Load:

| syscall               | ltp                                   |
| --------------------- | ------------------------------------- |
| connect               | ./runltp -f syscalls -s connect -t 5m |
| bind                  | ./runltp -f syscalls -s bind -t 5m  |
| execve                | ./runltp -f syscalls -s execve -t 5m  |
| security_inode_create | ./runltp -f syscalls -s open -t 5m    |
| ptrace                | ./runltp -f syscalls -s ptrace -t 5m  |

### Key kprobe Handler Testing Result(90s)

| hook function name                | Average Delay(us) | TP99(us) | TP95(us) | TP90(us) |
| --------------------------------- | ----------------- | -------- | -------- | -------- |
| connect_syscall_handler           | 0.7454            | 3.5017   | 1.904    | 1.43     |
| connect_syscall_entry_handler     | 0.0675            | 0.3      | 0.163    | 0.1149   |
| udp_recvmsg_handler               | 9.1290            | 68.7043  | 18.5357  | 15.9528  |
| udp_recvmsg_entry_handler         | 0.5882            | 7.5631   | 0.7811   | 0.3665   |
| bind_handler                      | 2.2558            | 10.0525  | 8.1996   | 7.041    |
| bind_entry_handler                | 0.4704            | 1.0180   | 0.8234   | 0.6739   |
| execve_entry_handler              | 6.9262            | 12.2824  | 9.437    | 8.638    |
| execve_handler                    | 15.2102           | 36.0903  | 25.9272  | 23.068   |
| security_inode_create_pre_handler | 1.5523            | 7.9454   | 5.5806   | 3.1441   |
| ptrace_pre_handler                | 0.2039            | 0.4648   | 0.254    | 0.228    |

`udp_recvmsg_handler` 仅工作在端口为 53 或 5353的情况

测试原始数据:[Benchmark Data](https://github.com/bytedance/Elkeid/tree/main/driver/benchmark_data/handler)


## 关于部署

可以使用DKMS或者提前编译好ko文件然后进行下发

* install driver: `insmod hids_driver.ko`
* remove driver: first you need kill userspace agent and `rmmod hids_driver.ko`




## 已知问题
* 内核模块 hook 点初始化失败 : do_init_module
<br>
在一些老版本的 ubuntu/centos 内核中出现，dmesg 会有如下输出:<br>
do_init_module register_kprobe failed, returned -2.<br>
内核模块仍然可以使用，但没有 do_init_module 数据

* 内核版本 > 5.4.X 或者 < 3.10.X
<br>
编译失败 : 这些内核版本尚未适配


## License

Elkeid kernel module are distributed under the GNU GPLv2 license.

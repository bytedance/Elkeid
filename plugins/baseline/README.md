# Baseline

English | [简体中文](README-zh_CN.md)  
基线插件通过已有或自定义的基线策略对资产进行检测，来判断资产上的基线安全配置是否存在风险。基线插件每天定时扫描一次，同时也可以通过前端进行立即检查。
## 平台兼容性
centos 6,7,8  
debian 8,9,10  
ubuntu 14.04-20.04  
*(其余版本以及发行版理论兼容)*

## 需要的编译环境
* Golang 1.16

## 编译
## 部署
## 基线配置
### 常规配置
基线插件的规则通过yaml文件配置，其中主要包括一下字段(建议参照config文件下实际配置对比)：
```yaml
check_id: 检查项id(int)
type: "类型(英文)"
title: "标题(英文)"
description: "描述(英文)"
solution: "解决方案(英文)"
security: "安全等级(high/mid/low)"
type_cn: "类型"
title_cn: "标题"
description_cn: "描述"
solution_cn: "解决方案"
check: # 检查规则（详见自定义规则）
    rules:
    - type: "file_line_check"
        param:
        - "/etc/login.defs"
        filter: '\s*\t*PASS_MAX_DAYS\s*\t*(\d+)'
        result: '$(<=)90'
```
### 自定义规则
每个检查项配置中的"check.rules"字段即为匹配规则，下边对每个字段进行解释：
#### rules.type
检查方式，目前baseline插件适配的内置检测规则(src/check/rules.go)包括如下几种：  
| 检测规则 | 含义 | 参数 | 返回值 |
|  ----  | ----  |  ----  | ----  |
| command_check  | 运行命令行语句 | 1：命令行语句<br>2：特殊参数(如*ignore_exit* 认为当命令行报错时认为通过检测) | 命令运行结果
| file_line_check  | 遍历文件，逐行匹配 | 1：文件绝对路径<br>2：该行的flag（用于快速筛选行，减轻正则匹配的压力）<br>3：该文件的注释符(默认为#) | true/flase/正则筛选值
| file_permission  | 检测文件权限是否符合安全配置 | 1： 文件绝对路径<br>2： 文件最小权限(基于8进制，如644) | true/false
| if_flie_exist  | 判断文件是否存在 | 1： 文件绝对路径 | true/false
| file_user_group  | 判断文件用户组 | 1： 文件绝对路径<br>2： 用户组id | true/false
| file_md5_check  | 判断文件MD5是否一致 | 1： 文件绝对路径<br>2： MD5 | true/false
| func_check  | 通过特殊基线规则判断 | 1： 目标规则 | true/false
#### rules.param
规则参数数组
#### rules.require
规则前提条件：一些安全基线配置可能会存在检测前提条件，如果满足了先决条件后才会存在安全隐患，如：
```yaml
rules:
  - type: "file_line_check"
    require: "allow_ssh_passwd"
    param:
        - "/etc/ssh/sshd_config"
    filter: '^\s*MaxAuthTries\s*\t*(\d+)'
    result: '$(<)5'
```
*allow_ssh_passwd*: 允许用户通过ssh密码登录
#### rules.result
检测结果，支持int，string，bool类型结果，
其中被*$()*为特殊检测语法，以下为部分语法示例：
|  检测语法 | 说明 | 示例 | 示例含义 |
|  ----  | ----  |  ----  |  ----  |
| $(&&) | 包含条件 | ok$(&&)success| 结果为ok或success |
| $(<=) | 常见运算符 | $(<=)4| 结果小于等于4 |
| $(not) | 结果取反 | $(not)error| 结果不为error |

复杂示例：
```
$(<)8$(&&)$(not)2  :  目标小于8且目标不为2
```
#### check.condition
由于规则的rule可能存在多个，因此可以通过condition字段定义规则之前的关系  
all: 全部规则命中  
any: 任一规则命中  
none: 无规则命中  
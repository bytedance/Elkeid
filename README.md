# Elkeid(AgentSmith-HIDS)

English | [简体中文](README-zh_CN.md)

Elkeid is a Cloud-Native Host-Based Intrusion Detection solution project to provide next-generation Threat Detection and Behavior Audition with modern architecture. 

Elkeid comprises three major components：
* **Elkeid Agent, co-worked with Elkeid Driver**, is the game-changer for the Data Collection market. It works at both Kernel and User Space of Linux System, providing rich data flow with much better performance. 
* **Elkeid Server** provides Service-Discovery for the production environment of up to millions of agents. The Server also supports primary data formatting along with rules distribution for the Agent. 
* **Elkeid HUB** provides high-performance, lightweight, and stateless alert generation with data manipulation to analyze the rich data flow. 

Now we are more than happy to announce the open-source of Elkeid Agent and Elkeid Driver. We decided to strengthen the Defense Community with our game-changing technology. Due to the lack of rule engine and detection functions, Elkeid Agent and Driver doesn't provide all HIDS capability on its own. However, it is a tremendous Host-Information-Collect-Agent that could be easily integrated with current HIDS/NIDS/XDR solutions on the market. Elkeid Agent and Elkeid Driver together advance solutions on the market in four major areas.

* **Better performance**  Data/Information are collected in kernel space to avoid additional supplement actions such as traversal of '/proc' directory or collecting from other audition processes such as "auditd".
* **Hard to be bypassed**  A specifically designed kernel driver powers data/Information collection, making it virtually impossible for malicious software, like rootkit, to evade detection or audition. The Driver could capture even evasion behavior itself.
* **Kernel + User Space**  Elkeid Agent provides User Space detection abilities, including file audition, in-house rule detection, and primary allowlists. 
* **Easy to be integrated**  Elkeid could empower any User Space agents far beyond Host Intrusion usages with the detailed and reliable data flow. A wide user action audition could benefit both Behavior Analysis and Compliance requests. When integrated with NIDS, security analyzers could build a comprehensive Provenance Graph from the network connections, along with high traceable process trees and file auditions.


## System Architecture

<img src="Elkeid.png"/>

Currently, we are only open-sourcing Elkeid Agent && Driver. Both components have been deployed and tested in production environments for months. We welcome any suggestions and cooperation.

* #### [Elkeid Driver](https://github.com/bytedance/Elkeid/tree/main/driver)
* #### [Elkeid Agent](https://github.com/bytedance/Elkeid/tree/main/agent)

## To be Continued 
* Elkeid Server is under development. More Features are on the way.

## Contact us && Cooperation

<img src="./Lark.png"/>

Lark Group

## License
* Elkeid Driver: GPLv2
* Elkeid Agent: Apache-2.0

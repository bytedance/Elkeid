# Build Elkeid CWPP from Source Code

In the current community version, some components have not been open sourced. Mainly, the related components of Elkeidup and Hub can only provide community version binaries at present, so it cannot provide a build manual built entirely from source code from zero to one. You can run the executable program built from source code by replacing the specified files in the package before installation, or replacing the executable program after installation. The specific file locations and corresponding relationships are described below.

## Replace before installation

### Agent

The Agent part will be built from the source code during the elkeidup deploy process, so the following files in the package can be replaced. It is recommended to unzip the file and confirm that the file and directory structure are the same as the files before replacement.

```
package/agent/v1.9.1/agent/elkeid-agent-src_1.7.0.24.tar.gz
```

### Driver Plugin

The Driver plugin will also build from the source code during the elkeidup deploy process, so you can also replace the following files in the package. It is recommended to unzip the file and confirm that the file and directory structure are the same as the files before replacement.

```
package/agent/v1.9.1/driver/driver-src_1.0.0.15.tar.gz
```

### Other agent plugins

Other agent plugins are pre-compiled. According to the documentation of each plugin, replace the corresponding files after compiling. Note that the plugin has plg format and tar.gz format. The plg format is an executable file, and the tar.gz is a compressed packet. The version number is currently hard coding in elkeidup, which needs to be consistent, please do not change it.

```
package/agent/v1.9.1/driver/driver-src_1.0.0.15.tar.gz
package/agent/v1.9.1/baseline/baseline-default-aarch64-1.0.1.23.tar.gz
package/agent/v1.9.1/baseline/baseline-default-x86_64-1.0.1.23.tar.gz
package/agent/v1.9.1/collector/collector-default-aarch64-1.0.0.140.plg
package/agent/v1.9.1/collector/collector-default-x86_64-1.0.0.140.plg
package/agent/v1.9.1/etrace/etrace-default-x86_64-1.0.0.92.tar.gz
package/agent/v1.9.1/journal_watcher/journal_watcher-default-aarch64-1.0.0.23.plg
package/agent/v1.9.1/journal_watcher/journal_watcher-default-x86_64-1.0.0.23.plg
package/agent/v1.9.1/rasp/rasp-default-x86_64-1.9.1.44.tar.gz
package/agent/v1.9.1/scanner/scanner-default-aarch64-3.1.9.6.tar.gz
package/agent/v1.9.1/scanner/scanner-default-x86_64-3.1.9.6.tar.gz
```

### ko

When deploying by default, the pre-compiled ko will not be copied to nginx. The pre-compiled ko will be provided in the release interface at the same time. After downloading the pre-compiled ko or compiling ko by yourself, you can replace the following files. The file is in tar.xz format. There is a ko folder after decompression, the format must be the same.

```
package/to_upload/agent/component/driver/ko.tar.xz
```

### Manager & ServiceDiscovery & AgentCenter

Compile the corresponding binary, decompress the tar.gz of the following path, and then replace the binary and pack it back to tar.gz.

```
# manager
package/manager/bin.tar.gz
# service discovery
package/service_discovery/bin.tar.gz
# agent center
package/agent_center/bin.tar.gz
```

## Replace after installation

### Agent related

The agent part can be uploaded through the front end, see the agent release document for details

### ko

Copy the corresponding ko and sing files to the following directory, and then execute the command to modify the directory permissions

```
# ko directory
/elkeid/nginx/ElkeidAgent/agent/component/driver/ko

# Modify permissions
chown -R nginx: nginx /elkeid/nginx
```

### Manager & ServiceDiscovery & AgentCenter

Pause the service, replace the corresponding binary, and restart the service

```
#manager
systemctl stop elkeid_manager
mv new_manager_bin /elkeid/manager/manager
systemctl start elkeid_manager

#service discovery
systemctl stop elkeid_sd
mv new_sd_bin /elkeid/service_discovery/sd
systemctl start elkeid_sd

#agent center
systemctl stop elkeid_ac
mv new_ac_bin /elkeid/agent_center/agent_center
systemctl start elkeid_ac
```
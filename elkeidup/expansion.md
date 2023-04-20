# Elkeid Community Edition, Expansion Guide

## ServiceDiscovery

### Self-expansion (dependency elkeidup)

1. Modify config.yaml add other hosts in sd, and the login conditions are the same as when installing.
2. Execute the following command elkeidup reinstall --component ServiceDiscovery --re-init

### Self-expansion (manual operation)

1. Copy the /elkeid/service_discovery of the installed SD machine to the machine to be expanded.
2. Update all SD configuration file /elkeid/service_discovery/conf/conf.yaml Cluster. Members item, which is an array of all SD instances, and each SD must fill in the addresses of all instances.
3. Execute the /elkeid/service_discovery/install.sh of the new SD instance, which will automatically start SD.
4. Restart all old sd instances'systemctl restart elkeid_sd '.

### sync up the upstream and downstream configuration

SD is currently a dependency of AgentCenter, Manager and Nginx. After expanding SD, you need to sync up and restart.

- AgentCenter: The configuration file is located sd.addrs/elkeid/agent_center/conf/svr.yml, restart the command'systemctl restart elkeid_ac '.
- Manager: configuration file is sd.addrs/elkeid/manager/conf/svr.yml, restart command'systemctl restart elkeid_manager '.
- Nginx: configuration file is located in the upstream sd_list of/elkeid/nginx/nginx/nginx.conf, restart command'systemctl restart elkeid_nginx '.

## AgentCenter

### Self-expansion (dependency elkeidup)

1. Modify config.yaml add other hosts in ac, and the login conditions are the same as when installing.
2. Execute the following command elkeidup reinstall --component AgentCenter --re-init

### Self-expansion (manual operation)

1. Copy the /elkeid/agent_center of the installed AC machine to the machine to be expanded.
2. Executing the /elkeid/agent_center/install.sh of the new AC instance installs and starts AC automatically.

### sync up the upstream and downstream configuration

If the agent is linked to the AC by means of service discovery, there is no need to manually sync up the upstream and downstream configurations.

If the agent is linkage AC through the AC address of the code, you need to re-compile the agent and add the new AC address to the agent linkage configuration.